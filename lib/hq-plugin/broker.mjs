// agent-comms broker mode as an HQ plugin (ADR-0306; agent-bot-hq plan §4.9
// and §9 row 13b). HQ core opens broker.sock and hands this plugin every
// frame on it. A member binds its connection first, in one of two ways:
//
// - `bind.challenge { runtime_id }`, then `bind { runtime_id, proof }`: the
//   member answers hq-admission's nonce with a proof keyed by its channel
//   binding, which is never sent (agent-bot-hq plan §9 row 16a). A member
//   that has its own OS account can bind only this way.
// - `bind { runtime_id, channel_binding }`: the binding itself, for a member
//   without an account.
//
// hq-admission decides whether the connection speaks for that live runtime;
// this plugin hands it the connection, and HQ core knows which account that
// connection arrived from. From then on the connection speaks for that
// runtime alone, and every later frame is delivered to the plugin that
// registered its kind, with the runtime ID and nothing else.
//
// This plugin authorizes nothing beyond the binding. Liveness, epoch, lease
// generation and "the request names the bound runtime" are checked by the
// consumer on every delivery (hq-tasks, through withBoundRuntime), so a
// superseded or expired runtime is refused there even on a bound connection.
// A separate B bridge principal uses bridge.bind.challenge/bridge.bind. Its
// receipt never becomes a runtime ID and never enters member delivery. HQ
// admission alone verifies the Machine assignment, B peer UID and HMAC.
// The versioned bridge.bind.v2 routes carry the protected launch reservation
// before Hello can mint a runtime ID.

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fail } from '../vendor/agent-bot-sdk/errors.mjs';
import { definePlugin } from '../vendor/agent-bot-sdk/plugin.mjs';
import { createNoticePump, NOTICE_ROUTES } from './notices.mjs';

const { name: NAME, version: VERSION } = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));

export const BIND = 'bind';
export const BIND_CHALLENGE = 'bind.challenge';
export const BRIDGE_BIND = 'bridge.bind';
export const BRIDGE_BIND_CHALLENGE = 'bridge.bind.challenge';
export const BRIDGE_BIND_V2 = 'bridge.bind.v2';
export const BRIDGE_BIND_CHALLENGE_V2 = 'bridge.bind.v2.challenge';
export const BRIDGE_BIND_V3 = 'bridge.bind.v3';
export const BRIDGE_BIND_CHALLENGE_V3 = 'bridge.bind.v3.challenge';

export const BRIDGE_QUALIFICATION_MESSAGES = 'bridge.qualification.messages.v1';
export const BRIDGE_RELAY_INGRESS = 'bridge.relay.ingress.v1';
export const STAGE2A_RELAY_PEER_CHALLENGE = 'stage2a-relay-peer-challenge';
export const BRIDGE_MEMBER_OBSERVE_V3 = 'bridge.member.observe.v3';
export const BRIDGE_MEMBER_ARM_V3 = 'bridge.member.arm.v3';
export const BRIDGE_RELAY_COMPLETE = 'bridge.relay.complete.v1';
export const BRIDGE_RELAY_PREWRITE = 'bridge.relay.prewrite.v1';

const BRIDGE_RECEIPT = /^[0-9a-f]{64}$/;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/;
const BRIDGE_V1 = {
  context: 'agent-bot-stage2a-bridge-bind-v1',
  challenge: 'bridgeBindChallenge',
  verify: 'verifyBridgeBinding',
};
const BRIDGE_V2 = {
  context: 'agent-bot-stage2a-bridge-bind-v2',
  challenge: 'bridgeBindChallengeV2',
  verify: 'verifyBridgeBindingV2',
};
const BRIDGE_V3 = {
  context: 'agent-bot-stage2a-bridge-bind-v3',
  challenge: 'bridgeBindChallengeV3',
  verify: 'verifyBridgeBindingV3',
};
const BRIDGE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const BRIDGE_V2_SELECTORS = [
  ['installation_id', BRIDGE_ID],
  ['start_id', /^st_[0-9a-f]{24}$/],
  ['launch_id', /^ln_[0-9a-f]{24}$/],
  ['plan_id', BRIDGE_ID],
  ['plan_digest', BRIDGE_RECEIPT],
  ['reservation_digest', /^sha256:[0-9a-f]{64}$/],
];
const BRIDGE_V3_SELECTORS = [
  ['installation_id', BRIDGE_ID],
  ['start_id', /^st_[0-9a-f]{24}$/],
  ['plan_id', BRIDGE_ID],
  ['plan_digest', BRIDGE_RECEIPT],
  ['reservation_digest', /^sha256:[0-9a-f]{64}$/],
  ['assignment_envelope_sha256', /^sha256:[0-9a-f]{64}$/],
  ['authority_envelope_sha256', /^sha256:[0-9a-f]{64}$/],
  ['member_selectors_sha256', /^sha256:[0-9a-f]{64}$/],
];
const RELAY_PEER_FIELDS = ['uid', 'pid', 'pid_version', 'start_seconds', 'start_micros',
  'parent_pid', 'parent_uid', 'parent_start_seconds', 'parent_start_micros'];

function validRelayPeer(peer) {
  return peer && typeof peer === 'object' && !Array.isArray(peer)
    && Object.keys(peer).length === RELAY_PEER_FIELDS.length
    && RELAY_PEER_FIELDS.every((key) => Object.hasOwn(peer, key)
      && Number.isSafeInteger(peer[key]) && peer[key] >= 0)
    && peer.uid === peer.parent_uid && peer.pid > 1 && peer.pid_version > 0
    && peer.start_seconds > 0 && peer.start_micros < 1_000_000
    && peer.parent_pid > 1 && peer.parent_start_seconds > 0
    && peer.parent_start_micros < 1_000_000;
}

function sameRelayPeer(left, right) {
  return validRelayPeer(right) && RELAY_PEER_FIELDS.every((key) => left[key] === right[key]);
}

function relayPeerDigest(peer) {
  const canonical = Object.fromEntries([...RELAY_PEER_FIELDS].sort().map((key) => [key, peer[key]]));
  return `sha256:${createHash('sha256').update(JSON.stringify(canonical)).digest('hex')}`;
}

function validateProtectedBridgeFrame(message, withProof) {
  const fields = withProof ? [...BRIDGE_V2_SELECTORS, ['proof', BRIDGE_RECEIPT]] : BRIDGE_V2_SELECTORS;
  if (!message || typeof message !== 'object' || Array.isArray(message)
    || Object.keys(message).length !== fields.length
    || fields.some(([key, pattern]) => !Object.hasOwn(message, key)
      || typeof message[key] !== 'string' || !pattern.test(message[key]))) {
    fail('host.invalid_request', 'invalid protected bridge bind frame');
  }
}
function validateV3BridgeFrame(message, withProof) {
  const fields = withProof ? [...BRIDGE_V3_SELECTORS, ['proof', BRIDGE_RECEIPT]] : BRIDGE_V3_SELECTORS;
  if (!message || typeof message !== 'object' || Array.isArray(message)
    || Object.keys(message).length !== fields.length
    || fields.some(([key, pattern]) => !Object.hasOwn(message, key)
      || typeof message[key] !== 'string' || !pattern.test(message[key]))) {
    fail('host.invalid_request', 'invalid two-member bridge bind frame');
  }
}
function validateV3MemberFrame(message, kind, selectors) {
  const observe = kind === BRIDGE_MEMBER_OBSERVE_V3;
  const fields = observe
    ? ['kind', 'selectors', 'member_id', 'member_selector', 'observe_nonce']
    : ['kind', 'selectors', 'member_id', 'member_selector', 'observe_nonce',
      'arm_nonce', 'child_observation_envelope_sha256', 'bridge_arm', 'bridge_arm_receipt_sha256'];
  if (!message || typeof message !== 'object' || Array.isArray(message)
    || Object.keys(message).length !== fields.length
    || fields.some((field) => !Object.hasOwn(message, field))
    || message.kind !== `${kind}.request`
    || typeof message.member_id !== 'string' || !BRIDGE_ID.test(message.member_id)
    || typeof message.member_selector !== 'string' || !/^mb_[0-9a-f]{64}$/.test(message.member_selector)
    || typeof message.observe_nonce !== 'string' || !BRIDGE_RECEIPT.test(message.observe_nonce)
    || !message.selectors || typeof message.selectors !== 'object' || Array.isArray(message.selectors)
    || Object.keys(message.selectors).length !== BRIDGE_V3_SELECTORS.length
    || BRIDGE_V3_SELECTORS.some(([key]) => message.selectors[key] !== selectors?.[key])
    || (!observe && (typeof message.arm_nonce !== 'string' || !BRIDGE_RECEIPT.test(message.arm_nonce)
      || typeof message.child_observation_envelope_sha256 !== 'string'
      || !/^sha256:[0-9a-f]{64}$/.test(message.child_observation_envelope_sha256)
      || typeof message.bridge_arm_receipt_sha256 !== 'string'
      || !/^sha256:[0-9a-f]{64}$/.test(message.bridge_arm_receipt_sha256)
      || !message.bridge_arm || typeof message.bridge_arm !== 'object' || Array.isArray(message.bridge_arm)))) {
    fail('host.invalid_request', 'invalid two-member bridge arm frame');
  }
}
const MAX_CLOSED_CONNECTIONS = 4_096;

// `beforeBind` is for tests: it holds a bind in flight.
export function brokerPlugin({ beforeBind, noticeTimers = {}, bridgeStopTimeoutMs = 4_000,
  enableBridgeQualification = false, enableBridgeRelayIngress = false,
  enableRelayPeerChallenge = false, enableMemberArmExchange = false,
  enableBridgeRelayCompletion = false, enableBridgeRelayPrewrite = false } = {}) {
  const noticePumps = new WeakMap();
  const bridgeConnections = new WeakMap();
  const bridgeOperations = new WeakMap();
  const bridgeRevocationFailures = new WeakMap();
  const stopping = new WeakSet();
  return definePlugin({
    name: NAME,
    version: VERSION,
    hostApi: 1,
    requires: { 'hq-admission': '^0.1.0' },
    services: ['config', 'store', 'identityService', 'events', 'clock', 'log'],
    identityServiceRoutes: NOTICE_ROUTES,
    async init(ctx) {
      const admission = ctx.deps['hq-admission'];
      const noticePump = createNoticePump({ ...ctx.services, options: ctx.services.config.get('notices'), ...noticeTimers });
      noticePumps.set(ctx, noticePump);
      // connection → a member bind in flight, a bridge challenge/bind in
      // flight, then either { runtime_id } or { bridge_receipt }. The two
      // authorities are disjoint. A closed connection has no entry.
      const connections = new Map();
      const closedConnections = new Set();
      bridgeConnections.set(ctx, connections);
      const operations = new Set();
      bridgeOperations.set(ctx, operations);
      const revocationFailures = [];
      bridgeRevocationFailures.set(ctx, revocationFailures);

      function trackBridge(operation, state, containment = false, connection) {
        const entry = { operation, state, containment, connection, closed: false };
        operations.add(entry);
        // Observe both outcomes without changing what the broker caller sees.
        operation.then(() => operations.delete(entry), (error) => {
          operations.delete(entry);
          if (containment) revocationFailures.push(error);
        });
        return entry;
      }

      function beginBridge(run, connection, bindTransition = true) {
        // Register before the first await. The microtask also checks the stop
        // fence, so an accepted frame cannot start after stop begins.
        let entry;
        const operation = Promise.resolve().then(() => {
          if (stopping.has(ctx) || entry.closed || closedConnections.has(connection)) {
            fail('host.invalid_request', 'the bridge connection closed or broker is stopping');
          }
          const result = run();
          if (bindTransition) entry.state = connections.get(connection);
          return result;
        });
        entry = trackBridge(operation, undefined, false, connection);
        return operation;
      }

      async function forgetBridge(connection, state) {
        if (state?.bridge) await admission.forgetBridgeConnection(connection, state.bridge_receipt);
      }

      async function bind(message, connection) {
        const prior = connections.get(connection);
        if (prior) fail('host.invalid_request', prior.binding ? 'a bind is already in flight on this connection' : 'this connection is already bound');
        const pending = { binding: true };
        connections.set(connection, pending);
        let bound;
        try {
          if (beforeBind) await beforeBind();
          bound = await admission.verifyBinding(message, { connection });
        } catch (e) {
          if (connections.get(connection) === pending) connections.delete(connection);
          throw e;
        }
        // The connection closed while hq-admission was answering: its
        // binding dies with it.
        if (connections.get(connection) !== pending) fail('host.invalid_request', 'the connection closed during bind');
        connections.set(connection, { runtime_id: bound.runtime_id });
        return { runtime_id: bound.runtime_id, member_id: bound.member_id, role: bound.role };
      }

      // The first half of a keyed bind. hq-admission keeps the challenge
      // against the connection; an HQ that predates row 16a has none to give.
      async function challenge(message, connection) {
        const prior = connections.get(connection);
        if (prior) fail('host.invalid_request', prior.binding ? 'a bind is already in flight on this connection' : 'this connection is already bound');
        if (typeof admission.bindChallenge !== 'function') fail('host.invalid_request', 'this HQ does not offer bind challenges');
        return admission.bindChallenge(message, { connection });
      }

      async function bridgeChallenge(message, connection, version) {
        const prior = connections.get(connection);
        if (prior) fail('host.invalid_request', prior.binding ? 'a bind is already in flight on this connection' : 'this connection is already bound');
        if (typeof admission[version.challenge] !== 'function' || typeof admission.forgetBridgeConnection !== 'function') {
          fail('host.invalid_request', 'this HQ does not offer bridge bind challenges');
        }
        if (version === BRIDGE_V2) validateProtectedBridgeFrame(message, false);
        if (version === BRIDGE_V3) validateV3BridgeFrame(message, false);
        const pending = { binding: true, bridge: true };
        connections.set(connection, pending);
        let challenge;
        try {
          challenge = await admission[version.challenge](message, { connection });
          if (typeof challenge?.nonce !== 'string' || !BRIDGE_RECEIPT.test(challenge.nonce)
            || challenge.algorithm !== 'hmac-sha256' || challenge.context !== version.context
            || typeof challenge.hq_epoch !== 'string' || !BRIDGE_RECEIPT.test(challenge.hq_epoch)
            || typeof challenge.expires_at !== 'string' || !Number.isFinite(Date.parse(challenge.expires_at))) {
            fail('host.invalid_request', 'HQ returned an invalid bridge challenge');
          }
        }
        catch (e) {
          if (connections.get(connection) === pending) connections.delete(connection);
          // HQ may have installed a challenge before failing to return it.
          // Revoke by connection even when no receipt was delivered.
          await admission.forgetBridgeConnection(connection);
          pending.contained = true;
          throw e;
        }
        if (connections.get(connection) !== pending) {
          await admission.forgetBridgeConnection(connection);
          pending.contained = true;
          fail('host.invalid_request', 'the connection closed during bridge challenge');
        }
        connections.set(connection, { bridge: true, challenged: version });
        return challenge;
      }

      async function bridgeBind(message, connection, version) {
        const prior = connections.get(connection);
        if (prior?.challenged !== version) fail('host.invalid_request', prior?.binding ? 'a bind is already in flight on this connection' : 'bridge.bind requires a challenge on this connection');
        if (typeof admission[version.verify] !== 'function' || typeof admission.forgetBridgeConnection !== 'function') {
          fail('host.invalid_request', 'this HQ does not offer bridge binding');
        }
        const pending = { binding: true, bridge: true };
        connections.set(connection, pending);
        let bound;
        try {
          if (beforeBind) await beforeBind();
          if (version === BRIDGE_V2) validateProtectedBridgeFrame(message, true);
          if (version === BRIDGE_V3) validateV3BridgeFrame(message, true);
          bound = await admission[version.verify](message, { connection });
          if (typeof bound?.bind_receipt !== 'string' || !BRIDGE_RECEIPT.test(bound.bind_receipt)) fail('host.invalid_request', 'HQ returned an invalid bridge receipt');
        } catch (e) {
          if (connections.get(connection) === pending) connections.delete(connection);
          // A malformed or rejected HQ result may follow creation of a live
          // receipt. HQ revokes by connection when the receipt is unknown.
          await admission.forgetBridgeConnection(connection);
          pending.contained = true;
          throw e;
        }
        if (connections.get(connection) !== pending) {
          await admission.forgetBridgeConnection(connection, bound.bind_receipt);
          pending.contained = true;
          fail('host.invalid_request', 'the connection closed during bridge bind');
        }
        connections.set(connection, { bridge: true, bridge_receipt: bound.bind_receipt, version,
          selectors: version === BRIDGE_V2
            ? Object.fromEntries(BRIDGE_V2_SELECTORS.map(([key]) => [key, message[key]]))
            : version === BRIDGE_V3
              ? Object.fromEntries(BRIDGE_V3_SELECTORS.map(([key]) => [key, message[key]]))
              : undefined });
        return { bind_receipt: bound.bind_receipt };
      }

      ctx.broker.serve({
        async accept(kind, message, { connection }) {
          if (stopping.has(ctx)) fail('host.invalid_request', 'the broker is stopping');
          if (kind === BIND_CHALLENGE) return challenge(message, connection);
          if (kind === BIND) return bind(message, connection);
          if (kind === BRIDGE_BIND_CHALLENGE) return beginBridge(() => bridgeChallenge(message, connection, BRIDGE_V1), connection);
          if (kind === BRIDGE_BIND_CHALLENGE_V2) return beginBridge(() => bridgeChallenge(message, connection, BRIDGE_V2), connection);
          if (kind === BRIDGE_BIND_CHALLENGE_V3) return beginBridge(() => bridgeChallenge(message, connection, BRIDGE_V3), connection);
          if (kind === BRIDGE_BIND) return beginBridge(() => bridgeBind(message, connection, BRIDGE_V1), connection);
          if (kind === BRIDGE_BIND_V2) return beginBridge(() => bridgeBind(message, connection, BRIDGE_V2), connection);
          if (kind === BRIDGE_BIND_V3) return beginBridge(() => bridgeBind(message, connection, BRIDGE_V3), connection);
          const state = connections.get(connection);
          if (kind === BRIDGE_QUALIFICATION_MESSAGES) {
            let hqEnabled = false;
            try { hqEnabled = admission.bridgeQualificationEnabledV2?.() === true; } catch { /* refuse below */ }
            if (enableBridgeQualification !== true || !hqEnabled || state?.version !== BRIDGE_V2
              || typeof admission.qualifyBridgeMessagesV2 !== 'function') {
              fail('caller_mismatch', 'qualification requires a dedicated v2 bridge binding');
            }
            return beginBridge(async () => {
              if (connections.get(connection) !== state) fail('caller_mismatch', 'bridge binding is no longer live');
              const result = await admission.qualifyBridgeMessagesV2(message, { connection }, state.bridge_receipt);
              if (stopping.has(ctx) || connections.get(connection) !== state) {
                fail('caller_mismatch', 'bridge binding is no longer live');
              }
              return result;
            }, connection, false);
          }
          if (kind === BRIDGE_RELAY_INGRESS) {
            let hqEnabled = false;
            try { hqEnabled = admission.bridgeRelayIngressEnabledV2?.() === true; } catch { /* refuse below */ }
            if (enableBridgeRelayIngress !== true || !hqEnabled || state?.version !== BRIDGE_V2
              || typeof state.bridge_receipt !== 'string'
              || typeof admission.relayBridgeIngressV2 !== 'function') {
              fail('caller_mismatch', 'relay ingress requires a dedicated v2 bridge binding');
            }
            if (!message || typeof message !== 'object' || Array.isArray(message)
              || Object.keys(message).length !== 3 || !Object.hasOwn(message, 'model')
              || !Object.hasOwn(message, 'prompt_sha256') || !Object.hasOwn(message, 'peer')
              || typeof message.model !== 'string' || !BRIDGE_ID.test(message.model)
              || typeof message.prompt_sha256 !== 'string' || !SHA256_DIGEST.test(message.prompt_sha256)
              || !validRelayPeer(message.peer)) {
              fail('host.invalid_request', 'relay ingress requires measured peer identity');
            }
            return beginBridge(async () => {
              if (connections.get(connection) !== state) fail('caller_mismatch', 'bridge binding is no longer live');
              if (state.relayIngress !== undefined) fail('caller_mismatch', 'relay ingress was already attempted');
              // Reserve this bound connection before awaiting HQ, preventing a
              // concurrent ingress or completion from racing the first one.
              state.relayIngress = null;
              // The signed B assignment and HQ's live bind own routing. Comms
              // treats the request as opaque and adds no C ticket, runtime ID,
              // member token or endpoint selector. HQ must validate or reject
              // any such claims inside the untrusted payload.
              const result = await admission.relayBridgeIngressV2(message, { connection }, state.bridge_receipt);
              if (stopping.has(ctx) || connections.get(connection) !== state) {
                fail('caller_mismatch', 'bridge binding is no longer live');
              }
              state.relayIngress = { model: message.model, request_sha256: message.prompt_sha256,
                peer: Object.fromEntries(RELAY_PEER_FIELDS.map((key) => [key, message.peer[key]])) };
              return result;
            }, connection, false);
          }
          if (kind === STAGE2A_RELAY_PEER_CHALLENGE) {
            let hqEnabled = false;
            try { hqEnabled = admission.stage2aRelayPeerChallengeEnabled?.() === true; } catch { /* refuse below */ }
            if (enableRelayPeerChallenge !== true || !hqEnabled
              || state?.version?.context !== 'agent-bot-stage2a-bridge-bind-v3'
              || typeof state.bridge_receipt !== 'string'
              || typeof admission.stage2aRelayPeerChallenge !== 'function') {
              fail('caller_mismatch', 'live relay peer requires a dedicated v3 bridge binding');
            }
            return beginBridge(async () => {
              if (connections.get(connection) !== state) fail('caller_mismatch', 'bridge binding is no longer live');
              const result = await admission.stage2aRelayPeerChallenge(message,
                { connection }, state.bridge_receipt);
              if (stopping.has(ctx) || connections.get(connection) !== state) {
                fail('caller_mismatch', 'bridge binding is no longer live');
              }
              return result;
            }, connection, false);
          }
          if (kind === BRIDGE_MEMBER_OBSERVE_V3 || kind === BRIDGE_MEMBER_ARM_V3) {
            let hqEnabled = false;
            try { hqEnabled = admission.stage2aMemberArmExchangeEnabledV3?.() === true; } catch { /* refuse below */ }
            const method = kind === BRIDGE_MEMBER_OBSERVE_V3
              ? 'stage2aMemberObserveV3' : 'stage2aMemberArmV3';
            if (enableMemberArmExchange !== true || !hqEnabled || state?.version !== BRIDGE_V3
              || typeof state.bridge_receipt !== 'string' || typeof admission[method] !== 'function') {
              fail('caller_mismatch', 'member arm requires a dedicated v3 bridge binding');
            }
            validateV3MemberFrame(message, kind, state.selectors);
            return beginBridge(async () => {
              if (connections.get(connection) !== state) fail('caller_mismatch', 'bridge binding is no longer live');
              const result = await admission[method](message, { connection }, state.bridge_receipt);
              if (stopping.has(ctx) || connections.get(connection) !== state) {
                fail('caller_mismatch', 'bridge binding is no longer live');
              }
              return result;
            }, connection, false);
          }
          if (kind === BRIDGE_RELAY_PREWRITE) {
            let hqEnabled = false;
            try { hqEnabled = admission.bridgeRelayPrewriteEnabledV2?.() === true; } catch { /* refuse below */ }
            if (enableBridgeRelayPrewrite !== true || !hqEnabled || state?.version !== BRIDGE_V2
              || typeof state.bridge_receipt !== 'string'
              || typeof admission.prewriteBridgeRelayV2 !== 'function') {
              fail('caller_mismatch', 'relay prewrite requires a dedicated v2 bridge binding');
            }
            return beginBridge(async () => {
              if (connections.get(connection) !== state || state.relayPrewrite !== undefined || !state.relayIngress) {
                fail('caller_mismatch', 'bridge binding is no longer live or prewrite was attempted');
              }
              state.relayPrewrite = null;
              const ingress = state.relayIngress;
              const keys = ['selectors', 'bind_receipt_sha256', 'peer', 'peer_sha256',
                'request_sha256', 'prompt_sha256', 'model',
                'response_wire_sha256', 'response_wire_bytes', 'http_status'];
              const receiptDigest = `sha256:${createHash('sha256').update(state.bridge_receipt).digest('hex')}`;
              if (!message || typeof message !== 'object' || Array.isArray(message)
                || Object.keys(message).length !== keys.length || keys.some((key) => !Object.hasOwn(message, key))
                || !message.selectors || typeof message.selectors !== 'object' || Array.isArray(message.selectors)
                || Object.keys(message.selectors).length !== BRIDGE_V2_SELECTORS.length
                || BRIDGE_V2_SELECTORS.some(([key]) => message.selectors[key] !== state.selectors[key])
                || message.bind_receipt_sha256 !== receiptDigest
                || !sameRelayPeer(ingress.peer, message.peer)
                || message.peer_sha256 !== relayPeerDigest(ingress.peer)
                || message.request_sha256 !== ingress.request_sha256
                || !SHA256_DIGEST.test(message.prompt_sha256) || message.model !== ingress.model
                || !SHA256_DIGEST.test(message.response_wire_sha256)
                || !Number.isSafeInteger(message.response_wire_bytes) || message.response_wire_bytes < 1
                || message.http_status !== 200) {
                fail('caller_mismatch', 'relay prewrite does not match bound ingress and response intent');
              }
              const result = await admission.prewriteBridgeRelayV2(message, { connection }, state.bridge_receipt);
              if (stopping.has(ctx) || connections.get(connection) !== state || result?.accepted !== true
                || typeof result.prewrite_receipt !== 'string' || !BRIDGE_RECEIPT.test(result.prewrite_receipt)) {
                fail('caller_mismatch', 'HQ did not persist live prewrite observation');
              }
              state.relayPrewrite = { ...message, prewrite_receipt: result.prewrite_receipt };
              return { accepted: true, prewrite_receipt: result.prewrite_receipt };
            }, connection, false);
          }
          if (kind === BRIDGE_RELAY_COMPLETE) {
            let hqEnabled = false;
            try { hqEnabled = admission.bridgeRelayCompletionEnabledV2?.() === true; } catch { /* refuse below */ }
            if (enableBridgeRelayCompletion !== true || !hqEnabled || state?.version !== BRIDGE_V2
              || typeof state.bridge_receipt !== 'string'
              || typeof admission.completeBridgeRelayV2 !== 'function') {
              fail('caller_mismatch', 'relay completion requires a dedicated v2 bridge binding');
            }
            return beginBridge(async () => {
              if (connections.get(connection) !== state || state.relayComplete !== undefined ||
                !state.relayIngress || !state.relayPrewrite) {
                fail('caller_mismatch', 'bridge binding is no longer live or completion was attempted');
              }
              state.relayComplete = true;
              const ingress = state.relayIngress;
              const prewrite = state.relayPrewrite;
              const keys = ['selectors', 'bind_receipt_sha256', 'peer', 'peer_sha256',
                'prewrite_receipt', 'request_sha256', 'prompt_sha256', 'model',
                'response_wire_sha256', 'response_wire_bytes', 'http_status', 'write_started_at',
                'write_completed_at', 'completion_origin_mac'];
              const receiptDigest = `sha256:${createHash('sha256').update(state.bridge_receipt).digest('hex')}`;
              if (!ingress || !message || typeof message !== 'object' || Array.isArray(message)
                || Object.keys(message).length !== keys.length || keys.some((key) => !Object.hasOwn(message, key))
                || !message.selectors || typeof message.selectors !== 'object' || Array.isArray(message.selectors)
                || Object.keys(message.selectors).length !== BRIDGE_V2_SELECTORS.length
                || BRIDGE_V2_SELECTORS.some(([key]) => message.selectors[key] !== state.selectors[key])
                || message.bind_receipt_sha256 !== receiptDigest
                || message.prewrite_receipt !== prewrite.prewrite_receipt
                || !sameRelayPeer(ingress.peer, message.peer)
                || message.peer_sha256 !== relayPeerDigest(ingress.peer)
                || message.request_sha256 !== ingress.request_sha256 || !SHA256_DIGEST.test(message.request_sha256)
                || message.prompt_sha256 !== prewrite.prompt_sha256 || message.model !== ingress.model
                || message.response_wire_sha256 !== prewrite.response_wire_sha256
                || message.response_wire_bytes !== prewrite.response_wire_bytes
                || message.http_status !== prewrite.http_status
                || typeof message.completion_origin_mac !== 'string'
                || !BRIDGE_RECEIPT.test(message.completion_origin_mac)
                || typeof message.write_started_at !== 'string' || !Number.isFinite(Date.parse(message.write_started_at))
                || typeof message.write_completed_at !== 'string' || !Number.isFinite(Date.parse(message.write_completed_at))
                || Date.parse(message.write_completed_at) < Date.parse(message.write_started_at)) {
                fail('caller_mismatch', 'relay completion does not match its bound ingress and response');
              }
              const result = await admission.completeBridgeRelayV2(message, { connection }, state.bridge_receipt);
              if (stopping.has(ctx) || connections.get(connection) !== state || result?.accepted !== true) {
                fail('caller_mismatch', 'HQ did not persist relay completion on the live binding');
              }
              return { accepted: true };
            }, connection, false);
          }
          if (state?.bridge_receipt) fail('caller_mismatch', 'a bridge binding does not grant member delivery');
          if (!state?.runtime_id) fail('caller_mismatch', 'a member binds its connection before anything else');
          return ctx.broker.deliver(kind, message, { runtime_id: state.runtime_id });
        },
        async closed(connection) {
          // A bridge frame may have been accepted but not entered its first
          // microtask yet. Tombstone its operation before any await.
          closedConnections.add(connection);
          for (const entry of operations) if (entry.connection === connection) entry.closed = true;
          if (closedConnections.size > MAX_CLOSED_CONNECTIONS)
            closedConnections.delete(closedConnections.values().next().value);
          const state = connections.get(connection);
          connections.delete(connection);
          // HQ's revocation hook must synchronously remove the live receipt
          // before its promise settles; the socket server may not await this.
          const revocation = forgetBridge(connection, state);
          if (state?.bridge) trackBridge(revocation, state, true);
          try { admission.forgetConnection?.(connection); } finally { await revocation; }
        },
      });

      return {
        provides: {
          boundConnections: () => [...connections.values()].filter((s) => s.runtime_id).length,
          boundBridgeConnections: () => [...connections.values()].filter((s) => s.bridge_receipt).length,
          notices: noticePump,
        },
      };
    },
    async start(ctx) { noticePumps.get(ctx).start(); },
    async stop(ctx) {
      stopping.add(ctx);
      noticePumps.get(ctx).stop();
      const connections = bridgeConnections.get(ctx);
      const admission = ctx.deps['hq-admission'];
      const revocations = [];
      for (const [connection, state] of connections) {
        connections.delete(connection);
        if (state.bridge) {
          try { revocations.push(Promise.resolve(admission.forgetBridgeConnection(connection, state.bridge_receipt))); }
          catch (e) { revocations.push(Promise.reject(e)); }
        }
      }
      const entries = [...bridgeOperations.get(ctx)];
      let timeout;
      const results = await Promise.race([
        Promise.allSettled([...revocations, ...entries.map(({ operation }) => operation)]),
        new Promise((_, reject) => {
          timeout = setTimeout(() => reject(new Error('bridge containment unconfirmed: stop drain timed out')), bridgeStopTimeoutMs);
        }),
      ]).finally(() => clearTimeout(timeout));
      const failed = results.find((result, index) => result.status === 'rejected' &&
        (index < revocations.length || entries[index - revocations.length].containment ||
          (entries[index - revocations.length].state?.bridge &&
            !entries[index - revocations.length].state.contained)));
      if (failed) throw failed.reason;
      if (bridgeRevocationFailures.get(ctx).length) throw bridgeRevocationFailures.get(ctx)[0];
    },
  });
}
