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

export const BRIDGE_QUALIFICATION_MESSAGES = 'bridge.qualification.messages.v1';
export const BRIDGE_RELAY_INGRESS = 'bridge.relay.ingress.v1';
export const BRIDGE_RELAY_COMPLETE = 'bridge.relay.complete.v1';

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
const BRIDGE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const BRIDGE_V2_SELECTORS = [
  ['installation_id', BRIDGE_ID],
  ['start_id', /^st_[0-9a-f]{24}$/],
  ['launch_id', /^ln_[0-9a-f]{24}$/],
  ['plan_id', BRIDGE_ID],
  ['plan_digest', BRIDGE_RECEIPT],
  ['reservation_digest', /^sha256:[0-9a-f]{64}$/],
];

function validateProtectedBridgeFrame(message, withProof) {
  const fields = withProof ? [...BRIDGE_V2_SELECTORS, ['proof', BRIDGE_RECEIPT]] : BRIDGE_V2_SELECTORS;
  if (!message || typeof message !== 'object' || Array.isArray(message)
    || Object.keys(message).length !== fields.length
    || fields.some(([key, pattern]) => !Object.hasOwn(message, key)
      || typeof message[key] !== 'string' || !pattern.test(message[key]))) {
    fail('host.invalid_request', 'invalid protected bridge bind frame');
  }
}
const MAX_CLOSED_CONNECTIONS = 4_096;

// `beforeBind` is for tests: it holds a bind in flight.
export function brokerPlugin({ beforeBind, noticeTimers = {}, bridgeStopTimeoutMs = 4_000,
  enableBridgeQualification = false, enableBridgeRelayIngress = false,
  enableBridgeRelayCompletion = false } = {}) {
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
          selectors: version === BRIDGE_V2 ? Object.fromEntries(BRIDGE_V2_SELECTORS.map(([key]) => [key, message[key]])) : undefined });
        return { bind_receipt: bound.bind_receipt };
      }

      ctx.broker.serve({
        async accept(kind, message, { connection }) {
          if (stopping.has(ctx)) fail('host.invalid_request', 'the broker is stopping');
          if (kind === BIND_CHALLENGE) return challenge(message, connection);
          if (kind === BIND) return bind(message, connection);
          if (kind === BRIDGE_BIND_CHALLENGE) return beginBridge(() => bridgeChallenge(message, connection, BRIDGE_V1), connection);
          if (kind === BRIDGE_BIND_CHALLENGE_V2) return beginBridge(() => bridgeChallenge(message, connection, BRIDGE_V2), connection);
          if (kind === BRIDGE_BIND) return beginBridge(() => bridgeBind(message, connection, BRIDGE_V1), connection);
          if (kind === BRIDGE_BIND_V2) return beginBridge(() => bridgeBind(message, connection, BRIDGE_V2), connection);
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
              state.relayIngress = { model: message?.model, request_sha256: message?.prompt_sha256 };
              return result;
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
              if (connections.get(connection) !== state || state.relayComplete !== undefined || !state.relayIngress) {
                fail('caller_mismatch', 'bridge binding is no longer live or completion was attempted');
              }
              state.relayComplete = true;
              const ingress = state.relayIngress;
              const keys = ['selectors', 'bind_receipt_sha256', 'request_sha256', 'prompt_sha256', 'model',
                'response_wire_sha256', 'response_wire_bytes', 'http_status', 'write_started_at', 'write_completed_at'];
              const receiptDigest = `sha256:${createHash('sha256').update(state.bridge_receipt).digest('hex')}`;
              if (!ingress || !message || typeof message !== 'object' || Array.isArray(message)
                || Object.keys(message).length !== keys.length || keys.some((key) => !Object.hasOwn(message, key))
                || !message.selectors || typeof message.selectors !== 'object' || Array.isArray(message.selectors)
                || Object.keys(message.selectors).length !== BRIDGE_V2_SELECTORS.length
                || BRIDGE_V2_SELECTORS.some(([key]) => message.selectors[key] !== state.selectors[key])
                || message.bind_receipt_sha256 !== receiptDigest
                || message.request_sha256 !== ingress.request_sha256 || !SHA256_DIGEST.test(message.request_sha256)
                || !SHA256_DIGEST.test(message.prompt_sha256) || message.model !== ingress.model
                || !SHA256_DIGEST.test(message.response_wire_sha256)
                || !Number.isSafeInteger(message.response_wire_bytes) || message.response_wire_bytes < 1
                || message.http_status !== 200
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
