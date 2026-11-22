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

import { readFileSync } from 'node:fs';
import { fail } from '../vendor/agent-bot-sdk/errors.mjs';
import { definePlugin } from '../vendor/agent-bot-sdk/plugin.mjs';
import { createNoticePump, NOTICE_ROUTES } from './notices.mjs';

const { name: NAME, version: VERSION } = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));

export const BIND = 'bind';
export const BIND_CHALLENGE = 'bind.challenge';
export const BRIDGE_BIND = 'bridge.bind';
export const BRIDGE_BIND_CHALLENGE = 'bridge.bind.challenge';

const BRIDGE_RECEIPT = /^[0-9a-f]{64}$/;
const BRIDGE_CONTEXT = 'agent-bot-stage2a-bridge-bind-v1';

// `beforeBind` is for tests: it holds a bind in flight.
export function brokerPlugin({ beforeBind, noticeTimers = {} } = {}) {
  const noticePumps = new WeakMap();
  const bridgeConnections = new WeakMap();
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
      bridgeConnections.set(ctx, connections);

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

      async function bridgeChallenge(message, connection) {
        const prior = connections.get(connection);
        if (prior) fail('host.invalid_request', prior.binding ? 'a bind is already in flight on this connection' : 'this connection is already bound');
        if (typeof admission.bridgeBindChallenge !== 'function' || typeof admission.forgetBridgeConnection !== 'function') {
          fail('host.invalid_request', 'this HQ does not offer bridge bind challenges');
        }
        const pending = { binding: true, bridge: true };
        connections.set(connection, pending);
        let challenge;
        try {
          challenge = await admission.bridgeBindChallenge(message, { connection });
          if (typeof challenge?.nonce !== 'string' || !BRIDGE_RECEIPT.test(challenge.nonce)
            || challenge.algorithm !== 'hmac-sha256' || challenge.context !== BRIDGE_CONTEXT
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
          throw e;
        }
        if (connections.get(connection) !== pending) {
          await admission.forgetBridgeConnection(connection);
          fail('host.invalid_request', 'the connection closed during bridge challenge');
        }
        connections.set(connection, { bridge: true, challenged: true });
        return challenge;
      }

      async function bridgeBind(message, connection) {
        const prior = connections.get(connection);
        if (!prior?.challenged) fail('host.invalid_request', prior?.binding ? 'a bind is already in flight on this connection' : 'bridge.bind requires a challenge on this connection');
        if (typeof admission.verifyBridgeBinding !== 'function' || typeof admission.forgetBridgeConnection !== 'function') {
          fail('host.invalid_request', 'this HQ does not offer bridge binding');
        }
        const pending = { binding: true, bridge: true };
        connections.set(connection, pending);
        let bound;
        try {
          if (beforeBind) await beforeBind();
          bound = await admission.verifyBridgeBinding(message, { connection });
          if (typeof bound?.bind_receipt !== 'string' || !BRIDGE_RECEIPT.test(bound.bind_receipt)) fail('host.invalid_request', 'HQ returned an invalid bridge receipt');
        } catch (e) {
          if (connections.get(connection) === pending) connections.delete(connection);
          // A malformed or rejected HQ result may follow creation of a live
          // receipt. HQ revokes by connection when the receipt is unknown.
          await admission.forgetBridgeConnection(connection);
          throw e;
        }
        if (connections.get(connection) !== pending) {
          await admission.forgetBridgeConnection(connection, bound.bind_receipt);
          fail('host.invalid_request', 'the connection closed during bridge bind');
        }
        connections.set(connection, { bridge: true, bridge_receipt: bound.bind_receipt });
        return { bind_receipt: bound.bind_receipt };
      }

      ctx.broker.serve({
        async accept(kind, message, { connection }) {
          if (kind === BIND_CHALLENGE) return challenge(message, connection);
          if (kind === BIND) return bind(message, connection);
          if (kind === BRIDGE_BIND_CHALLENGE) return bridgeChallenge(message, connection);
          if (kind === BRIDGE_BIND) return bridgeBind(message, connection);
          const state = connections.get(connection);
          if (state?.bridge_receipt) fail('caller_mismatch', 'a bridge binding does not grant member delivery');
          if (!state?.runtime_id) fail('caller_mismatch', 'a member binds its connection before anything else');
          return ctx.broker.deliver(kind, message, { runtime_id: state.runtime_id });
        },
        async closed(connection) {
          const state = connections.get(connection);
          connections.delete(connection);
          // HQ's revocation hook must synchronously remove the live receipt
          // before its promise settles; the socket server may not await this.
          const revocation = forgetBridge(connection, state);
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
      const results = await Promise.allSettled(revocations);
      const failed = results.find((result) => result.status === 'rejected');
      if (failed) throw failed.reason;
    },
  });
}
