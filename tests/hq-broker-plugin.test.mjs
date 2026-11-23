// Broker mode as an HQ plugin (ADR-0306), on the vendored SDK's test host:
// the vendored SDK is byte-identical to its agent-bot-hq revision, the
// plugin passes the SDK conformance suite, and it binds, refuses and
// delivers as agent-bot-hq plan §4.9 specifies.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { join, relative } from 'node:path';
import test from 'node:test';
import { agentBotHq, SOURCE, VENDOR } from './hq-agent-bot-hq.mjs';
import {
  BRIDGE_BIND, BRIDGE_BIND_CHALLENGE, BRIDGE_BIND_V2, BRIDGE_BIND_CHALLENGE_V2,
  BRIDGE_BIND_V3, BRIDGE_BIND_CHALLENGE_V3, BRIDGE_QUALIFICATION_MESSAGES,
  BRIDGE_RELAY_INGRESS, STAGE2A_RELAY_PEER_CHALLENGE, brokerPlugin,
} from '../lib/hq-plugin/broker.mjs';
import plugin from '../lib/hq-plugin/plugin.mjs';
import { checkPlugin, createTestHost, definePlugin } from '../lib/vendor/agent-bot-sdk/index.mjs';
import { fail } from '../lib/vendor/agent-bot-sdk/errors.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const code = (c) => (e) => { assert.equal(e.code, c, e.message); return true; };
const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

const walk = (dir) => readdirSync(dir).flatMap((name) => {
  const path = join(dir, name);
  return statSync(path).isDirectory() ? walk(path) : [path];
});

test('the vendored SDK is byte-identical to its agent-bot-hq revision, with nothing added', () => {
  const root = agentBotHq();
  const vendored = walk(VENDOR).map((p) => relative(VENDOR, p)).filter((p) => p !== 'source.json' && p !== 'LICENSE').sort();
  assert.deepEqual(vendored.map((p) => `sdk/${p}`), Object.keys(SOURCE.files).sort());
  assert.deepEqual(walk(join(root, 'sdk')).map((p) => relative(root, p)).sort(), Object.keys(SOURCE.files).sort(), 'every SDK file is vendored');
  for (const [path, digest] of Object.entries(SOURCE.files)) {
    const bytes = readFileSync(join(VENDOR, path.slice('sdk/'.length)));
    assert.equal(sha256(bytes), digest, `${path} hash`);
    assert.ok(bytes.equals(readFileSync(join(root, path))), `${path} equals agent-bot-hq ${SOURCE.commit}`);
  }
  assert.ok(readFileSync(join(VENDOR, 'LICENSE')).equals(readFileSync(join(root, 'LICENSE'))), 'the SDK ships with its MIT notice');
});

// A stand-in for hq-admission: two live runtimes and their bindings.
const RUNTIMES = {
  rt_lead: { channel_binding: 'cb_lead_0123456789abcdef', member_id: 'm_lead', role: 'lead' },
  rt_spec: { channel_binding: 'cb_spec_0123456789abcdef', member_id: 'm_spec', role: 'specialist' },
};
const admission = (calls = []) => definePlugin({
  name: 'hq-admission',
  version: '0.1.0',
  hostApi: 1,
  async init() {
    return { provides: { async verifyBinding(input) {
      calls.push(input);
      const rt = RUNTIMES[input?.runtime_id];
      if (!rt || rt.channel_binding !== input.channel_binding) fail('caller_mismatch', 'the channel binding does not match');
      return Object.freeze({ runtime_id: input.runtime_id, soul_id: 'agent_x', member_id: rt.member_id, role: rt.role, installation_epoch: 1, lease_generation: 1 });
    } } };
  },
});
const consumer = (seen) => definePlugin({
  name: 'consumer',
  version: '1.0.0',
  hostApi: 1,
  async init(ctx) {
    ctx.broker.registerKind({ kind: 'task.commit', consume: (message, meta) => { seen.push({ message, meta }); return { committed: message.n }; } });
  },
});
const bindAs = (id) => ({ runtime_id: id, channel_binding: RUNTIMES[id].channel_binding });

async function hostWith(options) {
  const seen = [];
  const calls = [];
  const host = createTestHost({ plugins: [admission(calls), consumer(seen), brokerPlugin(options)] });
  await host.start();
  return { host, seen, calls, broker: host.provided(pkg.name) };
}

test('the plugin is agent-comms at its package version, needs hq-admission, and passes SDK conformance', async () => {
  assert.equal(plugin.name, pkg.name);
  assert.equal(plugin.version, pkg.version);
  assert.deepEqual({ ...plugin.requires }, { 'hq-admission': '^0.1.0' });
  const r = await checkPlugin(plugin, { deps: [admission()] });
  assert.ok(r.ok, JSON.stringify(r.results.filter((x) => !x.ok)));
});

test('the installed package loads under its exact HQ pin and passes SDK conformance', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'agent-comms plugin '));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const build = fileURLToPath(new URL('../scripts/build-hq-plugin.mjs', import.meta.url));
  const { treeDigest, loadPlugins } = await import(pathToFileURL(join(agentBotHq(), 'hq/plugins.mjs')));
  const digests = [];
  for (const name of ['first', 'second']) {
    const stage = join(root, name);
    mkdirSync(stage);
    execFileSync(process.execPath, [build, stage]);
    const installed = join(stage, pkg.name);
    const digest = treeDigest(installed);
    digests.push(digest);
    assert.deepEqual(JSON.parse(readFileSync(join(installed, 'package.json'))), { name: pkg.name, version: pkg.version });
    const options = { dir: stage, available: { 'hq-admission': admission().version } };
    const unpinned = await loadPlugins(options);
    assert.equal(unpinned.report[0].state, 'refused');
    const pins = { plugins: [{ name: pkg.name, version: pkg.version, sha256: digest }] };
    const pinned = await loadPlugins({ ...options, pins });
    assert.equal(pinned.report[0].state, 'loaded');
    assert.equal(pinned.report[0].dev, undefined);
    const result = await checkPlugin(pinned.loaded[0].plugin, { deps: [admission()] });
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.throws(() => execFileSync(process.execPath, [build, stage], { stdio: 'pipe' }), /destination already exists/);
    assert.equal(treeDigest(installed), digest);
  }
  assert.equal(digests[0], digests[1]);

  // The installed tree also contains the producer's runtime inputs.
  const altered = join(root, 'first', pkg.name);
  mkdirSync(join(altered, 'scripts'));
  const alteredBuild = join(altered, 'scripts', 'build-hq-plugin.mjs');
  copyFileSync(build, alteredBuild);
  writeFileSync(join(altered, 'lib/vendor/agent-bot-sdk/README.md'), 'changed after vendoring');
  const refused = join(root, 'refused');
  mkdirSync(refused);
  assert.throws(() => execFileSync(process.execPath, [alteredBuild, refused], { stdio: 'pipe' }), /vendored SDK digest mismatch/);
  assert.deepEqual(readdirSync(refused), []);
});

test('it serves the broker, binds a connection, and delivers with the runtime ID alone', async () => {
  const { host, seen, calls, broker } = await hostWith();
  assert.deepEqual(host.registrations().servers, [{ key: 'broker', plugin: pkg.name }]);
  assert.deepEqual(await host.brokerAccept('bind', bindAs('rt_lead'), { connection: 'bc_1' }), { runtime_id: 'rt_lead', member_id: 'm_lead', role: 'lead' });
  assert.deepEqual(calls, [bindAs('rt_lead')]);
  assert.equal(broker.boundConnections(), 1);
  assert.deepEqual(await host.brokerAccept('task.commit', { n: 1 }, { connection: 'bc_1' }), { committed: 1 });
  assert.deepEqual(seen.map((s) => ({ ...s.meta })), [{ runtime_id: 'rt_lead' }]);
  // The binding never travels past the plugin.
  assert.equal(JSON.stringify(seen).includes(RUNTIMES.rt_lead.channel_binding), false);
});

test('a frame before bind, a wrong binding, an unknown runtime and a second bind are refused', async () => {
  const { host, seen, broker } = await hostWith();
  await assert.rejects(host.brokerAccept('task.commit', { n: 1 }, { connection: 'bc_1' }), code('caller_mismatch'));
  await assert.rejects(host.brokerAccept('bind', { runtime_id: 'rt_lead', channel_binding: RUNTIMES.rt_spec.channel_binding }, { connection: 'bc_1' }), code('caller_mismatch'));
  await assert.rejects(host.brokerAccept('bind', { runtime_id: 'rt_unknown', channel_binding: RUNTIMES.rt_spec.channel_binding }, { connection: 'bc_1' }), code('caller_mismatch'));
  // A refused bind leaves the connection unbound, so it may bind again.
  await assert.rejects(host.brokerAccept('task.commit', { n: 1 }, { connection: 'bc_1' }), code('caller_mismatch'));
  await host.brokerAccept('bind', bindAs('rt_spec'), { connection: 'bc_1' });
  await assert.rejects(host.brokerAccept('bind', bindAs('rt_lead'), { connection: 'bc_1' }), code('host.invalid_request'));
  await host.brokerAccept('task.commit', { n: 2 }, { connection: 'bc_1' });
  assert.deepEqual(seen.map((s) => s.meta.runtime_id), ['rt_spec']);
  assert.equal(broker.boundConnections(), 1);
  await assert.rejects(host.brokerAccept('notes.take', {}, { connection: 'bc_1' }), code('host.unknown_kind'));
});

test('connections are independent, and closing one drops only its binding', async () => {
  const { host, seen, broker } = await hostWith();
  await host.brokerAccept('bind', bindAs('rt_lead'), { connection: 'bc_1' });
  await host.brokerAccept('bind', bindAs('rt_spec'), { connection: 'bc_2' });
  await host.brokerAccept('bind', bindAs('rt_lead'), { connection: 'bc_3' });
  assert.equal(broker.boundConnections(), 3);
  await host.brokerClosed('bc_1');
  assert.equal(broker.boundConnections(), 2);
  await assert.rejects(host.brokerAccept('task.commit', { n: 1 }, { connection: 'bc_1' }), code('caller_mismatch'));
  await host.brokerAccept('task.commit', { n: 2 }, { connection: 'bc_2' });
  await host.brokerAccept('task.commit', { n: 3 }, { connection: 'bc_3' });
  assert.deepEqual(seen.map((s) => s.meta.runtime_id), ['rt_spec', 'rt_lead']);
});

test('a second bind while the first is in flight is refused, and a close during bind leaves no binding', async () => {
  let release;
  let held;
  const holding = new Promise((r) => { held = r; });
  const { host, broker } = await hostWith({ beforeBind: () => { held(); return new Promise((r) => { release = r; }); } });
  const first = host.brokerAccept('bind', bindAs('rt_lead'), { connection: 'bc_1' });
  await holding;
  await assert.rejects(host.brokerAccept('bind', bindAs('rt_spec'), { connection: 'bc_1' }), code('host.invalid_request'));
  await assert.rejects(host.brokerAccept('task.commit', { n: 1 }, { connection: 'bc_1' }), code('caller_mismatch'));
  await host.brokerClosed('bc_1');
  release();
  await assert.rejects(first, code('host.invalid_request'));
  assert.equal(broker.boundConnections(), 0);
  await assert.rejects(host.brokerAccept('task.commit', { n: 1 }, { connection: 'bc_1' }), code('caller_mismatch'));
});

// Row 16a (agent-bot-hq): the keyed bind. The plugin's part is to hand
// hq-admission the connection, for the challenge and for the bind.
const challengeAdmission = (log) => definePlugin({
  name: 'hq-admission',
  version: '0.1.0',
  hostApi: 1,
  async init() {
    return { provides: {
      async bindChallenge(input, meta) { log.push(['challenge', input, meta]); return { runtime_id: input.runtime_id, nonce: 'n'.repeat(64) }; },
      async verifyBinding(input, meta) {
        log.push(['bind', input, meta]);
        const rt = RUNTIMES[input?.runtime_id];
        if (!rt || input.proof !== 'p'.repeat(64)) fail('caller_mismatch', 'the caller does not match');
        return Object.freeze({ runtime_id: input.runtime_id, soul_id: 'agent_x', member_id: rt.member_id, role: rt.role, installation_epoch: 1, lease_generation: 1 });
      },
      forgetConnection(connection) { log.push(['forget', connection]); },
    } };
  },
});

test('a keyed bind: the challenge and the bind both carry the connection, and a close is passed on', async () => {
  const log = [];
  const host = createTestHost({ plugins: [challengeAdmission(log), brokerPlugin(), consumer([])] });
  await host.start();
  const challenge = await host.brokerAccept('bind.challenge', { runtime_id: 'rt_lead' }, { connection: 'bc_1' });
  assert.equal(challenge.nonce, 'n'.repeat(64));
  const bound = await host.brokerAccept('bind', { runtime_id: 'rt_lead', proof: 'p'.repeat(64) }, { connection: 'bc_1' });
  assert.deepEqual(bound, { runtime_id: 'rt_lead', member_id: 'm_lead', role: 'lead' });
  assert.deepEqual(log, [
    ['challenge', { runtime_id: 'rt_lead' }, { connection: 'bc_1' }],
    ['bind', { runtime_id: 'rt_lead', proof: 'p'.repeat(64) }, { connection: 'bc_1' }],
  ]);
  // A bound connection asks for no further challenge.
  await assert.rejects(host.brokerAccept('bind.challenge', { runtime_id: 'rt_lead' }, { connection: 'bc_1' }), code('host.invalid_request'));
  // A refused bind leaves the connection unbound, free to ask again.
  await host.brokerAccept('bind.challenge', { runtime_id: 'rt_spec' }, { connection: 'bc_2' });
  await assert.rejects(host.brokerAccept('bind', { runtime_id: 'rt_spec', proof: 'f'.repeat(64) }, { connection: 'bc_2' }), code('caller_mismatch'));
  await assert.rejects(host.brokerAccept('task.commit', { n: 1 }, { connection: 'bc_2' }), code('caller_mismatch'));
  await host.brokerAccept('bind.challenge', { runtime_id: 'rt_spec' }, { connection: 'bc_2' });
  await host.brokerClosed('bc_2');
  assert.deepEqual(log.at(-1), ['forget', 'bc_2']);
});

test('an HQ without bind challenges refuses the challenge and still binds by channel binding', async () => {
  const host = createTestHost({ plugins: [admission(), brokerPlugin(), consumer([])] });
  await host.start();
  await assert.rejects(host.brokerAccept('bind.challenge', { runtime_id: 'rt_lead' }, { connection: 'bc_1' }), code('host.invalid_request'));
  await host.brokerAccept('bind', { runtime_id: 'rt_lead', channel_binding: RUNTIMES.rt_lead.channel_binding }, { connection: 'bc_1' });
  await host.brokerClosed('bc_1');
});

const BRIDGE_SCOPE = Object.freeze({
  installation_id: 'install_1', start_id: 'start_1', launch_id: 'launch_1',
  runtime_id: 'rt_bridge', plan_id: 'plan_1', plan_digest: 'a'.repeat(64),
});
const BRIDGE_KEY = 'b'.repeat(64);
const BRIDGE_CONTEXT = 'agent-bot-stage2a-bridge-bind-v1';
const bridgeProof = (nonce, epoch) => createHmac('sha256', Buffer.from(BRIDGE_KEY, 'hex'))
  .update(JSON.stringify([BRIDGE_CONTEXT, nonce, epoch, BRIDGE_SCOPE])).digest('hex');

// HQ owns this authority. The stand-in models a Machine-approved assignment,
// current HQ epoch, one-use HMAC challenge and live receipt. Comms must only
// hand it the actual connection and must never turn B into a member runtime.
const bridgeAdmission = (log, { beforeChallenge, beforeBridgeBind } = {}) => definePlugin({
  name: 'hq-admission', version: '0.1.0', hostApi: 1,
  async init() {
    const challenges = new Map();
    const live = new Map();
    const spent = new Set();
    const closed = new Set();
    const epoch = '7'.repeat(64);
    function assigned(input, connection) {
      return /^b_[0-9]+$/.test(connection) && !closed.has(connection)
        && Object.keys(BRIDGE_SCOPE).every((key) => input?.[key] === BRIDGE_SCOPE[key]);
    }
    return { provides: {
      async verifyBinding() { fail('caller_mismatch', 'B is not a member'); },
      async bridgeBindChallenge(input, { connection }) {
        log.push(['challenge', connection]);
        if (!assigned(input, connection) || spent.has(input.start_id)) fail('caller_mismatch', 'wrong bridge assignment');
        if (beforeChallenge) await beforeChallenge();
        const nonce = 'c'.repeat(64);
        challenges.set(connection, nonce);
        return { nonce, algorithm: 'hmac-sha256', context: BRIDGE_CONTEXT,
          hq_epoch: epoch, expires_at: '2026-11-21T20:00:00.000Z' };
      },
      async verifyBridgeBinding(input, { connection }) {
        log.push(['bind', connection]);
        const nonce = challenges.get(connection);
        challenges.delete(connection);
        if (!nonce || !assigned(input, connection) || spent.has(input.start_id) ||
            input.proof !== bridgeProof(nonce, epoch)) fail('caller_mismatch', 'wrong bridge proof');
        if (beforeBridgeBind) await beforeBridgeBind();
        spent.add(input.start_id);
        const bind_receipt = 'd'.repeat(64);
        live.set(connection, bind_receipt);
        return { bind_receipt };
      },
      forgetBridgeConnection(connection, receipt) {
        log.push(['forget_bridge', connection, receipt]);
        closed.add(connection);
        challenges.delete(connection);
        live.delete(connection);
      },
      liveBridgeReceipt: (connection) => live.get(connection),
      bridgeChallengeActive: (connection) => challenges.has(connection),
    } };
  },
});

test('B bind is separate from member delivery and close revokes its live receipt', async () => {
  const log = [];
  const seen = [];
  const host = createTestHost({ plugins: [bridgeAdmission(log), consumer(seen), brokerPlugin()] });
  await host.start();
  const challenge = await host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_1' });
  assert.equal(challenge.hq_epoch, '7'.repeat(64));
  const bound = await host.brokerAccept(BRIDGE_BIND, { ...BRIDGE_SCOPE, proof: bridgeProof(challenge.nonce, challenge.hq_epoch) }, { connection: 'b_1' });
  assert.deepEqual(bound, { bind_receipt: 'd'.repeat(64) });
  const broker = host.provided(pkg.name);
  assert.equal(broker.boundConnections(), 0);
  assert.equal(broker.boundBridgeConnections(), 1);
  assert.equal(host.provided('hq-admission').liveBridgeReceipt('b_1'), bound.bind_receipt);
  await assert.rejects(host.brokerAccept('task.commit', { n: 1 }, { connection: 'b_1' }), code('caller_mismatch'));
  await assert.rejects(host.brokerAccept('bind', bindAs('rt_lead'), { connection: 'b_1' }), code('host.invalid_request'));
  assert.deepEqual(seen, []);
  await host.brokerClosed('b_1');
  assert.equal(broker.boundBridgeConnections(), 0);
  assert.equal(host.provided('hq-admission').liveBridgeReceipt('b_1'), undefined);
  assert.deepEqual(log.at(-1), ['forget_bridge', 'b_1', bound.bind_receipt]);
  await assert.rejects(host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_2' }), code('caller_mismatch'));
});

test('B bind delegates wrong UID, start, epoch proof and replay refusals to HQ', async () => {
  const host = createTestHost({ plugins: [bridgeAdmission([]), brokerPlugin()] });
  await host.start();
  await assert.rejects(host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'r_1' }), code('caller_mismatch'));
  await assert.rejects(host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'other_b_socket' }), code('caller_mismatch'));
  await assert.rejects(host.brokerAccept(BRIDGE_BIND_CHALLENGE, { ...BRIDGE_SCOPE, start_id: 'old_start' }, { connection: 'b_1' }), code('caller_mismatch'));
  await assert.rejects(host.brokerAccept(BRIDGE_BIND_CHALLENGE, { ...BRIDGE_SCOPE, plan_digest: 'e'.repeat(64) }, { connection: 'b_2' }), code('caller_mismatch'));
  const challenge = await host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_3' });
  await assert.rejects(host.brokerAccept(BRIDGE_BIND, { ...BRIDGE_SCOPE, proof: bridgeProof(challenge.nonce, 'old_hq_epoch') }, { connection: 'b_3' }), code('caller_mismatch'));
  await assert.rejects(host.brokerAccept(BRIDGE_BIND, { ...BRIDGE_SCOPE, proof: bridgeProof(challenge.nonce, challenge.hq_epoch) }, { connection: 'b_3' }), code('host.invalid_request'));
  const fresh = await host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_4' });
  await host.brokerAccept(BRIDGE_BIND, { ...BRIDGE_SCOPE, proof: bridgeProof(fresh.nonce, fresh.hq_epoch) }, { connection: 'b_4' });
  await host.brokerClosed('b_4');
  await assert.rejects(host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_5' }), code('caller_mismatch'));
});

test('bridge route stays unavailable on an HQ without dedicated B authority', async () => {
  const host = createTestHost({ plugins: [admission(), brokerPlugin()] });
  await host.start();
  await assert.rejects(host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_1' }), code('host.invalid_request'));
  await assert.rejects(host.brokerAccept(BRIDGE_BIND, { ...BRIDGE_SCOPE, proof: 'f'.repeat(64) }, { connection: 'b_1' }), code('host.invalid_request'));
  assert.equal(host.provided(pkg.name).boundBridgeConnections(), 0);
});

const PROTECTED_SCOPE = Object.freeze({
  installation_id: 'install_1',
  start_id: `st_${'a'.repeat(24)}`,
  launch_id: `ln_${'b'.repeat(24)}`,
  plan_id: 'plan_1',
  plan_digest: 'c'.repeat(64),
  reservation_digest: `sha256:${'d'.repeat(64)}`,
});
const PROTECTED_CONTEXT = 'agent-bot-stage2a-bridge-bind-v2';
const V3_CONTEXT = 'agent-bot-stage2a-bridge-bind-v3';
const V3_SCOPE = Object.freeze({ installation_id: 'install_1', start_id: `st_${'a'.repeat(24)}`,
  plan_id: 'plan_1', plan_digest: 'c'.repeat(64), reservation_digest: `sha256:${'d'.repeat(64)}`,
  assignment_envelope_sha256: `sha256:${'e'.repeat(64)}`,
  authority_envelope_sha256: `sha256:${'f'.repeat(64)}`,
  member_selectors_sha256: `sha256:${'1'.repeat(64)}` });
const PROTECTED_FRAME = { ...PROTECTED_SCOPE, proof: 'e'.repeat(64) };

const protectedAdmission = (log, context = PROTECTED_CONTEXT, qualificationEnabled = false,
  relayIngressEnabled = false, peerEnabled = false) => definePlugin({
  name: 'hq-admission', version: '0.1.0', hostApi: 1,
  async init() {
    return { provides: {
      bridgeQualificationEnabledV2: () => typeof qualificationEnabled === 'function'
        ? qualificationEnabled() : qualificationEnabled,
      bridgeRelayIngressEnabledV2: () => typeof relayIngressEnabled === 'function'
        ? relayIngressEnabled() : relayIngressEnabled,
      stage2aRelayPeerChallengeEnabled: () => peerEnabled,
      async stage2aRelayPeerChallenge(input, { connection }, receipt) {
        log.push(['live_peer', input, connection, receipt]);
        return { verdict: 'verified' };
      },
      async bridgeBindChallengeV2(input, { connection }) {
        log.push(['challenge_v2', input, connection]);
        return { nonce: 'a'.repeat(64), algorithm: 'hmac-sha256', context,
          hq_epoch: '1'.repeat(64), expires_at: '2026-11-21T20:00:00.000Z' };
      },
      async bridgeBindChallengeV3(input, { connection }) {
        log.push(['challenge_v3', input, connection]);
        return { nonce: 'a'.repeat(64), algorithm: 'hmac-sha256', context: V3_CONTEXT,
          hq_epoch: '1'.repeat(64), expires_at: '2026-11-21T20:00:00.000Z' };
      },
      async verifyBridgeBindingV3(input, { connection }) {
        log.push(['bind_v3', input, connection]);
        return { bind_receipt: '3'.repeat(64) };
      },
      async verifyBridgeBindingV2(input, { connection }) {
        log.push(['bind_v2', input, connection]);
        return { bind_receipt: '2'.repeat(64) };
      },
      async verifyBinding(input, { connection }) {
        log.push(['member_bind', input, connection]);
        return { runtime_id: input.runtime_id, member_id: 'member_1', role: 'agent' };
      },
      async qualifyBridgeMessagesV2(input, { connection }, receipt) {
        log.push(['qualify', input, connection, receipt]);
        return { model: input.model };
      },
      async relayBridgeIngressV2(input, { connection }, receipt) {
        log.push(['relay_ingress', input, connection, receipt]);
        return { accepted: true };
      },
      forgetBridgeConnection(connection, receipt) { log.push(['forget_bridge', connection, receipt]); },
    } };
  },
});

test('B relay ingress delegates opaque frames only over a live v2 bridge binding', async () => {
  const log = [];
  const frame = { opaque_frame: 'base64:fixture', sequence: 7 };
  const host = createTestHost({ plugins: [
    protectedAdmission(log, PROTECTED_CONTEXT, false, true),
    brokerPlugin({ enableBridgeRelayIngress: true }),
  ] });
  await host.start();
  try {
    const b = 'b_relay';
    await assert.rejects(host.brokerAccept(BRIDGE_RELAY_INGRESS, frame, { connection: b }), code('caller_mismatch'));
    await host.brokerAccept(BRIDGE_BIND_CHALLENGE_V2, PROTECTED_SCOPE, { connection: b });
    const { bind_receipt } = await host.brokerAccept(BRIDGE_BIND_V2, PROTECTED_FRAME, { connection: b });
    assert.deepEqual(await host.brokerAccept(BRIDGE_RELAY_INGRESS, frame, { connection: b }), { accepted: true });
    assert.deepEqual(log.at(-1), ['relay_ingress', frame, b, bind_receipt]);
    await assert.rejects(host.brokerAccept('task.commit', {}, { connection: b }), code('caller_mismatch'));

    const member = 'r_member';
    await host.brokerAccept('bind', { runtime_id: 'rt_member', proof: 'proof' }, { connection: member });
    await assert.rejects(host.brokerAccept(BRIDGE_RELAY_INGRESS, frame, { connection: member }), code('caller_mismatch'));
    assert.equal(log.filter(([kind]) => kind === 'relay_ingress').length, 1);
  } finally {
    await host.stop();
  }
});

test('packaged B relay ingress stays closed until HQ supplies its private relay capability', async () => {
  const log = [];
  const host = createTestHost({ plugins: [protectedAdmission(log), plugin] });
  await host.start();
  try {
    const connection = 'b_without_hq_relay';
    await host.brokerAccept(BRIDGE_BIND_CHALLENGE_V2, PROTECTED_SCOPE, { connection });
    await host.brokerAccept(BRIDGE_BIND_V2, PROTECTED_FRAME, { connection });
    await assert.rejects(host.brokerAccept(BRIDGE_RELAY_INGRESS, { opaque_frame: 'base64:fixture' }, { connection }), code('caller_mismatch'));
    assert.equal(log.some(([kind]) => kind === 'relay_ingress'), false);
  } finally {
    await host.stop();
  }
});

test('live peer challenge refuses a v2 bridge even when both optional gates are enabled', async () => {
  const log = [];
  const host = createTestHost({ plugins: [
    protectedAdmission(log, PROTECTED_CONTEXT, false, false, true),
    brokerPlugin({ enableRelayPeerChallenge: true }),
  ] });
  await host.start();
  try {
    const connection = 'b_v2_only';
    await host.brokerAccept(BRIDGE_BIND_CHALLENGE_V2, PROTECTED_SCOPE, { connection });
    await host.brokerAccept(BRIDGE_BIND_V2, PROTECTED_FRAME, { connection });
    await assert.rejects(host.brokerAccept(STAGE2A_RELAY_PEER_CHALLENGE,
      { rpc_id: `rpc_${'a'.repeat(32)}` }, { connection }), code('caller_mismatch'));
    assert.equal(log.some(([kind]) => kind === 'live_peer'), false);
  } finally { await host.stop(); }
});

test('v3 bridge binds eight exact selectors then routes live peer on that bound connection', async () => {
  const log = [];
  const host = createTestHost({ plugins: [protectedAdmission(log, PROTECTED_CONTEXT, false, false, true),
    brokerPlugin({ enableRelayPeerChallenge: true })] });
  await host.start();
  try {
    const connection = 'b_v3';
    await assert.rejects(host.brokerAccept(BRIDGE_BIND_CHALLENGE_V3,
      { ...V3_SCOPE, launch_id: `ln_${'a'.repeat(24)}` }, { connection }), code('host.invalid_request'));
    assert.equal(log.some(([kind]) => kind === 'challenge_v3'), false);
    const challenge = await host.brokerAccept(BRIDGE_BIND_CHALLENGE_V3, V3_SCOPE, { connection });
    assert.equal(challenge.context, V3_CONTEXT);
    const receipt = await host.brokerAccept(BRIDGE_BIND_V3, { ...V3_SCOPE, proof: 'a'.repeat(64) }, { connection });
    assert.equal(receipt.bind_receipt, '3'.repeat(64));
    const frame = { rpc_id: `rpc_${'a'.repeat(32)}` };
    assert.deepEqual(await host.brokerAccept(STAGE2A_RELAY_PEER_CHALLENGE, frame, { connection }),
      { verdict: 'verified' });
    assert.deepEqual(log.at(-1), ['live_peer', frame, connection, receipt.bind_receipt]);
    await assert.rejects(host.brokerAccept('task.commit', {}, { connection }), code('caller_mismatch'));
  } finally { await host.stop(); }
});

test('protected bridge bind uses the launch reservation on the same connection', async () => {
  const log = [];
  const host = createTestHost({ plugins: [protectedAdmission(log), brokerPlugin()] });
  await host.start();
  const connection = 'b_v2';
  const challenge = await host.brokerAccept(BRIDGE_BIND_CHALLENGE_V2, PROTECTED_SCOPE, { connection });
  assert.equal(challenge.context, PROTECTED_CONTEXT);
  await assert.rejects(host.brokerAccept(BRIDGE_BIND, PROTECTED_FRAME, { connection }), code('host.invalid_request'));
  await assert.rejects(host.brokerAccept(BRIDGE_BIND_V2, PROTECTED_FRAME, { connection: 'replacement' }), code('host.invalid_request'));
  const bound = await host.brokerAccept(BRIDGE_BIND_V2, PROTECTED_FRAME, { connection });
  assert.deepEqual(bound, { bind_receipt: '2'.repeat(64) });
  assert.equal(host.provided(pkg.name).boundConnections(), 0);
  assert.equal(host.provided(pkg.name).boundBridgeConnections(), 1);
  await assert.rejects(host.brokerAccept('task.commit', {}, { connection }), code('caller_mismatch'));
  await assert.rejects(host.brokerAccept('qualification.messages', {
    model: 'qualification-model', prompt_sha256: `sha256:${'a'.repeat(64)}`,
  }, { connection }), code('caller_mismatch'));
  await assert.rejects(host.brokerAccept(BRIDGE_BIND_V2, PROTECTED_FRAME, { connection }), code('host.invalid_request'));
  await host.brokerClosed(connection);
  assert.deepEqual(log, [
    ['challenge_v2', PROTECTED_SCOPE, connection],
    ['bind_v2', PROTECTED_FRAME, connection],
    ['forget_bridge', connection, bound.bind_receipt],
  ]);
});

test('bridge qualification route is opt-in and never grants member delivery', async () => {
  const frame = { model: 'fixture-model', prompt_sha256: `sha256:${'a'.repeat(64)}` };
  for (const enableBridgeQualification of [false, true]) {
    const log = [];
    const host = createTestHost({ plugins: [
      protectedAdmission(log, PROTECTED_CONTEXT, true), brokerPlugin({ enableBridgeQualification }),
    ] });
    await host.start();
    try {
      const connection = 'b_v2';
      await assert.rejects(host.brokerAccept(BRIDGE_QUALIFICATION_MESSAGES, frame, { connection }), code('caller_mismatch'));
      await host.brokerAccept(BRIDGE_BIND_CHALLENGE_V2, PROTECTED_SCOPE, { connection });
      const { bind_receipt } = await host.brokerAccept(BRIDGE_BIND_V2, PROTECTED_FRAME, { connection });
      const request = host.brokerAccept(BRIDGE_QUALIFICATION_MESSAGES, frame, { connection });
      if (enableBridgeQualification) {
        assert.deepEqual(await request, { model: frame.model });
        assert.deepEqual(log.at(-1), ['qualify', frame, connection, bind_receipt]);
      } else {
        await assert.rejects(request, code('caller_mismatch'));
        assert.equal(log.length, 2);
      }
      await assert.rejects(host.brokerAccept('qualification.messages', frame, { connection }), code('caller_mismatch'));
      await assert.rejects(host.brokerAccept('task.commit', {}, { connection }), code('caller_mismatch'));
    } finally {
      await host.stop();
    }
  }
});

test('packaged broker delegates qualification only with an HQ authority capability', async () => {
  const frame = { model: 'fixture-model', prompt_sha256: `sha256:${'a'.repeat(64)}` };
  for (const qualificationEnabled of [false, true]) {
    const log = [];
    const host = createTestHost({ plugins: [
      protectedAdmission(log, PROTECTED_CONTEXT, qualificationEnabled), plugin,
    ] });
    await host.start();
    try {
      const connection = `b_${qualificationEnabled}`;
      await host.brokerAccept(BRIDGE_BIND_CHALLENGE_V2, PROTECTED_SCOPE, { connection });
      const { bind_receipt } = await host.brokerAccept(BRIDGE_BIND_V2, PROTECTED_FRAME, { connection });
      const request = host.brokerAccept(BRIDGE_QUALIFICATION_MESSAGES, frame, { connection });
      if (qualificationEnabled) {
        assert.deepEqual(await request, { model: frame.model });
        assert.deepEqual(log.at(-1), ['qualify', frame, connection, bind_receipt]);
      } else {
        await assert.rejects(request, code('caller_mismatch'));
        assert.equal(log.length, 2);
      }
      await assert.rejects(host.brokerAccept('task.commit', {}, { connection }), code('caller_mismatch'));
    } finally {
      await host.stop();
    }
  }
});

test('direct factory opt-in cannot bypass an absent HQ qualification capability', async () => {
  const log = [];
  const host = createTestHost({ plugins: [
    protectedAdmission(log), brokerPlugin({ enableBridgeQualification: true }),
  ] });
  await host.start();
  try {
    const connection = 'b_no_authorizer';
    await host.brokerAccept(BRIDGE_BIND_CHALLENGE_V2, PROTECTED_SCOPE, { connection });
    await host.brokerAccept(BRIDGE_BIND_V2, PROTECTED_FRAME, { connection });
    await assert.rejects(host.brokerAccept(BRIDGE_QUALIFICATION_MESSAGES, {
      model: 'fixture-model', prompt_sha256: `sha256:${'a'.repeat(64)}`,
    }, { connection }), code('caller_mismatch'));
    assert.equal(log.length, 2);
  } finally {
    await host.stop();
  }
});

test('packaged broker rechecks HQ qualification capability on the live B request', async () => {
  const log = [];
  let enabled = true;
  const host = createTestHost({ plugins: [
    protectedAdmission(log, PROTECTED_CONTEXT, () => enabled), plugin,
  ] });
  await host.start();
  try {
    const connection = 'b_revoked';
    await host.brokerAccept(BRIDGE_BIND_CHALLENGE_V2, PROTECTED_SCOPE, { connection });
    await host.brokerAccept(BRIDGE_BIND_V2, PROTECTED_FRAME, { connection });
    enabled = false;
    const frame = { model: 'fixture-model', prompt_sha256: `sha256:${'a'.repeat(64)}` };
    await assert.rejects(host.brokerAccept(BRIDGE_QUALIFICATION_MESSAGES, frame, { connection }),
      code('caller_mismatch'));
    assert.equal(log.length, 2);
    enabled = true;
    assert.deepEqual(await host.brokerAccept(BRIDGE_QUALIFICATION_MESSAGES, frame, { connection }),
      { model: frame.model });
    assert.equal(log.at(-1)[0], 'qualify');
  } finally {
    await host.stop();
  }
});

test('protected bridge rejects runtime IDs, malformed digests and v1 HQ challenges', async () => {
  const log = [];
  const host = createTestHost({ plugins: [protectedAdmission(log, BRIDGE_CONTEXT), brokerPlugin()] });
  await host.start();
  const connection = 'b_v2';
  for (const frame of [BRIDGE_SCOPE, { ...PROTECTED_SCOPE, runtime_id: 'rt_old' },
    { ...PROTECTED_SCOPE, reservation_digest: 'a'.repeat(64) },
    { ...PROTECTED_SCOPE, launch_id: [PROTECTED_SCOPE.launch_id] }]) {
    await assert.rejects(host.brokerAccept(BRIDGE_BIND_CHALLENGE_V2, frame, { connection }), code('host.invalid_request'));
  }
  assert.deepEqual(log, []);
  await assert.rejects(host.brokerAccept(BRIDGE_BIND_CHALLENGE_V2, PROTECTED_SCOPE, { connection }), code('host.invalid_request'));
  await assert.rejects(host.brokerAccept(BRIDGE_BIND_V2, PROTECTED_FRAME, { connection }), code('host.invalid_request'));
  assert.deepEqual(log, [
    ['challenge_v2', PROTECTED_SCOPE, connection],
    ['forget_bridge', connection, undefined],
  ]);
});

test('protected bridge bind revokes the challenge if its response carries a runtime ID', async () => {
  const log = [];
  const host = createTestHost({ plugins: [protectedAdmission(log), brokerPlugin()] });
  await host.start();
  const connection = 'b_v2';
  await host.brokerAccept(BRIDGE_BIND_CHALLENGE_V2, PROTECTED_SCOPE, { connection });
  await assert.rejects(host.brokerAccept(BRIDGE_BIND_V2, { ...PROTECTED_FRAME, runtime_id: 'rt_old' }, { connection }), code('host.invalid_request'));
  await assert.rejects(host.brokerAccept(BRIDGE_BIND_V2, PROTECTED_FRAME, { connection }), code('host.invalid_request'));
  assert.deepEqual(log, [
    ['challenge_v2', PROTECTED_SCOPE, connection],
    ['forget_bridge', connection, undefined],
  ]);
});

test('protected bridge never falls back to the v1 HQ authority', async () => {
  const log = [];
  const host = createTestHost({ plugins: [bridgeAdmission(log), brokerPlugin()] });
  await host.start();
  await assert.rejects(host.brokerAccept(BRIDGE_BIND_CHALLENGE_V2, PROTECTED_SCOPE, { connection: 'b_1' }), code('host.invalid_request'));
  const challenge = await host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_1' });
  await assert.rejects(host.brokerAccept(BRIDGE_BIND_V2, PROTECTED_FRAME, { connection: 'b_1' }), code('host.invalid_request'));
  await host.brokerAccept(BRIDGE_BIND,
    { ...BRIDGE_SCOPE, proof: bridgeProof(challenge.nonce, challenge.hq_epoch) }, { connection: 'b_1' });
  assert.deepEqual(log, [['challenge', 'b_1'], ['bind', 'b_1']]);
  await host.stop();
});

test('plugin stop revokes every live B receipt', async () => {
  const host = createTestHost({ plugins: [bridgeAdmission([]), brokerPlugin()] });
  await host.start();
  const challenge = await host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_1' });
  await host.brokerAccept(BRIDGE_BIND, { ...BRIDGE_SCOPE, proof: bridgeProof(challenge.nonce, challenge.hq_epoch) }, { connection: 'b_1' });
  assert.equal(host.provided('hq-admission').liveBridgeReceipt('b_1'), 'd'.repeat(64));
  await host.stop();
  assert.equal(host.provided('hq-admission').liveBridgeReceipt('b_1'), undefined);
});

test('stop drains a verifier that installs a B receipt after the first revocation', async () => {
  let entered, release;
  const verifying = new Promise((resolve) => { entered = resolve; });
  const held = new Promise((resolve) => { release = resolve; });
  const log = [];
  const host = createTestHost({ plugins: [bridgeAdmission(log, { beforeBridgeBind: () => {
    entered();
    return held;
  } }), brokerPlugin()] });
  await host.start();
  const challenge = await host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_1' });
  const binding = host.brokerAccept(BRIDGE_BIND,
    { ...BRIDGE_SCOPE, proof: bridgeProof(challenge.nonce, challenge.hq_epoch) }, { connection: 'b_1' });
  const refused = assert.rejects(binding, code('host.invalid_request'));
  await verifying;
  let stopped = false;
  const stopping = host.stop().finally(() => { stopped = true; });
  await new Promise(setImmediate);
  assert.equal(stopped, false, 'stop must wait for the late verifier');
  assert.equal(log.filter(([kind]) => kind === 'forget_bridge').length, 1);
  release();
  await refused;
  const report = await stopping;
  assert.equal(report.find(({ name }) => name === pkg.name).ok, true);
  assert.equal(host.provided('hq-admission').liveBridgeReceipt('b_1'), undefined);
  assert.equal(log.filter(([kind]) => kind === 'forget_bridge').length, 2);
});

test('stop drains a challenge that installs after the first revocation', async () => {
  let entered, release;
  const challenging = new Promise((resolve) => { entered = resolve; });
  const held = new Promise((resolve) => { release = resolve; });
  const log = [];
  const host = createTestHost({ plugins: [bridgeAdmission(log, { beforeChallenge: () => {
    entered();
    return held;
  } }), brokerPlugin()] });
  await host.start();
  const challenge = host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_1' });
  const refused = assert.rejects(challenge, code('host.invalid_request'));
  await challenging;
  let stopped = false;
  const stopping = host.stop().finally(() => { stopped = true; });
  await new Promise(setImmediate);
  assert.equal(stopped, false, 'stop must wait for the late challenge');
  release();
  await refused;
  const report = await stopping;
  assert.equal(report.find(({ name }) => name === pkg.name).ok, true);
  assert.equal(log.filter(([kind]) => kind === 'forget_bridge').length, 2);
  assert.equal(host.provided('hq-admission').bridgeChallengeActive('b_1'), false);
});

test('same-tick socket close fences a queued B challenge or bind before HQ runs', async () => {
  for (const phase of ['challenge', 'bind']) {
    const log = [];
    const host = createTestHost({ plugins: [bridgeAdmission(log), brokerPlugin()] });
    await host.start();
    const first = phase === 'bind'
      ? await host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_1' }) : null;
    const pending = phase === 'challenge'
      ? host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_1' })
      : host.brokerAccept(BRIDGE_BIND,
        { ...BRIDGE_SCOPE, proof: bridgeProof(first.nonce, first.hq_epoch) }, { connection: 'b_1' });
    const refused = assert.rejects(pending, code('host.invalid_request'));
    await host.brokerClosed('b_1');
    await refused;
    assert.equal(log.filter(([kind]) => kind === (phase === 'challenge' ? 'challenge' : 'bind')).length,
      0, `${phase}: HQ never handles the queued frame`);
    assert.equal(host.provided('hq-admission').bridgeChallengeActive('b_1'), false);
    assert.equal(host.provided('hq-admission').liveBridgeReceipt('b_1'), undefined);
  }
});

test('closing a challenged B connection clears the challenge before bind', async () => {
  const log = [];
  const host = createTestHost({ plugins: [bridgeAdmission(log), brokerPlugin()] });
  await host.start();
  await host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_1' });
  await assert.rejects(host.brokerAccept('task.commit', { n: 1 }, { connection: 'b_1' }), code('caller_mismatch'));
  await host.brokerClosed('b_1');
  assert.deepEqual(log.at(-1), ['forget_bridge', 'b_1', undefined]);
  await assert.rejects(host.brokerAccept(BRIDGE_BIND, { ...BRIDGE_SCOPE, proof: 'f'.repeat(64) }, { connection: 'b_1' }), code('host.invalid_request'));
});

test('a connection closed during B bind cannot leave a live receipt', async () => {
  let release;
  let held;
  const holding = new Promise((resolve) => { held = resolve; });
  const host = createTestHost({ plugins: [bridgeAdmission([]), brokerPlugin({ beforeBind: () => {
    held();
    return new Promise((resolve) => { release = resolve; });
  } })] });
  await host.start();
  const challenge = await host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_1' });
  const pending = host.brokerAccept(BRIDGE_BIND, { ...BRIDGE_SCOPE, proof: bridgeProof(challenge.nonce, challenge.hq_epoch) }, { connection: 'b_1' });
  await holding;
  await assert.rejects(host.brokerAccept('task.commit', { n: 1 }, { connection: 'b_1' }), code('caller_mismatch'));
  await host.brokerClosed('b_1');
  release();
  await assert.rejects(pending, code('caller_mismatch'));
  assert.equal(host.provided('hq-admission').liveBridgeReceipt('b_1'), undefined);
  assert.equal(host.provided(pkg.name).boundBridgeConnections(), 0);
});

const faultyBridgeAdmission = (fault, onForget) => definePlugin({
  name: 'hq-admission', version: '0.1.0', hostApi: 1,
  async init() {
    const challenged = new Set();
    const live = new Map();
    let forgets = 0;
    return { provides: {
      bridgeBindChallenge(_input, { connection }) {
        challenged.add(connection);
        if (fault === 'challenge_throws') fail('caller_mismatch', 'HQ failed after installing challenge');
        if (fault === 'challenge_malformed') return { nonce: 'invalid' };
        return { nonce: 'c'.repeat(64), algorithm: 'hmac-sha256', context: BRIDGE_CONTEXT,
          hq_epoch: '7'.repeat(64), expires_at: '2026-11-21T20:00:00.000Z' };
      },
      verifyBridgeBinding(_input, { connection }) {
        challenged.delete(connection);
        live.set(connection, 'd'.repeat(64));
        if (fault === 'bind_throws') fail('caller_mismatch', 'HQ failed after installing receipt');
        if (fault === 'bind_malformed') return { bind_receipt: 'invalid' };
        return { bind_receipt: 'd'.repeat(64) };
      },
      forgetBridgeConnection(connection) {
        forgets += 1;
        challenged.delete(connection);
        live.delete(connection); // synchronous, before containment completes
        return onForget?.();
      },
      challenged: (connection) => challenged.has(connection),
      live: (connection) => live.has(connection),
      forgets: () => forgets,
    } };
  },
});

for (const fault of ['challenge_throws', 'challenge_malformed', 'bind_throws', 'bind_malformed']) {
  test(`ambiguous HQ ${fault} response revokes B authority by connection`, async () => {
    const host = createTestHost({ plugins: [faultyBridgeAdmission(fault), brokerPlugin(), consumer([])] });
    await host.start();
    if (fault.startsWith('challenge_')) {
      await assert.rejects(host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_1' }),
        code(fault === 'challenge_malformed' ? 'host.invalid_request' : 'caller_mismatch'));
    } else {
      await host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_1' });
      await assert.rejects(host.brokerAccept(BRIDGE_BIND, { ...BRIDGE_SCOPE, proof: 'e'.repeat(64) }, { connection: 'b_1' }),
        code(fault === 'bind_malformed' ? 'host.invalid_request' : 'caller_mismatch'));
    }
    const authority = host.provided('hq-admission');
    assert.equal(authority.challenged('b_1'), false);
    assert.equal(authority.live('b_1'), false);
    assert.equal(authority.forgets(), 1);
    assert.equal(host.provided(pkg.name).boundBridgeConnections(), 0);
    await assert.rejects(host.brokerAccept('task.commit', { n: 1 }, { connection: 'b_1' }), code('caller_mismatch'));
  });
}

test('socket close revokes HQ receipt synchronously even if later containment rejects', async () => {
  let rejectContainment;
  const containment = new Promise((_resolve, reject) => { rejectContainment = reject; });
  const host = createTestHost({ plugins: [faultyBridgeAdmission('none', () => containment), brokerPlugin(), consumer([])] });
  await host.start();
  await host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_1' });
  await host.brokerAccept(BRIDGE_BIND, { ...BRIDGE_SCOPE, proof: 'e'.repeat(64) }, { connection: 'b_1' });
  const authority = host.provided('hq-admission');
  assert.equal(authority.live('b_1'), true);
  const closing = host.brokerClosed('b_1'); // HQ's socket server may ignore this promise
  assert.equal(authority.live('b_1'), false);
  assert.equal(host.provided(pkg.name).boundBridgeConnections(), 0);
  rejectContainment(new Error('containment failed'));
  await closing; // the SDK swallows close errors; revocation has already happened
  await assert.rejects(host.brokerAccept('task.commit', { n: 1 }, { connection: 'b_1' }), code('caller_mismatch'));
  const report = await host.stop();
  assert.match(report.find(({ name }) => name === pkg.name).error, /containment failed/);
});

test('stop waits for a socket-close revocation already in flight', async () => {
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const host = createTestHost({ plugins: [faultyBridgeAdmission('none', () => held), brokerPlugin()] });
  await host.start();
  await host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_1' });
  await host.brokerAccept(BRIDGE_BIND, { ...BRIDGE_SCOPE, proof: 'e'.repeat(64) }, { connection: 'b_1' });
  const authority = host.provided('hq-admission');
  const closing = host.brokerClosed('b_1');
  assert.equal(authority.live('b_1'), false);
  let stopped = false;
  const stopping = host.stop().finally(() => { stopped = true; });
  await new Promise(setImmediate);
  assert.equal(stopped, false, 'stop must drain the close revocation');
  release();
  await closing;
  await stopping;
  assert.equal(authority.live('b_1'), false);
});

test('stop succeeds after close and a late verifier both revoke the same B receipt', async () => {
  let entered, release;
  const verifying = new Promise((resolve) => { entered = resolve; });
  const held = new Promise((resolve) => { release = resolve; });
  const log = [];
  const host = createTestHost({ plugins: [bridgeAdmission(log, { beforeBridgeBind: () => {
    entered();
    return held;
  } }), brokerPlugin()] });
  await host.start();
  const challenge = await host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_1' });
  const binding = host.brokerAccept(BRIDGE_BIND,
    { ...BRIDGE_SCOPE, proof: bridgeProof(challenge.nonce, challenge.hq_epoch) }, { connection: 'b_1' });
  const refused = assert.rejects(binding, code('host.invalid_request'));
  await verifying;
  await host.brokerClosed('b_1');
  let stopped = false;
  const stopping = host.stop().finally(() => { stopped = true; });
  await new Promise(setImmediate);
  assert.equal(stopped, false, 'stop still drains the late verifier');
  release();
  await refused;
  const report = await stopping;
  assert.equal(report.find(({ name }) => name === pkg.name).ok, true);
  assert.equal(host.provided('hq-admission').liveBridgeReceipt('b_1'), undefined);
  assert.equal(log.filter(([kind]) => kind === 'forget_bridge').length, 2);
});

test('a hung B verifier makes stop fail within its containment deadline', async () => {
  let entered, release;
  const verifying = new Promise((resolve) => { entered = resolve; });
  const held = new Promise((resolve) => { release = resolve; });
  const host = createTestHost({ plugins: [bridgeAdmission([], { beforeBridgeBind: () => {
    entered();
    return held;
  } }), brokerPlugin({ bridgeStopTimeoutMs: 20 })] });
  await host.start();
  const challenge = await host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection: 'b_1' });
  const binding = host.brokerAccept(BRIDGE_BIND,
    { ...BRIDGE_SCOPE, proof: bridgeProof(challenge.nonce, challenge.hq_epoch) }, { connection: 'b_1' });
  const refused = assert.rejects(binding, code('host.invalid_request'));
  await verifying;
  const report = await host.stop();
  assert.match(report.find(({ name }) => name === pkg.name).error,
    /bridge containment unconfirmed: stop drain timed out/);
  release();
  await refused;
  assert.equal(host.provided('hq-admission').liveBridgeReceipt('b_1'), undefined);
});

test('stop attempts every B revocation when one containment hook throws', async () => {
  const host = createTestHost({ plugins: [faultyBridgeAdmission('none', () => { throw new Error('containment failed'); }), brokerPlugin()] });
  await host.start();
  for (const connection of ['b_1', 'b_2']) {
    await host.brokerAccept(BRIDGE_BIND_CHALLENGE, BRIDGE_SCOPE, { connection });
    await host.brokerAccept(BRIDGE_BIND, { ...BRIDGE_SCOPE, proof: 'e'.repeat(64) }, { connection });
  }
  const authority = host.provided('hq-admission');
  assert.equal(authority.live('b_1'), true);
  assert.equal(authority.live('b_2'), true);
  await host.stop().catch(() => {}); // host lifecycle may report the hook failure
  assert.equal(authority.live('b_1'), false);
  assert.equal(authority.live('b_2'), false);
  assert.equal(authority.forgets(), 2);
});
