// Nonauthorizing integration: the Machine authority below is a test double.
// This exercises the production HQ verifier and Comms broker over a Unix
// socket; it does not establish a kernel peer UID or B connector handoff.
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { join } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { agentBotHq } from './hq-agent-bot-hq.mjs';
import { brokerPlugin } from '../lib/hq-plugin/broker.mjs';

// Separate from the SDK vendor pin: this is the HQ revision whose bridge
// verifier is exercised here. Update deliberately when refreshing coverage.
const HQ_COMMIT = 'd5fc908f19427f24699d8b268631bb5d1fa27bc5';
const { startHQ } = await import(pathToFileURL(join(agentBotHq(HQ_COMMIT), 'tests/hq-harness.mjs')).href);
const selectors = Object.freeze({ installation_id: 'inst_1', start_id: `st_${'a'.repeat(24)}`,
  launch_id: `ln_${'b'.repeat(24)}`, runtime_id: 'rt_1', plan_id: 'plan-1', plan_digest: 'c'.repeat(64) });
const key = Buffer.alloc(32, 0x41);
const context = { ...selectors, hq_epoch: 'd'.repeat(64), bridge_uid: 302,
  broker_socket: '/test-only/broker.sock', proof_key: key };
const proof = (challenge) => createHmac('sha256', key).update([
  'agent-bot-stage2a-bridge-bind-v1', challenge.nonce, context.hq_epoch,
  ...Object.keys(selectors).map((field) => selectors[field]), String(context.bridge_uid), context.broker_socket,
].join('\n')).digest('hex');

async function setup() {
  const stops = [];
  const hq = await startHQ({ plugins: [brokerPlugin()], bridgeAuthority: {
    verifyLiveStart: async () => context,
    onDisconnect: async (observation) => { stops.push(observation); },
  } });
  return { ...hq, stops, admission: hq.hq.host.provided('hq-admission') };
}

test('real HQ verifies Comms bridge proof and revokes the receipt on close', async () => {
  const t = await setup();
  try {
    const socket = await t.member();
    const challenge = await socket.request('bridge.bind.challenge', selectors);
    assert.equal(challenge.ok, true, JSON.stringify(challenge));
    const bound = await socket.request('bridge.bind', { ...selectors, proof: proof(challenge.result) });
    assert.equal(bound.ok, true, JSON.stringify(bound));
    const digest = `sha256:${createHash('sha256').update(bound.result.bind_receipt).digest('hex')}`;
    assert.equal((await t.admission.boundBridge(selectors, digest)).hmac_verified, true);
    const memberRequest = await socket.request('task.commit', {});
    assert.equal(memberRequest.refusal?.error, 'caller_mismatch');
    await socket.close();
    // Closing the client and server are asynchronous; wait for the server's
    // disconnect callback without relying on a fixed scheduling delay.
    for (let i = 0; i < 100 && t.stops.length === 0; i++) await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(t.stops.length, 1);
    assert.equal(t.stops[0].bind_receipt_sha256, digest);
    assert.equal(await t.admission.boundBridge(selectors, digest), null);
  } finally { await t.done(); }
});

test('real HQ rejects a wrong proof through Comms and spends the challenge', async () => {
  const t = await setup();
  try {
    const socket = await t.member();
    const challenge = await socket.request('bridge.bind.challenge', selectors);
    assert.equal(challenge.ok, true, JSON.stringify(challenge));
    const bad = await socket.request('bridge.bind', { ...selectors, proof: '0'.repeat(64) });
    assert.equal(bad.host_refusal?.code, 'host.launch_unavailable');
    assert.equal(t.stops.length, 1);
    const replay = await socket.request('bridge.bind', { ...selectors, proof: proof(challenge.result) });
    assert.equal(replay.host_refusal?.code, 'host.invalid_request');
    const another = await t.member();
    const reused = await another.request('bridge.bind.challenge', selectors);
    assert.equal(reused.host_refusal?.code, 'host.launch_unavailable');
  } finally { await t.done(); }
});
