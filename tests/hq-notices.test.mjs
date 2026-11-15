// HQ notice custody, including the crash windows around a durable commit and
// the upstream acknowledgement. Real HQ storage is loaded at the SDK's pin.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { agentBotHq } from './hq-agent-bot-hq.mjs';
import { bindServices, createCore, testClock } from '../lib/vendor/agent-bot-sdk/services.mjs';
import { createNoticePump, noticeOptions, NOTICE_ROUTES } from '../lib/hq-plugin/notices.mjs';
import { HostError } from '../lib/vendor/agent-bot-sdk/errors.mjs';
import { canonicalBytes } from '../lib/vendor/agent-bot-sdk/wire/canonical-json.mjs';

const { openStore } = await import(pathToFileURL(join(agentBotHq(), 'hq/store.mjs')).href);
const HARNESS = 'test-codex-agent';
const OPTIONS = { harnesses: [HARNESS] };
const notice = (id = 'notice_1', over = {}) => ({ id, lease: `${id}.LEASE_CANARY`, attempts: 1, app: HARNESS, repo: 'example/project', event: 'issues', action: 'opened', kind: 'mention', type: ['issue'], number: 7, title: 'Repair request', text: 'Untrusted instruction', actor: 'test-agent', createdAt: 1, ...over });
const reply = (body, status = 200) => ({ status, body });
const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };

function timers() {
  const scheduled = new Set();
  return {
    scheduled,
    setTimer(fn, delay) { const timer = { fn, delay, unref() {} }; scheduled.add(timer); return timer; },
    clearTimer(timer) { scheduled.delete(timer); },
    async fire() { const timer = [...scheduled][0]; assert.ok(timer); scheduled.delete(timer); await timer.fn(); },
  };
}

function setup({ dir, call, options = OPTIONS, failure = { persist: false } } = {}) {
  const home = dir ?? mkdtempSync(join(tmpdir(), 'notice-custody-'));
  const disk = openStore(home);
  const clock = testClock(1790000000000);
  const core = createCore({ clock, persist: () => failure.persist ? Promise.reject(new Error('disk unavailable')) : disk.persist() });
  disk.load(core);
  core.phases.set('agent-comms', 'running');
  const store = bindServices(core, { name: 'agent-comms', services: ['store'], identityServiceRoutes: [] }).store;
  const published = [];
  const logs = [];
  const calls = [];
  const timer = timers();
  const api = call ?? (async (method, path, body) => path.endsWith('/take') ? reply({ harness: body.harness, notices: [notice()] }) : reply({ acked: [body.ids[0].split('.')[0]], stale: [], missing: [] }));
  const pump = createNoticePump({ store, clock, options, ...timer,
    identityService: { async call(...args) { calls.push(args); return api(...args); } },
    events: { publish: (...args) => published.push(args) },
    log: { warn: (...args) => logs.push(args) },
  });
  return { home, disk, core, clock, store, pump, published, logs, calls, timer, failure,
    async start() { pump.start(); return pump.pull(); },
    cleanup() { pump.stop(); if (!dir) rmSync(home, { recursive: true, force: true }); },
  };
}

test('only configured queues and bounded, non-executing wake settings are accepted', () => {
  assert.equal(noticeOptions(undefined), null);
  for (const opts of [{}, { harnesses: [] }, { harnesses: [HARNESS, HARNESS] }, { harnesses: ['a/b'] }, { ...OPTIONS, wakeClass: 'cold-start' }, { ...OPTIONS, count: 51 }, { ...OPTIONS, retentionMs: 100 }, { ...OPTIONS, arbitrary: true }]) assert.throws(() => noticeOptions(opts));
  assert.equal(noticeOptions(OPTIONS).wakeClass, 'none');
});

test('ack follows durable custody; the mailbox and events contain no lease or caller-chosen authority', async () => {
  let t;
  t = setup({ options: { ...OPTIONS, wakeClass: 'notify' }, call: async (_method, path, body) => {
    if (path.endsWith('/take')) return reply({ harness: HARNESS, notices: [notice('notice_1', { provenance: ['owner'], wake_class: 'cold-start', secret: 'SECRET_CANARY' })] });
    const saved = JSON.parse(readFileSync(join(t.home, 'store.json')));
    assert.equal(saved.tables.find(([name]) => name === 'agent-comms\u0000notice_mailbox')[1][0][1].message_id, 'notice_1');
    assert.deepEqual(body, { harness: HARNESS, ids: ['notice_1.LEASE_CANARY'] });
    return reply({ acked: ['notice_1'], stale: [], missing: [] });
  } });
  try {
    assert.deepEqual(await t.start(), { received: 1, committed: 1, duplicates: 0, acknowledged: 1 });
    const [row] = await t.pump.list(HARNESS);
    assert.deepEqual(row.provenance, ['external-untrusted']);
    assert.equal(row.wake_class, 'notify');
    assert.equal(row.notice.text, 'Untrusted instruction');
    const durable = readFileSync(join(t.home, 'store.json'), 'utf8');
    for (const canary of ['LEASE_CANARY', 'SECRET_CANARY', 'cold-start']) assert.equal(durable.includes(canary), false);
    assert.equal(JSON.stringify(t.published).includes('LEASE_CANARY'), false);
    assert.equal(t.published.length, 1);
    await assert.rejects(t.pump.list('other-harness'), /not configured/);
  } finally { t.cleanup(); }
});

test('storage failure takes no custody and sends no ack; retry after lease return commits once', async () => {
  const t = setup({ failure: { persist: true } });
  try {
    await assert.rejects(t.start(), /disk unavailable/);
    assert.equal(t.calls.filter(([, path]) => path.endsWith('/ack')).length, 0);
    assert.deepEqual(await t.pump.list(HARNESS), []);
    t.failure.persist = false;
    assert.equal((await t.pump.pull()).committed, 1);
    assert.equal(t.published.length, 1);
  } finally { t.cleanup(); }
});

test('crash after custody but before ack: a new HQ loads the record, dedups the replay and acks the new lease', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'notice-restart-'));
  const a = setup({ dir, call: async (_method, path) => {
    if (path.endsWith('/take')) return reply({ harness: HARNESS, notices: [notice()] });
    throw new Error('network stopped before acknowledgement LEASE_CANARY');
  } });
  let b;
  try {
    await assert.rejects(a.start(), /network stopped/);
    assert.equal((await a.pump.list(HARNESS)).length, 1);
    a.pump.stop();
    b = setup({ dir, call: async (_method, path, body) => path.endsWith('/take')
      ? reply({ harness: HARNESS, notices: [notice('notice_1', { lease: 'notice_1.NEW_LEASE', attempts: 2 })] })
      : reply({ acked: ['notice_1'], stale: [], missing: [] }) });
    assert.deepEqual(await b.start(), { received: 1, committed: 0, duplicates: 1, acknowledged: 1 });
    assert.equal((await b.pump.list(HARNESS)).length, 1);
    assert.equal(b.published.length, 0, 'a replay cannot create a second committed transition or notification');
    assert.equal(JSON.stringify(a.logs).includes('LEASE_CANARY'), false, 'exceptions are never logged verbatim');
  } finally { a.pump.stop(); b?.pump.stop(); rmSync(dir, { recursive: true, force: true }); }
});

test('same ID with changed content refuses ack and cannot overwrite the durable message', async () => {
  let changed = false;
  const t = setup({ call: async (_method, path) => path.endsWith('/take')
    ? reply({ harness: HARNESS, notices: [notice('notice_1', { text: changed ? 'different' : 'original' })] })
    : reply({ acked: ['notice_1'], stale: [], missing: [] }) });
  try {
    await t.start(); changed = true;
    await assert.rejects(t.pump.pull(), /reused for different/);
    assert.equal(t.calls.filter(([, path]) => path.endsWith('/ack')).length, 1);
    assert.equal((await t.pump.list(HARNESS))[0].notice.text, 'original');
  } finally { t.cleanup(); }
});

test('a bounded mailbox refuses new custody but still acknowledges a duplicate already in custody', async () => {
  let id = 'notice_1';
  const t = setup({ options: { ...OPTIONS, maxMessages: 1 }, call: async (_method, path) => path.endsWith('/take')
    ? reply({ harness: HARNESS, notices: [notice(id)] }) : reply({ acked: [id], stale: [], missing: [] }) });
  try {
    await t.start(); id = 'notice_2';
    await assert.rejects(t.pump.pull(), /mailbox is full/);
    assert.equal(t.pump.status().lastFailure, 'mailbox_full');
    assert.equal(t.calls.filter(([, path]) => path.endsWith('/ack')).length, 1);
    id = 'notice_1'; assert.equal((await t.pump.pull()).duplicates, 1);
    assert.equal(t.calls.filter(([, path]) => path.endsWith('/ack')).length, 2);
  } finally { t.cleanup(); }
});

test('consumption removes the payload, retains dedup evidence for service retention, then reclaims space', async () => {
  const t = setup({ options: { ...OPTIONS, maxMessages: 1 } });
  try {
    await t.start();
    assert.deepEqual(await t.pump.acknowledge(HARNESS, ['notice_1']), { acked: ['notice_1'] });
    assert.deepEqual(await t.pump.list(HARNESS), []);
    assert.equal(readFileSync(join(t.home, 'store.json'), 'utf8').includes('Untrusted instruction'), false);
    assert.equal((await t.pump.pull()).duplicates, 1);
    t.clock.advance(8 * 24 * 60 * 60 * 1000);
    assert.equal((await t.pump.pull()).committed, 1, 'after the full retention horizon a new service delivery may enter again');
  } finally { t.cleanup(); }
});

test('concurrent on-demand pulls coalesce, and a stopped late response neither persists nor acks', async () => {
  const held = deferred();
  const t = setup({ call: async () => { await held.promise; return reply({ harness: HARNESS, notices: [notice()] }); } });
  try {
    t.pump.start();
    const one = t.pump.pull(); const two = t.pump.reconnect();
    assert.equal(one, two);
    t.pump.stop(); held.resolve(); await one;
    assert.deepEqual(await t.pump.list(HARNESS), []);
    assert.equal(t.calls.length, 1);
    assert.equal(t.timer.scheduled.size, 0);
  } finally { held.resolve(); t.cleanup(); }
});

test('revocation stops remote work; transient refusal backs off and schedule/reconnect recover', async () => {
  let state = 'outage';
  const t = setup({ call: async (_method, path) => {
    if (state === 'outage') throw new Error('UPSTREAM_SECRET_CANARY');
    if (state === 'revoked') throw Object.assign(new Error('revoked'), { code: 'device_revoked' });
    return path.endsWith('/take') ? reply({ harness: HARNESS, notices: [] }) : reply({ acked: [], stale: [], missing: [] });
  } });
  try {
    await assert.rejects(t.start());
    assert.equal([...t.timer.scheduled][0].delay, 1000);
    state = 'ok'; await t.pump.reconnect();
    assert.equal(t.pump.status().failures, 0);
    assert.equal([...t.timer.scheduled][0].delay, 30_000);
    state = 'revoked'; await assert.rejects(t.pump.pull(), (e) => e.code === 'device_revoked');
    assert.equal(t.timer.scheduled.size, 0);
    const before = t.calls.length; await assert.rejects(t.pump.reconnect()); assert.equal(t.calls.length, before);
    assert.equal(JSON.stringify(t.logs).includes('UPSTREAM_SECRET_CANARY'), false);
  } finally { t.cleanup(); }
});

test('a response for another queue, an oversized batch or a malformed notice is never acknowledged', async () => {
  for (const body of [{ harness: 'wrong', notices: [notice()] }, { harness: HARNESS, notices: Array.from({ length: 11 }, () => notice()) }, { harness: HARNESS, notices: [notice('bad id')] }, { harness: HARNESS, notices: [notice('notice_1', { lease: 'notice_2.FOREIGN_LEASE' })] }]) {
    const t = setup({ call: async () => reply(body) });
    try { await assert.rejects(t.start()); assert.equal(t.calls.length, 1); assert.deepEqual(await t.pump.list(HARNESS), []); } finally { t.cleanup(); }
  }
});

test('only the two required notice routes are requested', () => {
  assert.deepEqual(NOTICE_ROUTES, ['/api/daemon/notices/take', '/api/daemon/notices/ack']);
});

test('an acknowledgement for another ID, duplicate categories or an omitted result is refused', async () => {
  for (const ack of [{ acked: ['other'], stale: [], missing: [] }, { acked: ['notice_1'], stale: ['notice_1'], missing: [] }, { acked: [], stale: [], missing: [] }]) {
    const t = setup({ call: async (_method, path) => path.endsWith('/take') ? reply({ harness: HARNESS, notices: [notice()] }) : reply(ack) });
    try { await assert.rejects(t.start(), /invalid notice acknowledgement/); assert.equal(t.pump.status().last, null); assert.equal((await t.pump.list(HARNESS)).length, 1); } finally { t.cleanup(); }
  }
});

test('the mailbox remains recoverable when the in-process custody notification fails', async () => {
  const t = setup();
  const isolated = createNoticePump({ store: t.store, clock: t.clock, options: OPTIONS, ...t.timer,
    identityService: { call: async (_method, path) => path.endsWith('/take') ? reply({ harness: HARNESS, notices: [notice()] }) : reply({ acked: ['notice_1'], stale: [], missing: [] }) },
    events: { publish() { throw new Error('subscriber unavailable'); } }, log: { warn() {} },
  });
  try { isolated.start(); assert.equal((await isolated.pull()).acknowledged, 1); assert.equal((await isolated.list(HARNESS)).length, 1); } finally { isolated.stop(); t.cleanup(); }
});

test('two pump instances sharing the durable store still commit a notice only once', async () => {
  const t = setup();
  const published = [];
  const other = createNoticePump({ store: t.store, clock: t.clock, options: OPTIONS, ...timers(),
    identityService: { call: async (_method, path) => path.endsWith('/take') ? reply({ harness: HARNESS, notices: [notice()] }) : reply({ acked: ['notice_1'], stale: [], missing: [] }) },
    events: { publish: (...args) => published.push(args) }, log: { warn() {} },
  });
  try {
    t.pump.start(); other.start();
    const results = await Promise.all([t.pump.pull(), other.pull()]);
    assert.equal(results.reduce((n, r) => n + r.committed, 0), 1);
    assert.equal(results.reduce((n, r) => n + r.duplicates, 0), 1);
    assert.equal(t.published.length + published.length, 1);
    assert.equal((await t.pump.list(HARNESS)).length, 1);
  } finally { other.stop(); t.cleanup(); }
});

test('restart while an old request is in flight cannot cancel the new polling generation', async () => {
  const held = deferred();
  let requests = 0;
  const t = setup({ call: async () => {
    if (++requests === 1) await held.promise;
    return reply({ harness: HARNESS, notices: [] });
  } });
  try {
    t.pump.start(); const old = t.pump.pull(); t.pump.stop();
    t.pump.start(); await t.pump.pull(); assert.equal(t.timer.scheduled.size, 1);
    held.resolve(); await old; assert.equal(t.timer.scheduled.size, 1);
  } finally { held.resolve(); t.cleanup(); }
});

// The local mechanics take trusted host scope, not an agent request. HQ owns
// admission and invokes its full pinned response validator in prepareResult.
const scope = Object.freeze({ harness: HARNESS, repo: 'example/project' });
const prepare = () => {};
const ackFor = (body) => reply({ acked: [body.ids[0].slice(0, body.ids[0].indexOf('.'))], stale: [], missing: [] });
function batchSetup(batch, options = OPTIONS) {
  return setup({ options, call: async (_method, path, body) => path.endsWith('/take')
    ? reply({ harness: body.harness, notices: batch(body.harness) }) : ackFor(body) });
}

test('scoped peek is read-only, filters before selection, and follows custody sequence rather than source time or table order', async () => {
  const other = 'other-agent';
  const missing = notice('missing'); delete missing.repo;
  const invalid = ['example/..', 'example/.', 'https://example/project', 'example/project\n', 'example/project/extra'].map((repo, i) => notice(`invalid_${i}`, { repo }));
  const t = batchSetup((h) => h === other ? [notice('other_harness')] : [
    notice('first', { repo: 'Example/Project', createdAt: 900 }),
    notice('second', { createdAt: 1 }), missing, ...invalid, notice('other_repo', { repo: 'other/project' }),
  ], { harnesses: [HARNESS, other], count: 50 });
  try {
    await t.start();
    await t.store.tx((tx) => {
      const id = `${HARNESS}:first`; const first = tx.get('notice_mailbox', id);
      tx.delete('notice_mailbox', id); tx.put('notice_mailbox', id, first);
    });
    const before = readFileSync(join(t.home, 'store.json'), 'utf8');
    const calls = t.calls.length; const published = t.published.length;
    t.failure.persist = true; // Any unintended write would now fail.
    const peek = await t.pump.peek({ ...scope, repo: 'EXAMPLE/project', count: 50 });
    assert.deepEqual(peek.map((n) => n.message_id), ['first', 'second']);
    assert.equal(peek[0].content.repo, 'Example/Project', 'preserve source spelling');
    assert.ok(peek[0].content.createdAt > peek[1].content.createdAt);
    assert.equal(readFileSync(join(t.home, 'store.json'), 'utf8'), before);
    assert.equal(t.calls.length, calls); assert.equal(t.published.length, published);
    t.failure.persist = false;
    assert.deepEqual((await t.pump.consumeOne(scope, prepare)).map((n) => n.message_id), ['first']);
    assert.deepEqual((await t.pump.peek({ ...scope, count: 50 })).map((n) => n.message_id), ['second']);
    const remaining = await t.pump.list(HARNESS);
    assert.equal(remaining.length, 8, 'missing/invalid/other repository records remain ready alongside second');
    assert.equal((await t.pump.list(other)).length, 1);
    assert.equal(t.calls.length, calls, 'queries never take or acknowledge upstream');
    const malformed = remaining.find((r) => r.message_id === 'missing');
    assert.ok(malformed && !Object.hasOwn(malformed.notice, 'repo'));
    assert.deepEqual(await t.pump.acknowledge(HARNESS, ['missing']), { acked: ['missing'] }, 'explicit operator discard retains existing tombstone semantics');
  } finally { t.cleanup(); }
});

test('host-private local queries refuse malformed scope/count/selectors without storage or network effects', async () => {
  const t = setup();
  try {
    await t.start(); const before = readFileSync(join(t.home, 'store.json'), 'utf8'); const calls = t.calls.length;
    for (const query of [undefined, {}, { ...scope, harness: 'unconfigured' }, { ...scope, repo: 'example/project\n' },
      { ...scope, repo: 'example/..' }, { ...scope, count: 0 }, { ...scope, count: 51 }, { ...scope, count: 1.5 }, { ...scope, count: null },
      { ...scope, runtime_id: 'runtime:forged' }, { ...scope, installation_epoch: 1 }]) {
      await assert.rejects(t.pump.peek(query), (e) => e.code === 'host.invalid_request');
    }
    await assert.rejects(t.pump.consumeOne({ ...scope, count: 1 }, prepare), (e) => e.code === 'host.invalid_request');
    await assert.rejects(t.pump.consumeOne(scope), (e) => e.code === 'host.invalid_request');
    assert.equal(readFileSync(join(t.home, 'store.json'), 'utf8'), before); assert.equal(t.calls.length, calls);
  } finally { t.cleanup(); }
});

test('consume prepares an immutable full result before mutation, and failed/async preparation keeps the notice ready', async () => {
  const t = setup();
  try {
    await t.start(); const before = readFileSync(join(t.home, 'store.json'), 'utf8'); const calls = t.calls.length;
    await assert.rejects(t.pump.consumeOne(scope, () => { throw new Error('full result refused'); }), /full result refused/);
    await assert.rejects(t.pump.consumeOne(scope, () => Promise.resolve()), /must be synchronous/);
    await assert.rejects(t.pump.consumeOne(scope, async () => { throw new Error('async validator failed'); }), /must be synchronous/);
    await assert.rejects(t.pump.consumeOne(scope, (notices) => { notices[0].content.repo = 'other/project'; }), TypeError);
    assert.equal(readFileSync(join(t.home, 'store.json'), 'utf8'), before);
    let prepared;
    const result = await t.pump.consumeOne(scope, (notices) => {
      assert.equal(readFileSync(join(t.home, 'store.json'), 'utf8'), before, 'payload is durable and not yet consumed inside validation');
      assert.ok(Object.isFrozen(notices)); assert.ok(Object.isFrozen(notices[0].content.type));
      prepared = notices;
    });
    assert.equal(result, prepared, 'validated and returned content are the same immutable array');
    let emptyValidated = false;
    assert.deepEqual(await t.pump.consumeOne(scope, (notices) => { assert.deepEqual(notices, []); emptyValidated = true; }), []);
    assert.equal(emptyValidated, true); assert.equal(t.calls.length, calls);
    assert.equal((await t.pump.list(HARNESS)).length, 0);
  } finally { t.cleanup(); }
});

test('durability failure rolls back consume and no handoff is returned until a retry commits', async () => {
  const t = setup();
  try {
    await t.start(); const before = readFileSync(join(t.home, 'store.json'), 'utf8');
    t.failure.persist = true;
    await assert.rejects(t.pump.consumeOne(scope, prepare), /disk unavailable/);
    assert.equal(readFileSync(join(t.home, 'store.json'), 'utf8'), before);
    assert.deepEqual((await t.pump.peek(scope)).map((n) => n.message_id), ['notice_1']);
    t.failure.persist = false;
    assert.deepEqual((await t.pump.consumeOne(scope, prepare)).map((n) => n.message_id), ['notice_1']);
    assert.deepEqual(await t.pump.peek(scope), []);
  } finally { t.cleanup(); }
});

test('concurrent consumes across mailbox instances hand each ready notice off at most once', async () => {
  const t = batchSetup(() => [notice('one'), notice('two'), notice('three')]);
  const other = createNoticePump({ store: t.store, clock: t.clock, options: OPTIONS, ...timers(),
    identityService: { call() { throw new Error('local reads must not use the uplink'); } }, events: {}, log: {} });
  try {
    await t.start(); const calls = t.calls.length;
    const results = await Promise.all(Array.from({ length: 16 }, (_, i) => (i % 2 ? other : t.pump).consumeOne(scope, prepare)));
    assert.deepEqual(results.flat().map((n) => n.message_id), ['one', 'two', 'three']);
    assert.deepEqual(await t.pump.peek(scope), []); assert.equal(t.calls.length, calls);
    const stored = await t.store.tx((tx) => tx.list('notice_mailbox').map(([, row]) => row));
    assert.equal(stored.length, 3); assert.ok(stored.every((r) => r.state === 'consumed' && !Object.hasOwn(r, 'notice')));
  } finally { other.stop(); t.cleanup(); }
});

test('lost local response survives restart as a tombstone and upstream redelivery cannot resurrect it', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'notice-local-restart-'));
  const a = setup({ dir, call: async (_method, path) => path.endsWith('/take')
    ? reply({ harness: HARNESS, notices: [notice()] }) : Promise.reject(new Error('ack lost')) });
  let b;
  try {
    await assert.rejects(a.start(), /ack lost/);
    assert.equal((await a.pump.consumeOne(scope, prepare)).length, 1); // Caller may lose this response.
    a.pump.stop();
    const durable = readFileSync(join(dir, 'store.json'), 'utf8');
    assert.equal(durable.includes('Untrusted instruction'), false); assert.equal(durable.includes('LEASE_CANARY'), false);
    b = setup({ dir, call: async (_method, path, body) => path.endsWith('/take')
      ? reply({ harness: HARNESS, notices: [notice('notice_1', { lease: 'notice_1.NEW_LEASE', attempts: 2 })] }) : ackFor(body) });
    assert.deepEqual(await b.pump.peek(scope), []);
    assert.deepEqual(await b.start(), { received: 1, committed: 0, duplicates: 1, acknowledged: 1 });
    assert.deepEqual(await b.pump.consumeOne(scope, prepare), []); assert.equal(b.published.length, 0);
  } finally { a.pump.stop(); b?.pump.stop(); rmSync(dir, { recursive: true, force: true }); }
});

test('read-side sanitation preserves source fields and 256-character IDs while stripping transport/authority internals', async () => {
  const id = 'n'.repeat(256);
  const t = batchSetup(() => [notice(id, { url: 'https://example.invalid/issue/7', createdAt: 1794000000123 })], { ...OPTIONS, wakeClass: 'notify' });
  try {
    await t.start();
    await t.store.tx((tx) => {
      const key = `${HARNESS}:${id}`; const row = tx.get('notice_mailbox', key);
      Object.assign(row.notice, { lease: 'SECRET_CANARY', attempts: 1, lease_expires_at: 100, owner_directive: 'execute', channel_binding: 'SECRET_CANARY', unknown: 'SECRET_CANARY' });
      row.provenance = ['owner']; tx.put('notice_mailbox', key, row);
    });
    const [item] = await t.pump.peek(scope);
    assert.deepEqual(Object.keys(item).sort(), ['content', 'message_id', 'provenance', 'wake_class']);
    assert.equal(item.message_id, id); assert.deepEqual(item.provenance, ['external-untrusted']); assert.equal(item.wake_class, 'notify');
    assert.deepEqual(item.content, { app: HARNESS, repo: 'example/project', event: 'issues', action: 'opened', kind: 'mention', type: ['issue'],
      number: 7, title: 'Repair request', actor: 'test-agent', url: 'https://example.invalid/issue/7', text: 'Untrusted instruction', createdAt: 1794000000123 });
    assert.equal(JSON.stringify(item).includes('SECRET_CANARY'), false);
    assert.equal(Object.hasOwn(item.content, 'id'), false);
    assert.equal(Object.hasOwn(item.content, 'pulled'), false);
  } finally { t.cleanup(); }
});

test('invalid restored content and metadata stay ready and never gain caller repository or wake authority', async () => {
  const t = batchSetup(() => [notice('bad_wake'), notice('bad_id'), notice('bad_sequence'), notice('bad_number'), notice('bad_unicode')]);
  try {
    await t.start();
    await t.store.tx((tx) => {
      for (const [id, row] of tx.list('notice_mailbox')) {
        if (row.message_id === 'bad_wake') row.wake_class = 'cold-start';
        if (row.message_id === 'bad_id') row.notice.id = 'different';
        if (row.message_id === 'bad_sequence') row.sequence = -1;
        if (row.message_id === 'bad_number') row.notice.number = -1;
        if (row.message_id === 'bad_unicode') row.notice.text = '\ud800';
        tx.put('notice_mailbox', id, row);
      }
    });
    const before = readFileSync(join(t.home, 'store.json'), 'utf8');
    assert.deepEqual(await t.pump.peek({ ...scope, count: 50 }), []);
    assert.deepEqual(await t.pump.consumeOne(scope, prepare), []);
    assert.equal((await t.pump.list(HARNESS)).length, 5);
    assert.equal(readFileSync(join(t.home, 'store.json'), 'utf8'), before);
  } finally { t.cleanup(); }
});

test('canonical source budget is inclusive and excludes new result metadata', async () => {
  const source = { id: 'boundary', repo: 'example/project', text: '' };
  source.text = 'x'.repeat(65536 - canonicalBytes(source).length);
  const t = batchSetup(() => [{ ...source, lease: 'boundary.LEASE_CANARY' }]);
  try {
    await t.start();
    const [item] = await t.pump.peek(scope);
    assert.equal(canonicalBytes({ id: item.message_id, ...item.content }).length, 65536);
    assert.ok(canonicalBytes(item).length > 65536, 'new metadata does not narrow a legal source boundary');
    assert.equal((await t.pump.consumeOne(scope, prepare)).length, 1);
  } finally { t.cleanup(); }
});

test('oversize restored source is refused before preparation or mutation, measuring UTF-8 rather than code points', async () => {
  const t = batchSetup(() => [notice('oversize'), notice('out_of_scope', { repo: 'other/project' })]);
  try {
    await t.start();
    await t.store.tx((tx) => {
      for (const [id, row] of tx.list('notice_mailbox')) { row.notice.text = 'λ'.repeat(32768); tx.put('notice_mailbox', id, row); }
    });
    const before = readFileSync(join(t.home, 'store.json'), 'utf8'); const calls = t.calls.length;
    const tooLarge = (e) => e instanceof HostError && e.code === 'frame_too_large' && !e.message.includes('λ');
    await assert.rejects(t.pump.peek(scope), tooLarge);
    let validated = false;
    await assert.rejects(t.pump.consumeOne(scope, () => { validated = true; }), tooLarge);
    assert.equal(validated, false); assert.equal(readFileSync(join(t.home, 'store.json'), 'utf8'), before);
    assert.equal((await t.pump.list(HARNESS)).length, 2); assert.equal(t.calls.length, calls);
    await t.pump.acknowledge(HARNESS, ['oversize']);
    assert.deepEqual(await t.pump.peek(scope), [], 'out-of-scope oversize is neither exposed nor consumed');
    assert.equal((await t.pump.list(HARNESS)).length, 1);
  } finally { t.cleanup(); }
});

test('peek bounds aggregate canonical bytes without truncating or consuming content', async () => {
  const t = batchSetup(() => Array.from({ length: 10 }, (_, i) => notice(`large_${i}`, { text: 'x'.repeat(60000) })), { ...OPTIONS, count: 50 });
  try {
    await t.start(); const before = readFileSync(join(t.home, 'store.json'), 'utf8'); const calls = t.calls.length;
    const result = await t.pump.peek({ ...scope, count: 50 });
    assert.equal(result.length, 8); assert.ok(canonicalBytes(result).length <= 524288);
    assert.ok(canonicalBytes([...result, { ...result[0], message_id: 'large_8' }]).length > 524288);
    assert.ok(result.every((n) => n.content.text.length === 60000));
    assert.equal((await t.pump.list(HARNESS)).length, 10); assert.equal(readFileSync(join(t.home, 'store.json'), 'utf8'), before);
    assert.equal(t.calls.length, calls);
    assert.deepEqual((await t.pump.peek({ ...scope, count: 2 })).map((n) => n.message_id), ['large_0', 'large_1']);
  } finally { t.cleanup(); }
});

test('retained invalid repository metadata participates in capacity pressure instead of silent reassignment or eviction', async () => {
  let id = 'invalid';
  const t = batchSetup(() => [notice(id, { repo: 'not-a-repository' })], { ...OPTIONS, maxMessages: 1 });
  try {
    await t.start(); assert.deepEqual(await t.pump.peek(scope), []);
    assert.deepEqual(await t.pump.consumeOne(scope, prepare), []);
    id = 'later'; await assert.rejects(t.pump.pull(), (e) => e.noticeReason === 'mailbox_full');
    assert.equal((await t.pump.list(HARNESS))[0].message_id, 'invalid');
    assert.equal(t.pump.status().lastFailure, 'mailbox_full');
    assert.equal(t.calls.filter(([, path]) => path.endsWith('/ack')).length, 1, 'new delivery remains upstream unacknowledged');
  } finally { t.cleanup(); }
});
