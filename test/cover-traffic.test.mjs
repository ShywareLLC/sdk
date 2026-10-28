import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { CoverTrafficDispatcher, encodeDispatch, DISPATCH_BYTES } from '../adapters/ledger/coverTraffic.js';

test('real cast, replacement and withdrawal use dummy slots on an actual HTTP transport', async () => {
  const observed = [];
  let canonical = 0;
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const bytes = Buffer.concat(chunks);
    const envelope = JSON.parse(bytes);
    observed.push({ path: req.url, length: bytes.length, kind: envelope.kind });
    if (envelope.kind !== 'dummy') canonical++;
    res.end(JSON.stringify({ accepted: true }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const dispatch = new CoverTrafficDispatcher(async body => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/dispatch`, { method: 'POST', body });
    return response.json();
  }, { ratePerMinute: 0.01 });
  dispatch.start();
  try {
    await dispatch.tick();
    for (const [kind, body] of [['cast', { tx: 'cast' }], ['update', { tx: 'replace' }], ['update', { tx: 'withdraw' }]]) {
      const before = observed.length;
      const pending = dispatch.submit(kind, body);
      await new Promise(resolve => setImmediate(resolve));
      assert.equal(observed.length, before, 'real writes must wait for a slot');
      await dispatch.tick();
      assert.deepEqual(await pending, { accepted: true });
    }
    await dispatch.tick();
    assert.deepEqual(observed.map(r => r.kind), ['dummy', 'cast', 'update', 'update', 'dummy']);
    assert.ok(observed.every(r => r.path === '/dispatch' && r.length === DISPATCH_BYTES));
    assert.equal(canonical, 3);
  } finally { dispatch.stop(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});

test('invalid configuration, size, lifecycle, cancellation and transport failure', async () => {
  assert.throws(() => new CoverTrafficDispatcher(null));
  for (const rate of [0, -1, Infinity, NaN, 601]) assert.throws(() => new CoverTrafficDispatcher(async () => {}, { ratePerMinute: rate }));
  assert.throws(() => encodeDispatch('cast', { tx: 'x'.repeat(DISPATCH_BYTES) }));
  assert.equal(Buffer.byteLength(encodeDispatch('cast', { tx: 'é' })), DISPATCH_BYTES);
  let calls = 0;
  const d = new CoverTrafficDispatcher(async () => { calls++; throw new Error('network failed'); }, { ratePerMinute: 0.01, maxPending: 1 });
  assert.throws(() => d.submit('cast', {}), /not running/);
  d.start();
  const pending = d.submit('cast', {});
  const failure = assert.rejects(pending, /network failed/);
  assert.throws(() => d.submit('update', {}), /full/);
  await d.tick(); await failure;
  assert.equal(calls, 1, 'no automatic duplicate retry');
  const cancelled = d.submit('update', {});
  const cancellation = assert.rejects(cancelled, /stopped/);
  d.stop(); await cancellation;
});

test('scheduled ticks continue while a slow real request is in flight', async () => {
  const times = [];
  let release;
  const slow = new Promise(resolve => { release = resolve; });
  const d = new CoverTrafficDispatcher(async bytes => {
    times.push(performance.now());
    if (JSON.parse(bytes).kind === 'cast') await slow;
    return {};
  }, { ratePerMinute: 600 });
  d.start();
  const vote = d.submit('cast', {});
  try {
    await new Promise(resolve => setTimeout(resolve, 450));
    assert.ok(times.length >= 3, 'a slow response must not stop scheduled cover');
    assert.ok(times.slice(1).every((t, i) => t - times[i] >= 75), 'real activity must not add immediate requests');
  } finally { release(); await vote; d.stop(); }
});

test('voting client routes configured casts through the receiving endpoint', async () => {
  const { createVotingClient } = await import('../clients/embodiments/votingClient.js');
  const observed = [];
  const client = createVotingClient({
    defaultBase: 'https://example.test',
    manifest: { deployment: { submission_dispatch: 'cover_traffic', cover_traffic_rate: 600 } },
    getAuthHeaders: async () => ({ Authorization: 'Bearer test-token' }),
    fetchImpl: async (url, request) => {
      observed.push({ url, request });
      const raw = JSON.stringify({ status: 200, body: { queued: true } });
      return new Response(raw + ' '.repeat(DISPATCH_BYTES - Buffer.byteLength(raw)), { status: 200 });
    }
  });
  await assert.rejects(client.submitVote('{}'), /not running/);
  client.startCoverTraffic();
  try {
    const pending = client.submitVote('{}');
    assert.equal(observed.length, 0);
    assert.deepEqual(await pending, { queued: true });
    assert.equal(observed[0].url, 'https://example.test/dispatch');
    assert.equal(observed[0].request.headers.Authorization, 'Bearer test-token');
    assert.equal(Buffer.byteLength(observed[0].request.body), DISPATCH_BYTES);
    assert.equal(JSON.parse(observed[0].request.body).kind, 'cast');
  } finally { client.stopCoverTraffic(); }
});
