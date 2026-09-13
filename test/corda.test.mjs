import test from "node:test";
import assert from "node:assert/strict";
import { CordaLedgerInterface } from "../adapters/ledger/corda.js";

/**
 * Unit tests for the JS side of the Corda adapter, with the HTTP bridge mocked out.
 * This does NOT verify the chain-enforced logic (rejection predicate, sybil resistance,
 * replay protection, count-match, one-time-only close) -- that lives in
 * adapters/ledger/corda/cordapp/contracts/.../TwoListContract.kt and is exercised for
 * real by the Corda `driver`-based integration test at
 * adapters/ledger/corda/cordapp/workflows/src/test/kotlin/.../TwoListFlowTests.kt.
 * What this file verifies is narrower and just as necessary: that the JS adapter calls
 * the right bridge endpoint with the right body, and reshapes the bridge's response into
 * the exact shape every other LedgerInterface implementation returns, so it is a drop-in
 * swap for any consumer already coded against the interface.
 */

function mockLedger(responseByPath) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const path = url.replace(/^http:\/\/[^/]+/, "");
    const key = Object.keys(responseByPath).find((p) => path === p || path.startsWith(p));
    calls.push({ url, init });
    const body = responseByPath[key];
    return { ok: true, status: 200, json: async () => body };
  };
  const ledger = new CordaLedgerInterface({ baseUrl: "http://localhost:8081", fetchImpl });
  return { ledger, calls };
}

test("has the expected adapter name", () => {
  const { ledger } = mockLedger({});
  assert.equal(ledger.name, "corda");
});

test("submitTwoListWrite posts to /two-list/submit and reshapes the flow result", async () => {
  const { ledger, calls } = mockLedger({
    "/two-list/submit": { txId: "TX1", scopingId: "poll-1", l1Count: 3, l2Count: 3, countMatch: true },
  });

  const result = await ledger.submitTwoListWrite(
    "poll-1",
    { submissionId: "sub-1", payloadCommitment: "commit-1" },
    { identityHash: "hash-1" }
  );

  assert.deepEqual(result, { txId: "TX1", l1Count: 3, l2Count: 3, countMatch: true });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://localhost:8081/two-list/submit");
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    scopingId: "poll-1",
    submissionId: "sub-1",
    payloadCommitment: "commit-1",
    identityHash: "hash-1",
  });
});

test("getCount reads /two-list/count/:scopingId and drops non-interface fields", async () => {
  const { ledger, calls } = mockLedger({
    "/two-list/count/poll-1": { scopingId: "poll-1", l1Count: 5, l2Count: 5, countMatch: true },
  });

  const result = await ledger.getCount("poll-1");

  assert.deepEqual(result, { l1Count: 5, l2Count: 5, countMatch: true });
  assert.equal(calls[0].url, "http://localhost:8081/two-list/count/poll-1");
  assert.equal(calls[0].init.method, "GET");
});

test("rescindTwoListWrite posts to /two-list/rescind", async () => {
  const { ledger, calls } = mockLedger({
    "/two-list/rescind": { countMatch: true, rescinded: true },
  });

  const result = await ledger.rescindTwoListWrite("poll-1", "sub-1", "hash-1");

  assert.deepEqual(result, { countMatch: true, rescinded: true });
  assert.deepEqual(JSON.parse(calls[0].init.body), { scopingId: "poll-1", submissionId: "sub-1", identityHash: "hash-1" });
});

test("replaceTwoListWrite posts to /two-list/replace", async () => {
  const { ledger, calls } = mockLedger({
    "/two-list/replace": { countMatch: true, replaced: true, newSubmissionId: "sub-2" },
  });

  const result = await ledger.replaceTwoListWrite(
    "poll-1", "sub-1", { submissionId: "sub-2", payloadCommitment: "commit-2" }, "hash-1"
  );

  assert.deepEqual(result, { countMatch: true, replaced: true, newSubmissionId: "sub-2" });
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    scopingId: "poll-1",
    oldSubmissionId: "sub-1",
    newSubmissionId: "sub-2",
    newPayloadCommitment: "commit-2",
    identityHash: "hash-1",
  });
});

test("commitPeriodClose posts to /two-list/period-close", async () => {
  const { ledger, calls } = mockLedger({
    "/two-list/period-close": { txId: "TX9", timestamp: "2026-09-13T00:00:00Z" },
  });

  const result = await ledger.commitPeriodClose("poll-1", "l1root", "l2root", "sig");

  assert.deepEqual(result, { txId: "TX9", timestamp: "2026-09-13T00:00:00Z" });
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    scopingId: "poll-1", l1MerkleRoot: "l1root", l2MerkleRoot: "l2root", attestation: "sig",
  });
});

test("surfaces bridge-reported flow/contract rejections as thrown errors", async () => {
  const fetchImpl = async () => ({
    ok: false,
    status: 400,
    json: async () => ({ error: "rejection predicate violated: sha256(submissionId) == identityHash" }),
  });
  const ledger = new CordaLedgerInterface({ baseUrl: "http://localhost:8081", fetchImpl });

  await assert.rejects(
    ledger.submitTwoListWrite("poll-1", { submissionId: "x", payloadCommitment: "y" }, { identityHash: "z" }),
    /rejection predicate violated/
  );
});

test("disconnect resolves without throwing (stateless HTTP client)", async () => {
  const { ledger } = mockLedger({});
  await ledger.disconnect();
});
