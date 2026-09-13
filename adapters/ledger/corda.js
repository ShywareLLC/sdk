import { LedgerInterface } from './interface.js';

/**
 * CordaLedgerInterface — genuinely chain-enforced adapter targeting R3 Corda.
 *
 * Required env vars (all overridable via the constructor options object, matching the
 * override-friendly pattern used by every other adapter in this directory):
 *   CORDA_RPC_HOST      — host the CorDapp's webserver bridge (or the node's own RPC
 *                          port, if you point restBaseUrl elsewhere) is reachable at
 *   CORDA_RPC_PORT      — port for the above
 *   CORDA_RPC_USERNAME  — RPC user configured on the Corda node (see the CorDapp's
 *                          node.conf `rpcUsers` block) -- consumed by the webserver
 *                          bridge, not by this JS process directly
 *   CORDA_RPC_PASSWORD  — password for the above
 *   CORDA_REST_BASE_URL — optional full override, e.g. "https://corda-bridge.internal:8081"
 *                          (defaults to `http://${CORDA_RPC_HOST}:${CORDA_RPC_PORT}`)
 *
 * No peer dependency. Every other adapter in this directory (fabric.js, dynamodb.js,
 * etc.) dynamically imports its chain's official Node client library inside each
 * method, so that library stays an optional peer dependency. There is no equivalent
 * first-party Node client for Corda -- `corda-rpc` (CordaRPCClient) is JVM-only, and
 * no mature community Node/RPC bridge exists. Rather than depend on an unofficial or
 * unmaintained package, this adapter talks plain HTTP+JSON to a thin Spring Boot REST
 * bridge that ships as part of THIS CorDapp (see `./corda/cordapp/webserver/`), which
 * itself holds the CordaRPCClient connection to the node and starts flows on our
 * behalf, blocking until they complete. That bridge is the "mature client" substitute:
 * it's ours, it's checked in next to the contracts/flows it calls, and it's the only
 * thing in this adapter that has to change if a real `@corda/rpc` Node package ever
 * appears. Because the bridge is plain HTTP, this file needs no dynamic
 * `await import(...)` of a client library at all -- it uses the platform's built-in
 * `fetch` (Node >= 18), which keeps parity with the rest of this directory's
 * "no hard dependency on an unavailable client" goal via a different means.
 *
 * All chain enforcement (rejection predicate, sybil resistance, replay protection,
 * count-match, one-time-only period-close) lives in the CorDapp's TwoListContract,
 * verified by every node that resolves the transaction, and in the notary's refusal to
 * notarize two transactions that both try to consume the same version of a scopingId's
 * ScopingRegistryState. This file is a dumb HTTP client over that -- it does not, and
 * must not, re-implement any of those checks locally.
 */
export class CordaLedgerInterface extends LedgerInterface {
  constructor({
    rpcHost     = process.env.CORDA_RPC_HOST || 'localhost',
    rpcPort     = process.env.CORDA_RPC_PORT || '8081',
    rpcUsername = process.env.CORDA_RPC_USERNAME,
    rpcPassword = process.env.CORDA_RPC_PASSWORD,
    baseUrl     = process.env.CORDA_REST_BASE_URL || `http://${process.env.CORDA_RPC_HOST || 'localhost'}:${process.env.CORDA_RPC_PORT || '8081'}`,
    // Override-friendly: tests / callers can inject a fetch-compatible function directly
    // instead of relying on the global fetch, exactly like other adapters accept an
    // already-constructed client via the options object (see CockroachLedgerInterface's
    // `query` option).
    fetchImpl   = null,
    tracer      = null,
  } = {}) {
    super();
    this._cfg = { rpcHost, rpcPort, rpcUsername, rpcPassword, baseUrl };
    this._fetchImpl = fetchImpl;
    this._tracer = tracer;
  }

  get name() { return 'corda'; }

  async _fetch() {
    if (this._fetchImpl) return this._fetchImpl;
    if (typeof fetch === 'function') return fetch;
    // Fallback for Node < 18 or environments without a global fetch: dynamically import
    // node-fetch as an optional peer dependency, matching the lazy-import convention
    // used by every other adapter for their (mandatory, in their case) client library.
    const mod = await import('node-fetch');
    return mod.default;
  }

  async _traced(name, annotations, fn) {
    if (this._tracer) return this._tracer.trace(name, annotations, fn);
    return fn();
  }

  async _post(path, body) {
    const fetchFn = await this._fetch();
    const res = await fetchFn(`${this._cfg.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json?.error || `Corda bridge request failed: HTTP ${res.status}`);
    return json;
  }

  async _get(path) {
    const fetchFn = await this._fetch();
    const res = await fetchFn(`${this._cfg.baseUrl}${path}`, { method: 'GET' });
    const json = await res.json();
    if (!res.ok) throw new Error(json?.error || `Corda bridge request failed: HTTP ${res.status}`);
    return json;
  }

  async submitTwoListWrite(scopingId, list1, list2) {
    return this._traced('corda.flow.submit', { scopingId }, async () => {
      const result = await this._post('/two-list/submit', {
        scopingId,
        submissionId: list1.submissionId,
        payloadCommitment: list1.payloadCommitment,
        identityHash: list2.identityHash,
      });
      return { txId: result.txId, l1Count: result.l1Count, l2Count: result.l2Count, countMatch: result.countMatch };
    });
  }

  async getCount(scopingId) {
    return this._traced('corda.flow.getCount', { scopingId }, async () => {
      const result = await this._get(`/two-list/count/${encodeURIComponent(scopingId)}`);
      return { l1Count: result.l1Count, l2Count: result.l2Count, countMatch: result.countMatch };
    });
  }

  async rescindTwoListWrite(scopingId, submissionId, identityHash) {
    return this._traced('corda.flow.rescind', { scopingId }, async () => {
      const result = await this._post('/two-list/rescind', { scopingId, submissionId, identityHash });
      return { countMatch: result.countMatch, rescinded: result.rescinded };
    });
  }

  async replaceTwoListWrite(scopingId, oldSubmissionId, newList1, identityHash) {
    return this._traced('corda.flow.replace', { scopingId }, async () => {
      const result = await this._post('/two-list/replace', {
        scopingId,
        oldSubmissionId,
        newSubmissionId: newList1.submissionId,
        newPayloadCommitment: newList1.payloadCommitment,
        identityHash,
      });
      return { countMatch: result.countMatch, replaced: result.replaced, newSubmissionId: result.newSubmissionId };
    });
  }

  async commitPeriodClose(scopingId, l1MerkleRoot, l2MerkleRoot, attestation) {
    return this._traced('corda.flow.period-close', { scopingId }, async () => {
      const result = await this._post('/two-list/period-close', { scopingId, l1MerkleRoot, l2MerkleRoot, attestation });
      return { txId: result.txId, timestamp: result.timestamp };
    });
  }

  async disconnect() {
    // Stateless HTTP client -- nothing to tear down. The long-lived CordaRPCConnection
    // lives in the webserver bridge process, not here.
  }
}
