import { LedgerInterface } from './interface.js';

/**
 * CometBFTLedgerInterface — two-list write adapter for Shyware's own reference
 * chain: a real CometBFT BFT consensus node running the domain-agnostic
 * shygeneric ABCI application (github.com/ShywareLLC/core/domain/state/generic,
 * wired via github.com/ShywareLLC/core/app/genericapp).
 *
 * Unlike the vote embodiment's REST API (which is hard-wired to polls/ballots
 * and requires Didit identity-verification fields on every write), the
 * shygeneric REST layer (github.com/ShywareLLC/core/api/genericserver) exposes
 * exactly the five two-list operations this interface needs, over plain HTTP,
 * with no domain-specific fields. This adapter talks to that REST layer with
 * `fetch` — no external dependency, no CometBFT client library required.
 *
 * REST surface (see api/genericserver/router.go):
 *   POST /submissions                              -> submitTwoListWrite
 *   GET  /submissions/{scoping_id}/count            -> getCount
 *   POST /submissions/{scoping_id}/rescind          -> rescindTwoListWrite
 *   POST /submissions/{scoping_id}/replace          -> replaceTwoListWrite
 *   POST /submissions/{scoping_id}/period-close     -> commitPeriodClose
 *
 * Required env vars (all have constructor overrides):
 *   COMETBFT_API_URL   — base URL of the shygeneric REST layer
 *                        (default: http://127.0.0.1:8090)
 *
 * The REST layer itself is a stateless proxy to the CometBFT node's RPC
 * (broadcast_tx_commit / abci_query) — no database, no auth, no session.
 * Deployments front it with their own middleware as needed.
 */
export class CometBFTLedgerInterface extends LedgerInterface {
  constructor({
    apiUrl = process.env.COMETBFT_API_URL || 'http://127.0.0.1:8090',
  } = {}) {
    super();
    this._apiUrl = apiUrl.replace(/\/+$/, '');
  }

  get name() { return 'cometbft'; }

  async _post(path, body) {
    const res = await fetch(`${this._apiUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return this._parseBroadcast(res);
  }

  async _get(path) {
    const res = await fetch(`${this._apiUrl}${path}`, { method: 'GET' });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`CometBFT ledger query failed (${res.status}): ${text}`);
    }
    return res.json();
  }

  /**
   * Parses a broadcast_tx_commit response and throws if either the mempool
   * (check_tx) or the finalized-block (tx_result) execution rejected the tx —
   * mirroring the txFailed() check the vote embodiment's own REST layer uses.
   */
  async _parseBroadcast(res) {
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`CometBFT ledger write failed (${res.status}): ${text}`);
    }
    const body = await res.json();
    const result = body?.result ?? {};
    const checkTx = result.check_tx ?? {};
    const txResult = result.tx_result ?? result.deliver_tx ?? {};
    if (checkTx.code) {
      throw new Error(`CometBFT rejected tx at CheckTx: ${checkTx.log || checkTx.code}`);
    }
    if (txResult.code) {
      throw new Error(`CometBFT rejected tx at FinalizeBlock: ${txResult.log || txResult.code}`);
    }
    return { txId: result.hash, height: result.height };
  }

  async submitTwoListWrite(scopingId, list1, list2) {
    const { txId } = await this._post('/submissions', {
      scoping_id: scopingId,
      list1,
      list2,
    });
    return { txId, ...(await this.getCount(scopingId)) };
  }

  async getCount(scopingId) {
    const data = await this._get(`/submissions/${encodeURIComponent(scopingId)}/count`);
    return {
      l1Count: data.l1Count ?? 0,
      l2Count: data.l2Count ?? 0,
      countMatch: data.countMatch ?? (data.l1Count === data.l2Count),
    };
  }

  async commitPeriodClose(scopingId, l1MerkleRoot, l2MerkleRoot, attestation) {
    const { txId } = await this._post(`/submissions/${encodeURIComponent(scopingId)}/period-close`, {
      l1_merkle_root: l1MerkleRoot,
      l2_merkle_root: l2MerkleRoot,
      attestation,
    });
    return { txId, timestamp: new Date().toISOString() };
  }

  async rescindTwoListWrite(scopingId, submissionId, identityHash) {
    await this._post(`/submissions/${encodeURIComponent(scopingId)}/rescind`, {
      submission_id: submissionId,
      identity_hash: identityHash,
    });
    return { rescinded: true, ...(await this.getCount(scopingId)) };
  }

  async replaceTwoListWrite(scopingId, oldSubmissionId, newList1, identityHash) {
    await this._post(`/submissions/${encodeURIComponent(scopingId)}/replace`, {
      old_submission_id: oldSubmissionId,
      new_list1: newList1,
      identity_hash: identityHash,
    });
    return {
      replaced: true,
      newSubmissionId: newList1.submissionId,
      ...(await this.getCount(scopingId)),
    };
  }

  async disconnect() {}
}
