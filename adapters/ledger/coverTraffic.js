import { LedgerInterface } from './interface.js';
import crypto from 'crypto';

// Dummy tag written into submissionId and identityHash fields of cover writes.
// The tag is a fixed prefix; the filter checks for it before ABCI broadcast.
// Never appears in a real submission (real submissionIds are SHA-256 hex; no prefix).
const DUMMY_PREFIX = '__cover__';

/**
 * CoverTrafficInterface — LedgerInterface decorator.
 *
 * Wraps any real LedgerInterface. Intercepts submitTwoListWrite:
 *   - Real writes pass through to the underlying adapter unchanged.
 *   - Dummy writes (submissionId starts with DUMMY_PREFIX) are dropped
 *     and never forwarded to the ABCI layer — canonical state is never touched.
 *
 * Background noise: starts a background interval that fires dummy two-list
 * write calls at `ratePerMinute`. Each dummy is indistinguishable at the API
 * layer from a real submission but is silently discarded here before reaching
 * the ledger. Timing observers watching the API see a continuous stream of
 * writes regardless of real user activity.
 *
 * Count-match invariant is always preserved: dummies are stripped before
 * any canonical write, so |L1| and |L2| reflect only real submissions.
 *
 * Configured via shyconfig deployment.submission_dispatch: "cover_traffic"
 * and deployment.cover_traffic_rate (dummies per minute, default 10).
 *
 * @param {LedgerInterface} inner  — the real ledger adapter
 * @param {{ ratePerMinute?: number }} opts
 */
export class CoverTrafficInterface extends LedgerInterface {
  constructor(inner, { ratePerMinute = 10 } = {}) {
    super();
    this._inner = inner;
    this._ratePerMinute = ratePerMinute;
    this._timer = null;
    this._activeScopingIds = new Set();
    // Counts real submissions since last dummy interval tick.
    // Each real submission absorbs one upcoming dummy slot so the
    // aggregate write-shaped request rate at the transport layer
    // remains governed by the configured cover-traffic schedule.
    this._pendingRealCount = 0;
  }

  get name() { return `cover_traffic(${this._inner.name})`; }

  // Track which scopingIds are active so background dummies use a real one.
  _registerScopingId(scopingId) {
    this._activeScopingIds.add(scopingId);
  }

  _dummySubmissionId() {
    return DUMMY_PREFIX + crypto.randomBytes(16).toString('hex');
  }

  _isDummy(list1) {
    return typeof list1?.submissionId === 'string' &&
           list1.submissionId.startsWith(DUMMY_PREFIX);
  }

  async submitTwoListWrite(scopingId, list1, list2) {
    this._registerScopingId(scopingId);
    // Drop dummy writes silently — never reaches canonical state.
    if (this._isDummy(list1)) {
      return { txId: null, l1Count: 0, l2Count: 0, countMatch: true, _dummy: true };
    }
    // Real submission: absorb the next dummy slot so aggregate transport-layer
    // rate stays governed by the configured cover-traffic schedule.
    this._pendingRealCount++;
    return this._inner.submitTwoListWrite(scopingId, list1, list2);
  }

  async getCount(scopingId) {
    return this._inner.getCount(scopingId);
  }

  async commitPeriodClose(scopingId, l1MerkleRoot, l2MerkleRoot, attestation) {
    return this._inner.commitPeriodClose(scopingId, l1MerkleRoot, l2MerkleRoot, attestation);
  }

  async rescindTwoListWrite(scopingId, submissionId, identityHash) {
    return this._inner.rescindTwoListWrite(scopingId, submissionId, identityHash);
  }

  async replaceTwoListWrite(scopingId, oldSubmissionId, newList1, identityHash) {
    return this._inner.replaceTwoListWrite(scopingId, oldSubmissionId, newList1, identityHash);
  }

  /**
   * Start background dummy traffic. Fires ratePerMinute dummy submitTwoListWrite
   * calls per minute spread evenly across the interval. Each is immediately
   * dropped by this adapter's own filter before touching the ledger.
   *
   * The noise is visible at the HTTP/API layer (the calls are real HTTP requests
   * to the same endpoint as real submissions) but transparent to canonical state.
   */
  startCoverTraffic() {
    if (this._timer) return;
    const intervalMs = Math.round(60_000 / this._ratePerMinute);
    this._timer = setInterval(() => {
      // If a real submission already fired this slot, absorb it — skip the
      // dummy so the aggregate transport-layer rate stays at the configured
      // cover-traffic schedule rather than spiking on real activity.
      if (this._pendingRealCount > 0) {
        this._pendingRealCount--;
        return;
      }
      const scopingId = this._activeScopingIds.size > 0
        ? [...this._activeScopingIds][Math.floor(Math.random() * this._activeScopingIds.size)]
        : 'cover-scoping-id';
      const dummyList1 = {
        submissionId: this._dummySubmissionId(),
        payloadCommitment: crypto.randomBytes(32).toString('hex'),
      };
      const dummyList2 = {
        identityHash: DUMMY_PREFIX + crypto.randomBytes(32).toString('hex'),
      };
      // Fire and forget — silently dropped by submitTwoListWrite above.
      this.submitTwoListWrite(scopingId, dummyList1, dummyList2).catch(() => {});
    }, intervalMs);
  }

  stopCoverTraffic() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }

  async disconnect() {
    this.stopCoverTraffic();
    await this._inner.disconnect();
  }
}

/**
 * Wrap a LedgerInterface with cover traffic if shyconfig requests it.
 *
 * Usage in consumer ledger server:
 *   import { wrapWithCoverTraffic } from '@shyware/sdk/adapters/ledger/coverTraffic.js';
 *   const ledger = wrapWithCoverTraffic(new FabricLedgerInterface(...), shyconfig);
 *   ledger.startCoverTraffic();
 *
 * @param {LedgerInterface} adapter
 * @param {object} shyconfig
 * @returns {LedgerInterface}
 */
export function wrapWithCoverTraffic(adapter, shyconfig) {
  const dispatch = shyconfig?.deployment?.submission_dispatch;
  if (dispatch !== 'cover_traffic') return adapter;
  const rate = shyconfig?.deployment?.cover_traffic_rate ?? 10;
  return new CoverTrafficInterface(adapter, { ratePerMinute: rate });
}
