import { randomUUID } from 'crypto';
import { LedgerInterface } from './interface.js';

/**
 * MemoryLedgerInterface — in-process two-list ledger for dev and unit tests.
 *
 * State is held in Maps; nothing is persisted. Create one instance per test
 * and discard it — there is no reset() because isolation is free with `new`.
 *
 * The rejection predicate is enforced in the same way as CockroachLedgerInterface:
 * list1 must not contain identityHash; list2 must not contain submissionId.
 *
 * Usage:
 *   import { MemoryLedgerInterface } from '@shyware/sdk/adapters';
 *   const ledger = new MemoryLedgerInterface();
 */
export class MemoryLedgerInterface extends LedgerInterface {
  constructor() {
    super();
    // { `${scopingId}:${submissionId}` → { txId, scopingId, submissionId, payloadCommitment, ...rest } }
    this._l1 = new Map();
    // { `${scopingId}:${identityHash}` → { txId, scopingId, identityHash, ...rest } }
    this._l2 = new Map();
    // { scopingId → [{ txId, l1MerkleRoot, l2MerkleRoot, attestation, timestamp }] }
    this._periodCloses = new Map();
  }

  get name() { return 'memory'; }

  _rejectIfJoinable(list1, list2) {
    if ('identityHash' in list1) throw new Error('Rejection predicate: list1 must not contain identityHash');
    if ('submissionId' in list2) throw new Error('Rejection predicate: list2 must not contain submissionId');
  }

  async submitTwoListWrite(scopingId, list1, list2) {
    this._rejectIfJoinable(list1, list2);
    const txId = randomUUID();
    this._l1.set(`${scopingId}:${list1.submissionId}`, { txId, scopingId, ...list1 });
    this._l2.set(`${scopingId}:${list2.identityHash}`, { txId, scopingId, ...list2 });
    return { txId, ...(await this.getCount(scopingId)) };
  }

  async getCount(scopingId) {
    let l1Count = 0, l2Count = 0;
    const prefix = `${scopingId}:`;
    for (const k of this._l1.keys()) if (k.startsWith(prefix)) l1Count++;
    for (const k of this._l2.keys()) if (k.startsWith(prefix)) l2Count++;
    return { l1Count, l2Count, countMatch: l1Count === l2Count };
  }

  async rescindTwoListWrite(scopingId, submissionId, identityHash) {
    const l1Key = `${scopingId}:${submissionId}`;
    const l2Key = `${scopingId}:${identityHash}`;
    const rescinded = this._l1.has(l1Key) && this._l2.has(l2Key);
    this._l1.delete(l1Key);
    this._l2.delete(l2Key);
    return { rescinded, ...(await this.getCount(scopingId)) };
  }

  async replaceTwoListWrite(scopingId, oldSubmissionId, newList1, identityHash) {
    this._rejectIfJoinable(newList1, {});
    this._l1.delete(`${scopingId}:${oldSubmissionId}`);
    const txId = randomUUID();
    this._l1.set(`${scopingId}:${newList1.submissionId}`, { txId, scopingId, ...newList1 });
    return { replaced: true, newSubmissionId: newList1.submissionId, ...(await this.getCount(scopingId)) };
  }

  async commitPeriodClose(scopingId, l1MerkleRoot, l2MerkleRoot, attestation) {
    const txId = randomUUID();
    const timestamp = new Date().toISOString();
    const closes = this._periodCloses.get(scopingId) ?? [];
    closes.push({ txId, l1MerkleRoot, l2MerkleRoot, attestation, timestamp });
    this._periodCloses.set(scopingId, closes);
    return { txId, timestamp };
  }

  /** Test helper — returns all L1 entries for a scopingId. */
  l1Entries(scopingId) {
    const prefix = `${scopingId}:`;
    return [...this._l1.entries()]
      .filter(([k]) => k.startsWith(prefix))
      .map(([, v]) => v);
  }

  /** Test helper — returns all L2 entries for a scopingId. */
  l2Entries(scopingId) {
    const prefix = `${scopingId}:`;
    return [...this._l2.entries()]
      .filter(([k]) => k.startsWith(prefix))
      .map(([, v]) => v);
  }
}
