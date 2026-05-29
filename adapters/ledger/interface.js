export class LedgerInterface {
  get name() { throw new Error('LedgerInterface.name not implemented'); }

  /**
   * Atomically write one L1 record (no identity) and one L2 record (no payload).
   * Claim 1 (rejection predicate): the adapter must ensure no join key between L1 and L2
   * is ever committed to canonical state.
   *
   * Claim 24: list1.submissionId and list2.identityHash must be derived through
   * independent paths — no shared input, seed, or intermediate state.
   *
   * Claim 25: list2.identityHash must include the scopingId as a derivation input
   * so the same participant's identity commitment is unlinkable across different
   * transaction-scoping identifiers.
   *
   * @param {string} scopingId
   * @param {{ submissionId: string, payloadCommitment: string }} list1
   * @param {{ identityHash: string }} list2  identityHash = H(uid || scopingId)
   * @returns {Promise<{ txId: string, l1Count: number, l2Count: number, countMatch: boolean }>}
   */
  async submitTwoListWrite(_scopingId, _list1, _list2) {
    throw new Error('LedgerInterface.submitTwoListWrite not implemented');
  }

  /**
   * @param {string} scopingId
   * @returns {Promise<{ l1Count: number, l2Count: number, countMatch: boolean }>}
   */
  async getCount(_scopingId) {
    throw new Error('LedgerInterface.getCount not implemented');
  }

  /**
   * Seal a period with disjoint Merkle roots. No join between the two roots is written.
   * Claim 61: l1MerkleRoot is over submission identifiers only; l2MerkleRoot is over
   * identity hashes only. The attestation is a single signature over both roots + count,
   * produced by a key not in canonical state.
   *
   * @param {string} scopingId
   * @param {string} l1MerkleRoot  — over submission identifiers only
   * @param {string} l2MerkleRoot  — over identity hashes only
   * @param {string} attestation   — signing-adapter signature (KMS / CloudHSM for Claim 80)
   * @returns {Promise<{ txId: string, timestamp: string }>}
   */
  async commitPeriodClose(_scopingId, _l1MerkleRoot, _l2MerkleRoot, _attestation) {
    throw new Error('LedgerInterface.commitPeriodClose not implemented');
  }

  /**
   * Participant-initiated withdrawal (Claim 7): atomically delete L1 + L2 for a submission,
   * decrement count. No co-authorization required. No new identity commitment introduced.
   * Count-match is preserved after deletion.
   *
   * Credential-free rescission (Claim 32): caller derives identityHash from a fresh
   * authentication attestation — no retained receipt, device key, or memorized secret.
   *
   * @param {string} scopingId
   * @param {string} submissionId  — from L1 record to delete
   * @param {string} identityHash  — H(uid || scopingId) derived from fresh auth
   * @returns {Promise<{ countMatch: boolean, rescinded: boolean }>}
   */
  async rescindTwoListWrite(_scopingId, _submissionId, _identityHash) {
    throw new Error('LedgerInterface.rescindTwoListWrite not implemented');
  }

  /**
   * Participant-initiated replacement (Claim 7/4): atomically replace the L1 record
   * (new submissionId + payload) while leaving L2 unchanged. Count-match preserved.
   *
   * Credential-free replacement (Claim 32): new submissionId derived from new nonce;
   * L2 identity commitment unchanged; no new participant introduced.
   *
   * @param {string} scopingId
   * @param {string} oldSubmissionId
   * @param {{ submissionId: string, payloadCommitment: string }} newList1
   * @param {string} identityHash  — H(uid || scopingId) from fresh auth (for audit)
   * @returns {Promise<{ countMatch: boolean, replaced: boolean, newSubmissionId: string }>}
   */
  async replaceTwoListWrite(_scopingId, _oldSubmissionId, _newList1, _identityHash) {
    throw new Error('LedgerInterface.replaceTwoListWrite not implemented');
  }

  async disconnect() {}
}
