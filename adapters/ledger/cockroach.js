import { randomUUID, createHash } from 'crypto';
import { LedgerInterface } from './interface.js';

export class CockroachLedgerInterface extends LedgerInterface {
  constructor({ query }) {
    super();
    if (typeof query !== 'function') throw new Error('CockroachLedgerInterface requires a query function');
    this._query = query;
  }

  get name() { return 'cockroach'; }

  _rejectIfJoinable(list1, list2) {
    if ('identityHash' in list1) throw new Error('Rejection predicate: list1 must not contain identityHash');
    if ('submissionId' in list2) throw new Error('Rejection predicate: list2 must not contain submissionId');
  }

  async submitTwoListWrite(scopingId, list1, list2) {
    this._rejectIfJoinable(list1, list2);
    const txId = randomUUID();
    const now = new Date().toISOString();
    await this._query(
      `INSERT INTO shy_l1 (tx_id,scoping_id,submission_id,payload_commitment,domain_fields,created_at) VALUES ($1,$2,$3,$4,$5::jsonb,$6) ON CONFLICT DO NOTHING`,
      [txId, scopingId, list1.submissionId, list1.payloadCommitment, JSON.stringify(list1), now]
    );
    await this._query(
      `INSERT INTO shy_l2 (tx_id,scoping_id,identity_hash,domain_fields,created_at) VALUES ($1,$2,$3,$4::jsonb,$5) ON CONFLICT DO NOTHING`,
      [txId, scopingId, list2.identityHash, JSON.stringify(list2), now]
    );
    return { txId, ...(await this.getCount(scopingId)) };
  }

  async getCount(scopingId) {
    const [r1, r2] = await Promise.all([
      this._query(`SELECT COUNT(*)::int AS n FROM shy_l1 WHERE scoping_id = $1`, [scopingId]),
      this._query(`SELECT COUNT(*)::int AS n FROM shy_l2 WHERE scoping_id = $1`, [scopingId]),
    ]);
    const l1Count = Number(r1.rows[0].n), l2Count = Number(r2.rows[0].n);
    return { l1Count, l2Count, countMatch: l1Count === l2Count };
  }

  async commitPeriodClose(scopingId, l1MerkleRoot, l2MerkleRoot, attestation) {
    const txId = randomUUID(), timestamp = new Date().toISOString();
    await this._query(
      `INSERT INTO shy_period_close (tx_id,scoping_id,l1_merkle_root,l2_merkle_root,attestation,created_at) VALUES ($1,$2,$3,$4,$5,$6)`,
      [txId, scopingId, l1MerkleRoot, l2MerkleRoot, attestation, timestamp]
    );
    return { txId, timestamp };
  }
}
