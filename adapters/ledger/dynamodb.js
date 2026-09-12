import { randomUUID } from 'crypto';
import { LedgerInterface } from './interface.js';

/**
 * DynamoDBLedgerInterface — two-list write adapter for AWS DynamoDB.
 *
 * Table layout (three tables, all created with `aws dynamodb create-table`):
 *
 *   shy_l1          PK: scoping_id (S)  SK: submission_id (S)
 *   shy_l2          PK: scoping_id (S)  SK: identity_hash (S)
 *   shy_period_close PK: scoping_id (S)  SK: tx_id (S)
 *
 * The two-list write is not natively atomic in DynamoDB. The adapter uses a
 * TransactWriteItems call (up to 100 operations, single region) to write the
 * L1 and L2 records atomically. TransactWrite has a 25-item limit per call,
 * which is sufficient for a single two-list write.
 *
 * DynamoDB has no native count(*); getCount scans with Select: COUNT. For
 * high-volume scoping IDs, replace with a GSI-backed counter or a separate
 * count item. The interface contract is preserved regardless.
 *
 * Required env vars (all have constructor overrides):
 *   AWS_REGION          — DynamoDB region (default: us-east-1)
 *   DYNAMODB_L1_TABLE   — L1 table name (default: shy_l1)
 *   DYNAMODB_L2_TABLE   — L2 table name (default: shy_l2)
 *   DYNAMODB_PC_TABLE   — period-close table name (default: shy_period_close)
 *
 * Auth: standard AWS credential chain (env vars, instance profile, ECS task role, etc.)
 *
 * Peer dep: @aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb
 */
export class DynamoDBLedgerInterface extends LedgerInterface {
  constructor({
    region   = process.env.AWS_REGION || process.env.CLOUD_REGION || 'us-east-1',
    l1Table  = process.env.DYNAMODB_L1_TABLE  || 'shy_l1',
    l2Table  = process.env.DYNAMODB_L2_TABLE  || 'shy_l2',
    pcTable  = process.env.DYNAMODB_PC_TABLE  || 'shy_period_close',
  } = {}) {
    super();
    this._region  = region;
    this._l1Table = l1Table;
    this._l2Table = l2Table;
    this._pcTable = pcTable;
    this._client  = null;
    this._doc     = null;
  }

  get name() { return 'dynamodb'; }

  async _clients() {
    if (this._doc) return { client: this._client, doc: this._doc };
    const { DynamoDBClient }          = await import('@aws-sdk/client-dynamodb');
    const { DynamoDBDocumentClient }  = await import('@aws-sdk/lib-dynamodb');
    this._client = new DynamoDBClient({ region: this._region });
    this._doc    = DynamoDBDocumentClient.from(this._client);
    return { client: this._client, doc: this._doc };
  }

  _rejectIfJoinable(list1, list2) {
    if ('identityHash' in list1) throw new Error('Rejection predicate: list1 must not contain identityHash');
    if ('submissionId' in list2) throw new Error('Rejection predicate: list2 must not contain submissionId');
  }

  async submitTwoListWrite(scopingId, list1, list2) {
    this._rejectIfJoinable(list1, list2);
    const { TransactWriteCommand } = await import('@aws-sdk/lib-dynamodb');
    const { doc } = await this._clients();
    const txId = randomUUID();
    const now  = new Date().toISOString();

    await doc.send(new TransactWriteCommand({
      TransactItems: [
        {
          Put: {
            TableName: this._l1Table,
            Item: { scoping_id: scopingId, submission_id: list1.submissionId,
                    tx_id: txId, payload_commitment: list1.payloadCommitment,
                    domain_fields: list1, created_at: now },
            ConditionExpression: 'attribute_not_exists(submission_id)',
          },
        },
        {
          Put: {
            TableName: this._l2Table,
            Item: { scoping_id: scopingId, identity_hash: list2.identityHash,
                    tx_id: txId, domain_fields: list2, created_at: now },
            ConditionExpression: 'attribute_not_exists(identity_hash)',
          },
        },
      ],
    }));

    return { txId, ...(await this.getCount(scopingId)) };
  }

  async getCount(scopingId) {
    const { ScanCommand } = await import('@aws-sdk/lib-dynamodb');
    const { doc } = await this._clients();
    const [r1, r2] = await Promise.all([
      doc.send(new ScanCommand({
        TableName: this._l1Table,
        FilterExpression: 'scoping_id = :s',
        ExpressionAttributeValues: { ':s': scopingId },
        Select: 'COUNT',
      })),
      doc.send(new ScanCommand({
        TableName: this._l2Table,
        FilterExpression: 'scoping_id = :s',
        ExpressionAttributeValues: { ':s': scopingId },
        Select: 'COUNT',
      })),
    ]);
    const l1Count = r1.Count ?? 0, l2Count = r2.Count ?? 0;
    return { l1Count, l2Count, countMatch: l1Count === l2Count };
  }

  async rescindTwoListWrite(scopingId, submissionId, identityHash) {
    const { TransactWriteCommand } = await import('@aws-sdk/lib-dynamodb');
    const { doc } = await this._clients();
    await doc.send(new TransactWriteCommand({
      TransactItems: [
        { Delete: { TableName: this._l1Table,
                    Key: { scoping_id: scopingId, submission_id: submissionId } } },
        { Delete: { TableName: this._l2Table,
                    Key: { scoping_id: scopingId, identity_hash: identityHash } } },
      ],
    }));
    return { rescinded: true, ...(await this.getCount(scopingId)) };
  }

  async replaceTwoListWrite(scopingId, oldSubmissionId, newList1, identityHash) {
    this._rejectIfJoinable(newList1, {});
    const { TransactWriteCommand } = await import('@aws-sdk/lib-dynamodb');
    const { doc } = await this._clients();
    const txId = randomUUID();
    const now  = new Date().toISOString();
    await doc.send(new TransactWriteCommand({
      TransactItems: [
        { Delete: { TableName: this._l1Table,
                    Key: { scoping_id: scopingId, submission_id: oldSubmissionId } } },
        { Put: { TableName: this._l1Table,
                 Item: { scoping_id: scopingId, submission_id: newList1.submissionId,
                         tx_id: txId, payload_commitment: newList1.payloadCommitment,
                         domain_fields: newList1, created_at: now },
                 ConditionExpression: 'attribute_not_exists(submission_id)' } },
      ],
    }));
    return { replaced: true, newSubmissionId: newList1.submissionId,
             ...(await this.getCount(scopingId)) };
  }

  async commitPeriodClose(scopingId, l1MerkleRoot, l2MerkleRoot, attestation) {
    const { PutCommand } = await import('@aws-sdk/lib-dynamodb');
    const { doc } = await this._clients();
    const txId = randomUUID();
    const timestamp = new Date().toISOString();
    await doc.send(new PutCommand({
      TableName: this._pcTable,
      Item: { scoping_id: scopingId, tx_id: txId,
              l1_merkle_root: l1MerkleRoot, l2_merkle_root: l2MerkleRoot,
              attestation, created_at: timestamp },
    }));
    return { txId, timestamp };
  }

  async disconnect() {
    if (this._client) { this._client.destroy(); this._client = null; this._doc = null; }
  }
}
