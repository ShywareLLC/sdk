// AlgorandLedgerInterface end-to-end-shaped test.
//
// A real Algorand LocalNet (AlgoKit / classic sandbox) requires Docker,
// which is not available in this environment (no `docker` binary, no
// daemon). This test therefore runs the adapter against `FakeAlgod`
// (./fakeAlgod.js), a hand-written stand-in for algod's REST surface that
// re-derives the same box-storage state machine the compiled
// shyware_two_list.py contract implements. Real algosdk is used
// throughout -- real transaction building, real ABI argument encoding,
// real ABI return-value decoding, real AtomicTransactionComposer grouping
// -- only the network round-trip is faked. This proves the adapter is
// wired correctly (box-key derivation, method dispatch, argument order,
// atomic grouping, return decoding, error propagation) but does NOT
// prove the compiled TEAL itself behaves this way on a real validating
// node; that requires the LocalNet run described in the task report.
//
// See adapters/ledger/algorand/contracts/shyware_two_list.py for the
// PyTeal source these five methods and four checks are modeled on.

import { describe, it, expect, beforeEach } from 'vitest';
import { createHash, randomUUID } from 'crypto';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { AlgorandLedgerInterface } from '../../../adapters/ledger/algorand.js';
import { FakeAlgod } from './fakeAlgod.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ABI_SPEC_PATH = join(__dirname, '..', '..', '..', 'adapters', 'ledger', 'algorand', 'contracts', 'shyware_two_list.arc4.json');
const APP_ID = 1001;

async function makeLedger() {
  const algosdk = await import('algosdk');
  const spec = JSON.parse(readFileSync(ABI_SPEC_PATH, 'utf8'));
  const contract = new algosdk.ABIContract(spec);
  const account = algosdk.generateAccount();
  const fakeAlgod = new FakeAlgod({ algosdk, contract });
  const ledger = new AlgorandLedgerInterface({
    appId: APP_ID,
    account,
    algodClient: fakeAlgod,
    boxFundingMicroAlgos: 0, // fake algod does not model MBR; keep groups to a single txn
    waitRounds: 4,
  });
  return { ledger, fakeAlgod };
}

function identityHashFor(uid, scopingId) {
  return createHash('sha256').update(`${uid}|${scopingId}`, 'utf8').digest('hex');
}

describe('AlgorandLedgerInterface', () => {
  let ledger;

  beforeEach(async () => {
    ({ ledger } = await makeLedger());
  });

  it('reports its name', () => {
    expect(ledger.name).toBe('algorand');
  });

  it('rejects construction without ALGORAND_APP_ID', () => {
    expect(() => new AlgorandLedgerInterface({ mnemonic: 'x' })).toThrow(/ALGORAND_APP_ID/);
  });

  it('rejects construction without a mnemonic or account override', () => {
    expect(() => new AlgorandLedgerInterface({ appId: 1 })).toThrow(/ALGORAND_ACCOUNT_MNEMONIC/);
  });

  it('submits a two-list write and returns count-match', async () => {
    const scopingId = `poll-${randomUUID()}`;
    const submissionId = randomUUID();
    const identityHash = identityHashFor('voter-1', scopingId);

    const result = await ledger.submitTwoListWrite(
      scopingId,
      { submissionId, payloadCommitment: 'commit:yes' },
      { identityHash }
    );

    expect(result.txId).toBeTypeOf('string');
    expect(result.l1Count).toBe(1);
    expect(result.l2Count).toBe(1);
    expect(result.countMatch).toBe(true);
  });

  it('getCount reflects a write without submitting a transaction', async () => {
    const scopingId = `poll-${randomUUID()}`;
    const submissionId = randomUUID();
    const identityHash = identityHashFor('voter-2', scopingId);

    expect(await ledger.getCount(scopingId)).toEqual({ l1Count: 0, l2Count: 0, countMatch: true });

    await ledger.submitTwoListWrite(scopingId, { submissionId, payloadCommitment: 'commit:yes' }, { identityHash });

    expect(await ledger.getCount(scopingId)).toEqual({ l1Count: 1, l2Count: 1, countMatch: true });
  });

  it('rejects a second submit with the same submissionId (replay protection)', async () => {
    const scopingId = `poll-${randomUUID()}`;
    const submissionId = randomUUID();

    await ledger.submitTwoListWrite(
      scopingId,
      { submissionId, payloadCommitment: 'commit:yes' },
      { identityHash: identityHashFor('voter-3', scopingId) }
    );

    await expect(
      ledger.submitTwoListWrite(
        scopingId,
        { submissionId, payloadCommitment: 'commit:no' },
        { identityHash: identityHashFor('voter-4', scopingId) }
      )
    ).rejects.toThrow(/replay protection/);

    // rejected transaction must not have moved the count
    expect(await ledger.getCount(scopingId)).toEqual({ l1Count: 1, l2Count: 1, countMatch: true });
  });

  it('rejects a second submit with the same identityHash under the same scopingId (sybil resistance)', async () => {
    const scopingId = `poll-${randomUUID()}`;
    const identityHash = identityHashFor('voter-5', scopingId);

    await ledger.submitTwoListWrite(
      scopingId,
      { submissionId: randomUUID(), payloadCommitment: 'commit:yes' },
      { identityHash }
    );

    await expect(
      ledger.submitTwoListWrite(
        scopingId,
        { submissionId: randomUUID(), payloadCommitment: 'commit:no' },
        { identityHash }
      )
    ).rejects.toThrow(/sybil resistance/);

    expect(await ledger.getCount(scopingId)).toEqual({ l1Count: 1, l2Count: 1, countMatch: true });
  });

  it('client-side rejection predicate throws before any transaction is built', async () => {
    const scopingId = `poll-${randomUUID()}`;
    const submissionId = 'sub-x';
    const identityHash = createHash('sha256').update(submissionId, 'utf8').digest('hex'); // = sha256(submissionId)

    await expect(
      ledger.submitTwoListWrite(scopingId, { submissionId, payloadCommitment: 'c' }, { identityHash })
    ).rejects.toThrow(/Rejection predicate/);
  });

  it('rescindTwoListWrite deletes both records and decrements the count', async () => {
    const scopingId = `poll-${randomUUID()}`;
    const submissionId = randomUUID();
    const identityHash = identityHashFor('voter-6', scopingId);

    await ledger.submitTwoListWrite(scopingId, { submissionId, payloadCommitment: 'commit:yes' }, { identityHash });
    expect(await ledger.getCount(scopingId)).toEqual({ l1Count: 1, l2Count: 1, countMatch: true });

    const rescindResult = await ledger.rescindTwoListWrite(scopingId, submissionId, identityHash);
    expect(rescindResult).toEqual({ countMatch: true, rescinded: true });

    expect(await ledger.getCount(scopingId)).toEqual({ l1Count: 0, l2Count: 0, countMatch: true });

    // the submissionId is free again after rescission
    await expect(
      ledger.submitTwoListWrite(scopingId, { submissionId, payloadCommitment: 'commit:no' }, { identityHash })
    ).resolves.toMatchObject({ l1Count: 1, l2Count: 1, countMatch: true });
  });

  it('replaceTwoListWrite swaps the L1 payload and leaves the count untouched', async () => {
    const scopingId = `poll-${randomUUID()}`;
    const oldSubmissionId = randomUUID();
    const newSubmissionId = randomUUID();
    const identityHash = identityHashFor('voter-7', scopingId);

    await ledger.submitTwoListWrite(scopingId, { submissionId: oldSubmissionId, payloadCommitment: 'commit:yes' }, { identityHash });

    const replaceResult = await ledger.replaceTwoListWrite(
      scopingId,
      oldSubmissionId,
      { submissionId: newSubmissionId, payloadCommitment: 'commit:no' },
      identityHash
    );

    expect(replaceResult).toEqual({ countMatch: true, replaced: true, newSubmissionId });
    expect(await ledger.getCount(scopingId)).toEqual({ l1Count: 1, l2Count: 1, countMatch: true });
  });

  it('commitPeriodClose writes once and rejects a second close for the same scopingId', async () => {
    const scopingId = `poll-${randomUUID()}`;
    const l1Root = 'a'.repeat(32);
    const l2Root = 'b'.repeat(32);

    const result = await ledger.commitPeriodClose(scopingId, l1Root, l2Root, 'sig:abc');
    expect(result.txId).toBeTypeOf('string');
    expect(() => new Date(result.timestamp).toISOString()).not.toThrow();

    await expect(ledger.commitPeriodClose(scopingId, l1Root, l2Root, 'sig:def')).rejects.toThrow(/already closed/);
  });
});
