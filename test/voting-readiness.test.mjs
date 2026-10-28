import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { assertVotingManifest, createVotingClient } from '../clients/embodiments/votingClient.js';
import { deriveSubmissionId } from '../protocol/submissionId.js';

function manifest(signing) {
  return {
    contract_version: 'shyvoting-v1',
    anon_layer: { black_box_required: true, required_flows: ['poll_read', 'ballot_build', 'ballot_submit', 'receipt_verify'] },
    identity: { provider: 'didit' },
    signing,
    receipts: { match_store: 'encrypted', double_vote_enforcement: 'scoped' },
    deployment: { default_posture: 'coercion_resistant', runtime_fallbacks: {} },
  };
}

test('unsigned and optionally signed voting retain identity and flow validation', () => {
  for (const signing of [undefined, { required: false, backend: 'none' }, { required: false, backend: 'software' }, { required: true, backend: 'aws_kms' }]) {
    const config = manifest(signing);
    assert.doesNotThrow(() => assertVotingManifest(config));
    assert.throws(() => assertVotingManifest({ ...config, identity: { provider: 'none' } }), /identity provider/);
    assert.throws(() => assertVotingManifest({ ...config, anon_layer: { black_box_required: true, required_flows: [] } }), /missing required voting flow/);
  }
});

test('public derivation and receipt verification agree with canonical raw-byte hashing', async () => {
  const beacon = 'ab'.repeat(32);
  const nonce = Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0')).join('');
  const canonicalId = createHash('sha256').update(Buffer.from(beacon + nonce, 'hex')).digest('hex');
  assert.equal(await deriveSubmissionId(beacon, nonce), canonicalId);
  assert.equal(await deriveSubmissionId(beacon, new Uint8Array(Buffer.from(nonce, 'hex'))), canonicalId);
  const client = createVotingClient({ manifest: manifest({ required: false, backend: 'none' }) });
  const records = [{ submission_id: canonicalId, payload: 'yes' }];
  assert.equal(await client.verifyReceipt(nonce, 'yes', records, { beaconBlockHash: beacon }), true);
  assert.equal(await client.verifyReceipt(nonce, 'no', records, { beaconBlockHash: beacon }), false);
  assert.equal(await client.verifyReceipt(nonce, 'yes', records, { beaconBlockHash: 'cd'.repeat(32) }), false);
  await assert.rejects(client.verifyReceipt(nonce, 'yes', records), /original beacon/);
  await assert.rejects(deriveSubmissionId('zz'.repeat(32), nonce), /hexadecimal/);
});
