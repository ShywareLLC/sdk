import test from 'node:test';
import assert from 'node:assert/strict';
import { assertWireManifest } from '../clients/embodiments/wireClient.js';
import { assertSharesManifest } from '../clients/embodiments/sharesClient.js';
import { assertContractsManifest } from '../clients/embodiments/contractsClient.js';
import { assertCustodyManifest } from '../clients/embodiments/custodyClient.js';
import { assertBetsManifest } from '../clients/composites/betsClient.js';
import { assertStreamManifest } from '../clients/utilities/streamClient.js';
import { assertHopManifest } from '../clients/utilities/hopClient.js';
import { assertUtilityManifest } from '../clients/utilities/utilityClient.js';

const flows = [
  'wire_issue', 'wire_transfer', 'wire_redeem',
  'contract_register', 'contract_activate', 'contract_execute',
  'organization_read', 'membership_snapshot_read', 'proposal_create', 'weighted_ballot_submit', 'tally_read', 'action_queue_read', 'action_dispatch',
  'policy_read', 'lot_record', 'silo_transfer', 'redemption_request', 'redemption_settlement', 'demurrage_apply',
  'cam_attest_store', 'cam_attest_reveal', 'stream_event', 'stream_clip', 'stream_read', 'biometric_rederive',
  'hop_route_store', 'hop_route_reveal', 'event_create', 'order_place', 'order_book_read', 'settlement_read', 'settlement_finalize', 'reconcile_request',
];

for (const [product, validate] of [
  ['shywire', assertWireManifest], ['shyshares', assertSharesManifest],
  ['shycontracts', assertContractsManifest], ['shycustody', assertCustodyManifest],
  ['shybets', assertBetsManifest], ['shystream', assertStreamManifest],
  ['shyhop', assertHopManifest], ['shyhop', assertUtilityManifest],
]) {
  test(`${validate.name} accepts unsigned operation and retains structural validation`, () => {
    const config = {
      contract_version: `${product}-v1`, app: { id: 'unsigned-test', product_type: product },
      anon_layer: { black_box_required: true, required_flows: flows },
      identity: { provider: 'didit' }, wire: {}, custody: {}, contracts: {},
      governance: {}, execution: {}, store: {}, stream: { provider: 'test' },
      domains: { private: { console: 'https://example.test' } },
      signing: { required: false, backend: 'none' },
    };
    validate(config);
    validate({ ...config, signing: { required: false, backend: 'software' } });
    validate({ ...config, signing: undefined });
    assert.throws(() => validate({ ...config, anon_layer: { ...config.anon_layer, black_box_required: false } }));
  });
}
