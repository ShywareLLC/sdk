/**
 * App-facing web SDK for Shylots, a regulated auctions domain that composes
 * shycustody inventory semantics with shywire settlement rails.
 */

import { createCustodyClient } from "../embodiments/custodyClient.js";
import { createWireClient } from "../embodiments/wireClient.js";

export const LOTS_MANIFEST_CONTRACT_VERSION = "shylots-v1";

const REQUIRED_CUSTODY_FLOWS = [
  "policy_read",
  "lot_record",
  "silo_transfer",
  "redemption_request",
  "redemption_settlement",
  "demurrage_apply"
];

const REQUIRED_WIRE_FLOWS = ["wire_issue", "wire_transfer", "wire_redeem"];

function requiredFlowSet(shyconfig) {
  return new Set(shyconfig?.anon_layer?.required_flows ?? []);
}

function assertFlows(shyconfig, flows, label) {
  const activeFlows = requiredFlowSet(shyconfig);
  for (const flow of flows) {
    if (!activeFlows.has(flow)) {
      throw new Error(`shyconfig is missing required ${label} flow: ${flow}`);
    }
  }
}

function normalizeLot(lot, lotsProfile) {
  if (!lot || typeof lot !== "object") return lot;
  return {
    ...lot,
    settlement_asset_id: lotsProfile.settlementAssetId,
    evidence_mode: lotsProfile.evidenceMode,
    bid_visibility: lotsProfile.bidVisibility,
    open_mode: lotsProfile.openMode
  };
}

function filterLots(records, filters = {}) {
  const entries = Array.isArray(records) ? records : [];
  return entries.filter((lot) => {
    if (filters.assetId && lot.asset_id !== filters.assetId) return false;
    if (filters.operatorId && lot.operator_id !== filters.operatorId)
      return false;
    if (filters.warehouseId && lot.warehouse_id !== filters.warehouseId)
      return false;
    if (filters.skuClassId && lot.sku_class_id !== filters.skuClassId)
      return false;
    if (filters.status && lot.status !== filters.status) return false;
    return true;
  });
}

function buildLotsProfile(manifest) {
  const lots = manifest?.lots ?? {};
  return {
    marketOperator: lots.market_operator ?? null,
    saleModes: lots.sale_modes ?? ["sealed_bid"],
    openMode: lots.open_mode ?? "operator_attested_close",
    bidVisibility: lots.bid_visibility ?? "sealed_until_close",
    reserveFundingMode: lots.reserve_funding_mode ?? "bid_bond_transfer",
    settlementAssetId:
      lots.settlement_asset_id ?? manifest?.wire?.asset_id ?? null,
    bidderIdentityMode: lots.bidder_identity_mode ?? "anonymous_commitment",
    evidenceMode: lots.evidence_mode ?? "custody_refs",
    redemptionSurface: lots.redemption_surface ?? "custody_request",
    disputeWindowHours: Number(lots.dispute_window_hours ?? 0)
  };
}

export function assertLotsManifest(shyconfig) {
  if (shyconfig?.contract_version !== LOTS_MANIFEST_CONTRACT_VERSION) {
    throw new Error(
      `shyconfig must declare contract_version=${LOTS_MANIFEST_CONTRACT_VERSION} for shylots apps.`
    );
  }

  if (shyconfig?.app?.product_type !== "shylots") {
    throw new Error("shyconfig product_type must be shylots for shylots apps.");
  }

  if (!shyconfig?.domains?.private?.console) {
    throw new Error(
      "shyconfig must declare a private console domain for shylots apps."
    );
  }

  if (!shyconfig?.anon_layer?.black_box_required) {
    throw new Error(
      "shyconfig must require the anonymous layer as a black box."
    );
  }

  if (!shyconfig?.custody) {
    throw new Error(
      "shyconfig must declare custody settings for shylots apps."
    );
  }

  if (!shyconfig?.wire) {
    throw new Error("shyconfig must declare wire settings for shylots apps.");
  }

  if (!shyconfig?.lots) {
    throw new Error("shyconfig must declare lots settings for shylots apps.");
  }

  if (shyconfig.custody.transfer_layer && shyconfig.custody.transfer_layer !== "shywire") {
    throw new Error('shylots custody.transfer_layer must be "shywire" when declared. Omit it to use your own settlement rail.');
  }

  assertFlows(shyconfig, REQUIRED_CUSTODY_FLOWS, "shylots custody");
  assertFlows(shyconfig, REQUIRED_WIRE_FLOWS, "shylots settlement");
}

export function createLotsClient({
  defaultBase = "/api",
  defaultSubmitBase = null,
  storageKey = "shyware_lots_api_base",
  fetchImpl = globalThis.fetch?.bind(globalThis),
  getAuthHeaders = null,
  manifest = null,
  operatorMode = false
} = {}) {
  if (!fetchImpl) {
    throw new Error("fetch is required by the shylots client.");
  }

  const custodyClient = createCustodyClient({
    defaultBase,
    defaultSubmitBase,
    storageKey,
    fetchImpl,
    getAuthHeaders,
    manifest,
    operatorMode
  });

  const wireClient = createWireClient({
    defaultBase,
    defaultSubmitBase,
    storageKey,
    fetchImpl,
    getAuthHeaders,
    manifest,
    operatorMode
  });

  const lotsProfile = buildLotsProfile(manifest);

  function getBase() {
    return custodyClient.getBase();
  }

  function setBase(url) {
    custodyClient.setBase(url);
    wireClient.setBase(url);
  }

  function getSubmitBase() {
    return wireClient.getSubmitBase();
  }

  return {
    initialize() {
      return {
        contractVersion: manifest?.contract_version ?? null,
        appId: manifest?.app?.id ?? null,
        appName: manifest?.app?.name ?? null,
        chainId: manifest?.app?.chain_id ?? null,
        apiBase: getBase(),
        submitBase: getSubmitBase(),
        domains: manifest?.domains ?? null,
        identity: manifest?.identity ?? null,
        deployment: manifest?.deployment ?? null,
        lotsProfile,
        inventoryLayer: {
          contractVersion: LOTS_MANIFEST_CONTRACT_VERSION,
          assetId: manifest?.custody?.asset_id ?? null,
          transferLayer: manifest?.custody?.transfer_layer ?? null,
          evidenceRequirements: manifest?.custody?.evidence_requirements ?? []
        },
        settlementLayer: {
          transferRail: manifest?.custody?.transfer_layer ?? null,
          assetId: lotsProfile.settlementAssetId,
          providerProfile: wireClient.getProviderProfile()
        }
      };
    },
    getBase,
    setBase,
    getSubmitBase,
    getManifest: () => manifest,

    getLotsProfile: () => lotsProfile,
    getInventoryClient: () => custodyClient,
    getSettlementClient: () => wireClient,
    createWalletProof(args) {
      return wireClient.createWalletProof(args);
    },
    createIdentityCommitment(input, options = {}) {
      return wireClient.createIdentityCommitment(input, options);
    },
    createIdentityProofHash(input, options = {}) {
      return wireClient.createIdentityProofHash(input, options);
    },
    getCurrentPolicy: () => custodyClient.getCurrentPolicy(),
    listPolicies: () => custodyClient.listPolicies(),
    getPolicy: (policyId) => custodyClient.getPolicy(policyId),
    listOperators: () => custodyClient.listOperators(),
    getOperator: (operatorId) => custodyClient.getOperator(operatorId),
    listSkuClasses: () => custodyClient.listSkuClasses(),
    getSkuClass: (skuClassId) => custodyClient.getSkuClass(skuClassId),
    listMarketplaceLots: async (filters = {}) => {
      const records = await custodyClient.listLots();
      return filterLots(records, filters).map((lot) =>
        normalizeLot(lot, lotsProfile)
      );
    },
    getMarketplaceLot: async (lotId) => {
      const lot = await custodyClient.getLot(lotId);
      return normalizeLot(lot, lotsProfile);
    },
    getSettlementAsset: () =>
      wireClient.getAsset(lotsProfile.settlementAssetId),
    getSettlementSupply: () =>
      wireClient.getSupply(lotsProfile.settlementAssetId),
    getSettlementBalance: (accountCommitment) =>
      wireClient.getBalance(lotsProfile.settlementAssetId, accountCommitment),
    buildRegisterBidderAccount: (args) => wireClient.buildRegisterAccount(args),
    submitRegisterBidderAccount: (txJson) =>
      wireClient.submitRegisterAccount(txJson),
    registerBidderAccount: (args) => wireClient.registerAccount(args),
    async buildBidBondTransfer({
      assetId = lotsProfile.settlementAssetId,
      senderCommitment,
      recipientCommitment,
      amount,
      timestamp
    }) {
      return wireClient.buildWire({
        assetId,
        senderCommitment,
        recipientCommitment,
        amount,
        timestamp
      });
    },
    submitBidBondTransfer: (txJson) => wireClient.submitWire(txJson),
    async transferBidBond(args) {
      return wireClient.wireSubmission({
        assetId: args.assetId ?? lotsProfile.settlementAssetId,
        ...args
      });
    },
    async buildAwardSettlementTransfer({
      assetId = lotsProfile.settlementAssetId,
      senderCommitment,
      recipientCommitment,
      amount,
      timestamp
    }) {
      return wireClient.buildWire({
        assetId,
        senderCommitment,
        recipientCommitment,
        amount,
        timestamp
      });
    },
    submitAwardSettlementTransfer: (txJson) =>
      wireClient.submitWire(txJson),
    async settleAwardTransfer(args) {
      return wireClient.wireSubmission({
        assetId: args.assetId ?? lotsProfile.settlementAssetId,
        ...args
      });
    },
    createFundingIntent: (args, options = {}) =>
      wireClient.createIssueIntent(args, options),
    createPayoutIntent: (args, options = {}) =>
      wireClient.createRedeemIntent(args, options),
    async buildLotRedemptionRequest({
      assetId = manifest?.custody?.asset_id,
      accountCommitment,
      warehouseId,
      skuClassId,
      siloAmount,
      requestedQuantity,
      destinationRef,
      requestId
    }) {
      return custodyClient.buildRequestRedemption({
        requestId,
        assetId,
        accountCommitment,
        warehouseId,
        skuClassId,
        siloAmount,
        requestedQuantity,
        destinationRef
      });
    },
    async requestLotRedemption(args) {
      return custodyClient.requestRedemption({
        assetId: args.assetId ?? manifest?.custody?.asset_id,
        ...args
      });
    }
  };
}

export function initializeFromShyConfig(shyconfig, options = {}) {
  assertLotsManifest(shyconfig);

  if (
    shyconfig.api?.requires_auth &&
    typeof options.getAuthHeaders !== "function"
  ) {
    throw new Error(
      "shyconfig requires authenticated Shylots API access, but no auth header provider was supplied."
    );
  }

  return createLotsClient({
    defaultBase: shyconfig.api?.base_url ?? "/api",
    defaultSubmitBase: shyconfig.api?.submit_base_url ?? null,
    storageKey:
      shyconfig.api?.storage_key ??
      options.storageKey ??
      "shyware_lots_api_base",
    fetchImpl: options.fetchImpl,
    getAuthHeaders: options.getAuthHeaders,
    manifest: shyconfig,
    operatorMode: Boolean(options.operatorMode)
  });
}
