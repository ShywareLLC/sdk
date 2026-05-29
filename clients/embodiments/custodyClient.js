// Sealer stub: This embodiment does not currently require PII/high-risk payload sealing.
// To enable, gate all PII/high-risk payloads with manifest.sealer and use shared sealer logic from shywareSealer.js.
/**
 * App-facing web SDK for the shyware custody layer.
 *
 * Apps should treat this client as the only entrypoint into custody flows:
 * policy reads, lot recording, silo mint/burn/transfer, redemption, and
 * demurrage all flow through this module.
 */

import { createIdentityResolver } from "../../protocol/identity/identityClient.js";
import { createWalletProofBase64 } from "../../protocol/walletProof.js";
import {
  applyStoreAnonLayerDefaults,
  assertStoreBackedAnonLayer
} from "../../protocol/anonLayer.js";

export const CUSTODY_MANIFEST_CONTRACT_VERSION = "shycustody-v1";

const REQUIRED_CUSTODY_FLOWS = [
  "policy_read",
  "lot_record",
  "silo_transfer",
  "redemption_request",
  "redemption_settlement",
  "demurrage_apply"
];

const REQUIRED_CAM_FLOWS = ["cam_attest_store", "cam_attest_reveal"];

const REQUIRED_STREAM_FLOWS = ["stream_event", "stream_clip", "stream_read"];

function requiredWebCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error(
      "Web Crypto API is required by the shyware custody client."
    );
  }
  return globalThis.crypto;
}

function normalizeBase(base) {
  if (base == null || base === "") return "";
  return String(base).endsWith("/") ? String(base).slice(0, -1) : String(base);
}

function joinBaseAndPath(base, path) {
  return `${normalizeBase(base)}${path}`;
}

function nowUnix() {
  return Math.floor(Date.now() / 1000);
}

function randomHex(bytes = 32) {
  const arr = requiredWebCrypto().getRandomValues(new Uint8Array(bytes));
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256hex(value) {
  const payload = typeof value === "string" ? value : JSON.stringify(value);
  const bytes = new TextEncoder().encode(payload);
  const digest = await requiredWebCrypto().subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function buildEnvelope(type, data) {
  const tx = {
    type,
    signature: "AQ==",
    data
  };

  return {
    txJson: JSON.stringify(tx),
    type,
    data
  };
}

function assertOperatorMode(operatorMode, action) {
  if (!operatorMode) {
    throw new Error(`${action} requires operator authority.`);
  }
}

export function assertCustodyManifest(shyconfig) {
  applyStoreAnonLayerDefaults(shyconfig);

  if (shyconfig?.contract_version !== CUSTODY_MANIFEST_CONTRACT_VERSION) {
    throw new Error(
      `shyconfig must declare contract_version=${CUSTODY_MANIFEST_CONTRACT_VERSION} for shycustody apps.`
    );
  }

  if (shyconfig?.app?.product_type !== "shycustody") {
    throw new Error(
      "shyconfig product_type must be shycustody for shycustody apps."
    );
  }

  if (!shyconfig?.anon_layer?.black_box_required) {
    throw new Error(
      "shyconfig must require the anonymous layer as a black box."
    );
  }

  if (!shyconfig.signing?.required || shyconfig.signing.backend === "none") {
    throw new Error(
      "shyconfig must require protocol signing for shycustody apps."
    );
  }

  if (!shyconfig.custody) {
    throw new Error(
      "shyconfig must declare custody settings for shycustody apps."
    );
  }

  if (shyconfig.custody.transfer_layer && shyconfig.custody.transfer_layer !== "shywire") {
    throw new Error(
      'shyconfig custody.transfer_layer must be "shywire" when declared. Omit it to use your own transfer rail.'
    );
  }

  if (!shyconfig?.store) {
    throw new Error(
      "shycustody requires a store block for shycam/shystream sealed evidence handling."
    );
  }

  if (!shyconfig?.stream) {
    throw new Error(
      "shycustody requires a stream block for shystream media/event handling."
    );
  }

  assertStoreBackedAnonLayer(shyconfig, "shycustody");

  const requiredFlows = new Set(shyconfig.anon_layer.required_flows ?? []);
  for (const flow of REQUIRED_CUSTODY_FLOWS) {
    if (!requiredFlows.has(flow)) {
      throw new Error(`shyconfig is missing required shycustody flow: ${flow}`);
    }
  }

  for (const flow of REQUIRED_CAM_FLOWS) {
    if (!requiredFlows.has(flow)) {
      throw new Error(
        `shyconfig is missing required shycustody shycam flow: ${flow}`
      );
    }
  }

  for (const flow of REQUIRED_STREAM_FLOWS) {
    if (!requiredFlows.has(flow)) {
      throw new Error(
        `shyconfig is missing required shycustody shystream flow: ${flow}`
      );
    }
  }
}

export function createCustodyClient({
  defaultBase = "/api",
  defaultSubmitBase = null,
  storageKey = "shyware_custody_api_base",
  fetchImpl = globalThis.fetch?.bind(globalThis),
  getAuthHeaders = null,
  manifest = null,
  operatorMode = false
} = {}) {
  if (!fetchImpl) {
    throw new Error("fetch is required by the shyware custody client.");
  }

  const identityResolver = createIdentityResolver(manifest);

  function getBase() {
    if (typeof localStorage === "undefined") return defaultBase;
    return localStorage.getItem(storageKey) || defaultBase;
  }

  function setBase(url) {
    if (typeof localStorage === "undefined") return;
    if (!url) {
      localStorage.removeItem(storageKey);
      return;
    }
    localStorage.setItem(storageKey, url);
  }

  function getSubmitBase() {
    return defaultSubmitBase == null ? getBase() : defaultSubmitBase;
  }

  async function resolveHeaders(extraHeaders = {}) {
    if (!getAuthHeaders) return extraHeaders;
    const authHeaders = await getAuthHeaders();
    return {
      ...authHeaders,
      ...extraHeaders
    };
  }

  async function get(path) {
    let res;
    try {
      res = await fetchImpl(joinBaseAndPath(getBase(), path), {
        headers: await resolveHeaders()
      });
    } catch {
      throw new Error(
        "API not reachable - check Settings or your network connection."
      );
    }
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error ?? `HTTP ${res.status}`);
    }
    return res.json();
  }

  async function post(path, body) {
    let res;
    try {
      res = await fetchImpl(joinBaseAndPath(getSubmitBase(), path), {
        method: "POST",
        headers: await resolveHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(body)
      });
    } catch {
      throw new Error(
        "API not reachable - check Settings or your network connection."
      );
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error ?? `HTTP ${res.status}`);
    }
    return res.json();
  }

  return {
    initialize() {
      return {
        contractVersion: manifest?.contract_version ?? null,
        appId: manifest?.app?.id ?? null,
        chainId: manifest?.app?.chain_id ?? null,
        apiBase: getBase(),
        submitBase: getSubmitBase(),
        identity: manifest?.identity ?? null,
        identityProfile: identityResolver.profile,
        signing: manifest?.signing ?? null,
        deployment: manifest?.deployment ?? null,
        custody: manifest?.custody ?? null,
        operatorAuthority: {
          operatorMode,
          operatorMintBurn: manifest?.custody?.operator_mint_burn ?? false
        }
      };
    },
    getBase,
    setBase,
    getSubmitBase,
    getManifest: () => manifest,

    createWalletProof(args) {
      return createWalletProofBase64(args);
    },
    isOperatorMode: () => operatorMode,
    createIdentityCommitment(input, options = {}) {
      return identityResolver.createCommitment(input, options);
    },
    createIdentityProofHash(input, options = {}) {
      return identityResolver.createProofHash(input, options);
    },
    getCurrentPolicy: () => get("/custody/policies/current"),
    listPolicies: () => get("/custody/policies"),
    getPolicy: (policyId) => get(`/custody/policies/${policyId}`),
    listOperators: () => get("/custody/operators"),
    getOperator: (operatorId) => get(`/custody/operators/${operatorId}`),
    listSkuClasses: () => get("/custody/skus"),
    getSkuClass: (skuClassId) => get(`/custody/skus/${skuClassId}`),
    listLots: () => get("/custody/lots"),
    getLot: (lotId) => get(`/custody/lots/${lotId}`),
    listRedemptions: () => get("/custody/redemptions"),
    getRedemption: (requestId) => get(`/custody/redemptions/${requestId}`),
    listSettlements: () => get("/custody/settlements"),
    getSettlement: (settlementId) =>
      get(`/custody/settlements/${settlementId}`),
    listDemurrage: () => get("/custody/demurrage"),
    getDemurrageAssessment: (assessmentId) =>
      get(`/custody/demurrage/${assessmentId}`),
    getAsset: (assetId) => get(`/assets/${assetId}`),
    getSupply: (assetId) => get(`/supply/${assetId}`),
    getBalance: (assetId, accountCommitment) =>
      get(`/balance/${assetId}/${accountCommitment}`),
    async buildRegisterAsset({ assetId, name, decimals = 2 }) {
      return buildEnvelope(1, {
        asset_id: assetId,
        name,
        decimals: Number(decimals)
      });
    },
    submitRegisterAsset(txJson) {
      assertOperatorMode(operatorMode, "registerAsset");
      return post("/assets", { tx: txJson });
    },
    async registerAsset(args) {
      assertOperatorMode(operatorMode, "registerAsset");
      const envelope = await this.buildRegisterAsset(args);
      await this.submitRegisterAsset(envelope.txJson);
      return envelope;
    },
    async buildRegisterAccount({
      walletAddress = "",
      identityInput = null,
      accountCommitment = null,
      walletProofBase64 = "",
      enrollmentToken = "",
      enrollmentProofBase64 = ""
    }) {
      const resolvedWalletAddress =
        walletAddress ||
        (typeof identityInput === "string" ? identityInput.trim() : "");
      const commitment =
        accountCommitment ??
        (await identityResolver.createCommitment(
          identityInput ?? resolvedWalletAddress,
          {
            namespace: "account"
          }
        ));
      const resolvedWalletProofBase64 =
        walletProofBase64 ||
        (resolvedWalletAddress
          ? await createWalletProofBase64({
              accountCommitment: commitment,
              walletAddress: resolvedWalletAddress,
            })
          : "");
      if (!resolvedWalletProofBase64) {
        throw new Error(
          "walletProofBase64 is required for account registration."
        );
      }
      return {
        ...(await buildEnvelope(5, {
          account_commitment: commitment,
          wallet_proof: resolvedWalletProofBase64,
          enrollment_token: enrollmentToken,
          enrollment_proof: enrollmentProofBase64
        })),
        accountCommitment: commitment
      };
    },
    submitRegisterAccount: (txJson) => post("/accounts", { tx: txJson }),
    async registerAccount(args) {
      const envelope = await this.buildRegisterAccount(args);
      await this.submitRegisterAccount(envelope.txJson);
      return envelope;
    },
    async buildMintSilo({
      assetId,
      accountCommitment,
      amount,
      timestamp = nowUnix()
    }) {
      return buildEnvelope(2, {
        asset_id: assetId,
        account_commitment: accountCommitment,
        amount: Number(amount),
        timestamp
      });
    },
    submitMintSilo(txJson) {
      assertOperatorMode(operatorMode, "mintSilo");
      return post("/mint", { tx: txJson });
    },
    async mintSilo(args) {
      assertOperatorMode(operatorMode, "mintSilo");
      const envelope = await this.buildMintSilo(args);
      await this.submitMintSilo(envelope.txJson);
      return envelope;
    },
    async buildTransferSilo({
      assetId,
      senderCommitment,
      recipientCommitment,
      amount,
      timestamp = nowUnix()
    }) {
      const transferNonce = randomHex(32);
      const nullifier = await sha256hex(
        `${senderCommitment}:${assetId}:${transferNonce}`
      );
      const transferId = await sha256hex(transferNonce);
      return {
        ...(await buildEnvelope(4, {
          asset_id: assetId,
          sender_commitment: senderCommitment,
          recipient_commitment: recipientCommitment,
          amount: Number(amount),
          nullifier,
          transfer_nonce: transferNonce,
          sender_proof: "AQ==",
          timestamp
        })),
        transferId,
        nullifier
      };
    },
    submitTransferSilo: (txJson) => post("/transfers", { tx: txJson }),
    async transferSilo(args) {
      const envelope = await this.buildTransferSilo(args);
      await this.submitTransferSilo(envelope.txJson);
      return envelope;
    },
    async buildRegisterWarehouseOperator({
      operatorId,
      name,
      warehouseId,
      region = "",
      videoStreamRef = "",
      status = "active",
      timestamp = nowUnix()
    }) {
      return buildEnvelope(11, {
        operator_id: operatorId,
        name,
        warehouse_id: warehouseId,
        region,
        video_stream_ref: videoStreamRef,
        status,
        timestamp
      });
    },
    submitRegisterWarehouseOperator(txJson) {
      assertOperatorMode(operatorMode, "registerWarehouseOperator");
      return post("/custody/operators", { tx: txJson });
    },
    async registerWarehouseOperator(args) {
      assertOperatorMode(operatorMode, "registerWarehouseOperator");
      const envelope = await this.buildRegisterWarehouseOperator(args);
      await this.submitRegisterWarehouseOperator(envelope.txJson);
      return envelope;
    },
    async buildRegisterAcceptedSkuClass({
      skuClassId,
      name,
      gradeBand,
      unitOfMeasure,
      normalizedFactorBps,
      storageClass = "standard",
      status = "active",
      timestamp = nowUnix()
    }) {
      return buildEnvelope(12, {
        sku_class_id: skuClassId,
        name,
        grade_band: gradeBand,
        unit_of_measure: unitOfMeasure,
        normalized_factor_bps: Number(normalizedFactorBps),
        storage_class: storageClass,
        status,
        timestamp
      });
    },
    submitRegisterAcceptedSkuClass(txJson) {
      assertOperatorMode(operatorMode, "registerAcceptedSkuClass");
      return post("/custody/skus", { tx: txJson });
    },
    async registerAcceptedSkuClass(args) {
      assertOperatorMode(operatorMode, "registerAcceptedSkuClass");
      const envelope = await this.buildRegisterAcceptedSkuClass(args);
      await this.submitRegisterAcceptedSkuClass(envelope.txJson);
      return envelope;
    },
    async buildRegisterConsortiumPolicy({
      policyId,
      assetId,
      name,
      activeOperatorIds,
      acceptedSkuClassIds,
      unitOfMeasure,
      quantityNormalization,
      shippingAdjustmentRef = "",
      demurrageRateBps = 0,
      operatorFeeBps = 0,
      redemptionMode,
      redemptionRouting,
      evidenceRequirements = [],
      timestamp = nowUnix()
    }) {
      return buildEnvelope(10, {
        policy_id: policyId,
        asset_id: assetId,
        name,
        active_operator_ids: activeOperatorIds,
        accepted_sku_class_ids: acceptedSkuClassIds,
        unit_of_measure: unitOfMeasure,
        quantity_normalization: quantityNormalization,
        shipping_adjustment_ref: shippingAdjustmentRef,
        demurrage_rate_bps: Number(demurrageRateBps),
        operator_fee_bps: Number(operatorFeeBps),
        redemption_mode: redemptionMode,
        redemption_routing: redemptionRouting,
        evidence_requirements: evidenceRequirements,
        timestamp
      });
    },
    submitRegisterConsortiumPolicy(txJson) {
      assertOperatorMode(operatorMode, "registerConsortiumPolicy");
      return post("/custody/policies", { tx: txJson });
    },
    async registerConsortiumPolicy(args) {
      assertOperatorMode(operatorMode, "registerConsortiumPolicy");
      const envelope = await this.buildRegisterConsortiumPolicy(args);
      await this.submitRegisterConsortiumPolicy(envelope.txJson);
      return envelope;
    },
    async buildRecordIntakeLot({
      lotId,
      policyId,
      assetId,
      operatorId,
      warehouseId,
      accountCommitment,
      skuClassId,
      quantity,
      mintedAmount,
      operatorFeeAmount = 0,
      shippingCostAmount = 0,
      storageReserveAmount = 0,
      videoSessionRef,
      evidenceRefs,
      timestamp = nowUnix()
    }) {
      return buildEnvelope(13, {
        lot_id: lotId,
        policy_id: policyId,
        asset_id: assetId,
        operator_id: operatorId,
        warehouse_id: warehouseId,
        account_commitment: accountCommitment,
        sku_class_id: skuClassId,
        quantity: Number(quantity),
        minted_amount: Number(mintedAmount),
        operator_fee_amount: Number(operatorFeeAmount),
        shipping_cost_amount: Number(shippingCostAmount),
        storage_reserve_amount: Number(storageReserveAmount),
        video_session_ref: videoSessionRef,
        evidence_refs: evidenceRefs,
        timestamp
      });
    },
    submitRecordIntakeLot(txJson) {
      assertOperatorMode(operatorMode, "recordIntakeLot");
      return post("/custody/lots", { tx: txJson });
    },
    async recordIntakeLot(args) {
      assertOperatorMode(operatorMode, "recordIntakeLot");
      const envelope = await this.buildRecordIntakeLot(args);
      await this.submitRecordIntakeLot(envelope.txJson);
      return envelope;
    },
    async buildRequestRedemption({
      requestId = null,
      assetId,
      accountCommitment,
      warehouseId,
      skuClassId,
      siloAmount,
      requestedQuantity,
      destinationRef = "",
      timestamp = nowUnix()
    }) {
      const resolvedRequestID =
        requestId ?? (await sha256hex(`${randomHex(8)}:${Date.now()}`));
      return {
        ...(await buildEnvelope(14, {
          request_id: resolvedRequestID,
          asset_id: assetId,
          account_commitment: accountCommitment,
          warehouse_id: warehouseId,
          sku_class_id: skuClassId,
          silo_amount: Number(siloAmount),
          requested_quantity: Number(requestedQuantity),
          destination_ref: destinationRef,
          timestamp
        })),
        requestId: resolvedRequestID
      };
    },
    submitRequestRedemption: (txJson) =>
      post("/custody/redemptions", { tx: txJson }),
    async requestRedemption(args) {
      const envelope = await this.buildRequestRedemption(args);
      await this.submitRequestRedemption(envelope.txJson);
      return envelope;
    },
    async buildSettleRedemption({
      settlementId = null,
      requestId,
      operatorId,
      warehouseId,
      fulfillmentRef,
      burnAmount,
      settledQuantity,
      settledAt = nowUnix()
    }) {
      const resolvedSettlementID =
        settlementId ?? (await sha256hex(`${randomHex(8)}:${Date.now()}`));
      return {
        ...(await buildEnvelope(15, {
          settlement_id: resolvedSettlementID,
          request_id: requestId,
          operator_id: operatorId,
          warehouse_id: warehouseId,
          fulfillment_ref: fulfillmentRef,
          burn_amount: Number(burnAmount),
          settled_quantity: Number(settledQuantity),
          settled_at: settledAt
        })),
        settlementId: resolvedSettlementID
      };
    },
    submitSettleRedemption(txJson) {
      assertOperatorMode(operatorMode, "settleRedemption");
      return post("/custody/redemptions/settle", { tx: txJson });
    },
    async settleRedemption(args) {
      assertOperatorMode(operatorMode, "settleRedemption");
      const envelope = await this.buildSettleRedemption(args);
      await this.submitSettleRedemption(envelope.txJson);
      return envelope;
    },
    async buildApplyDemurrage({
      assessmentId = null,
      assetId,
      accountCommitment,
      policyId,
      amount,
      periodStart,
      periodEnd,
      reason,
      appliedAt = nowUnix()
    }) {
      const resolvedAssessmentID =
        assessmentId ?? (await sha256hex(`${randomHex(8)}:${Date.now()}`));
      return {
        ...(await buildEnvelope(16, {
          assessment_id: resolvedAssessmentID,
          asset_id: assetId,
          account_commitment: accountCommitment,
          policy_id: policyId,
          amount: Number(amount),
          period_start: Number(periodStart),
          period_end: Number(periodEnd),
          reason,
          applied_at: appliedAt
        })),
        assessmentId: resolvedAssessmentID
      };
    },
    submitApplyDemurrage(txJson) {
      assertOperatorMode(operatorMode, "applyDemurrage");
      return post("/custody/demurrage", { tx: txJson });
    },
    async applyDemurrage(args) {
      assertOperatorMode(operatorMode, "applyDemurrage");
      const envelope = await this.buildApplyDemurrage(args);
      await this.submitApplyDemurrage(envelope.txJson);
      return envelope;
    }
  };
}

export function initializeFromShyConfig(shyconfig, options = {}) {
  applyStoreAnonLayerDefaults(shyconfig);
  assertCustodyManifest(shyconfig);

  if (
    shyconfig.api?.requires_auth &&
    typeof options.getAuthHeaders !== "function"
  ) {
    throw new Error(
      "shyconfig requires authenticated custody API access, but no auth header provider was supplied."
    );
  }

  return createCustodyClient({
    defaultBase: shyconfig.api?.base_url ?? "/api",
    defaultSubmitBase: shyconfig.api?.submit_base_url ?? null,
    storageKey:
      shyconfig.api?.storage_key ??
      options.storageKey ??
      "shyware_custody_api_base",
    fetchImpl: options.fetchImpl,
    getAuthHeaders: options.getAuthHeaders,
    manifest: shyconfig,
    operatorMode: Boolean(options.operatorMode)
  });
}
