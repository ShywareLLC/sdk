/**
 * App-facing web SDK for the shybets trading and betting embodiment.
 *
 * Shybets is a regulated domain contract version (shybets-v1) that exposes
 * event creation, order placement, order-book reads, settlement, and
 * authority-gated reconcile requests while preserving structural anonymity.
 */

import { createIdentityResolver } from "../../protocol/identity/identityClient.js";
import { createWireClient } from "../embodiments/wireClient.js";

export const BETS_MANIFEST_CONTRACT_VERSION = "shybets-v1";

const REQUIRED_FLOWS = [
  "event_create",
  "order_place",
  "order_book_read",
  "settlement_read",
  "settlement_finalize",
  "reconcile_request"
];

function requiredWebCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API is required by the shybets client.");
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

export function assertBetsManifest(shyconfig) {
  if (shyconfig?.contract_version !== BETS_MANIFEST_CONTRACT_VERSION) {
    throw new Error(
      `shyconfig must declare contract_version=${BETS_MANIFEST_CONTRACT_VERSION} for shybets apps.`
    );
  }

  if (shyconfig?.app?.product_type !== "shybets") {
    throw new Error("shyconfig product_type must be shybets for shybets apps.");
  }

  if (!shyconfig?.anon_layer?.black_box_required) {
    throw new Error(
      "shyconfig must require the anonymous layer as a black box."
    );
  }

  if (!shyconfig?.signing?.required || shyconfig.signing.backend === "none") {
    throw new Error(
      "shyconfig must require protocol signing for shybets apps."
    );
  }

  if (!shyconfig?.wire) {
    throw new Error(
      "shyconfig must declare wire settings for shybets apps (stake/funding settlement rail)."
    );
  }

  const activeFlows = new Set(shyconfig.anon_layer.required_flows ?? []);
  for (const flow of REQUIRED_FLOWS) {
    if (!activeFlows.has(flow)) {
      throw new Error(`shyconfig is missing required shybets flow: ${flow}`);
    }
  }
}

export function createBetsClient({
  defaultBase = "/api",
  defaultSubmitBase = null,
  storageKey = "shyware_bets_api_base",
  fetchImpl = globalThis.fetch?.bind(globalThis),
  getAuthHeaders = null,
  manifest = null,
  operatorMode = false
} = {}) {
  if (!fetchImpl) {
    throw new Error("fetch is required by the shybets client.");
  }

  const identityResolver = createIdentityResolver(manifest);
  const wireClient = createWireClient({
    defaultBase,
    defaultSubmitBase,
    storageKey,
    fetchImpl,
    getAuthHeaders,
    manifest,
    operatorMode
  });

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

  function listPath(basePath, filters = {}) {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(filters)) {
      if (value != null && value !== "") params.set(key, String(value));
    }
    const query = params.toString();
    return query ? `${basePath}?${query}` : basePath;
  }

  return {
    initialize() {
      return {
        contractVersion: manifest?.contract_version ?? null,
        appId: manifest?.app?.id ?? null,
        chainId: manifest?.app?.chain_id ?? null,
        productType: manifest?.app?.product_type ?? null,
        apiBase: getBase(),
        submitBase: getSubmitBase(),
        identity: manifest?.identity ?? null,
        identityProfile: identityResolver.profile,
        signing: manifest?.signing ?? null,
        deployment: manifest?.deployment ?? null,
        wire: manifest?.wire ?? null,
        requiredFlows: manifest?.anon_layer?.required_flows ?? [],
        operatorMode
      };
    },
    getBase,
    setBase,
    getSubmitBase,
    getManifest: () => manifest,

    getSettlementClient: () => wireClient,
    createWalletProof(args) {
      return wireClient.createWalletProof(args);
    },
    createIdentityCommitment(input, options = {}) {
      return identityResolver.createCommitment(input, options);
    },
    createIdentityProofHash(input, options = {}) {
      return identityResolver.createProofHash(input, options);
    },
    listEvents(filters = {}) {
      return get(listPath("/bets/events", filters));
    },
    getEvent(eventId) {
      return get(`/bets/events/${eventId}`);
    },
    listOrderBook(eventId) {
      return get(`/bets/events/${eventId}/order-book`);
    },
    listOrders(filters = {}) {
      return get(listPath("/bets/orders", filters));
    },
    getOrder(orderId) {
      return get(`/bets/orders/${orderId}`);
    },
    listSettlements(filters = {}) {
      return get(listPath("/bets/settlements", filters));
    },
    getSettlement(eventId) {
      return get(`/bets/settlements/${eventId}`);
    },
    async buildCreateEventTx({
      eventId,
      marketId,
      title,
      outcomes,
      closesAt,
      metadata = {}
    }) {
      const canonicalEventId =
        eventId || (await sha256hex(`${marketId}:${title}:${closesAt}`));
      return buildEnvelope(1, {
        event_id: canonicalEventId,
        market_id: marketId,
        title,
        outcomes,
        closes_at: closesAt,
        metadata,
        timestamp: nowUnix()
      });
    },
    submitCreateEventTx(txJson) {
      return post("/bets/events/tx", { tx: txJson });
    },
    async createEvent(args) {
      const envelope = await this.buildCreateEventTx(args);
      const receipt = await this.submitCreateEventTx(envelope.txJson);
      return {
        ...envelope,
        receipt
      };
    },
    async buildPlaceOrderTx({
      eventId,
      side,
      outcome,
      stake,
      odds,
      accountCommitment,
      orderNonce,
      settlementAssetId = manifest?.wire?.asset_id ?? null
    }) {
      const nonce = orderNonce || randomHex(32);
      const orderId = await sha256hex(
        `${eventId}:${accountCommitment}:${nonce}`
      );
      return buildEnvelope(2, {
        order_id: orderId,
        event_id: eventId,
        side,
        outcome,
        stake,
        odds,
        settlement_asset_id: settlementAssetId,
        account_commitment: accountCommitment,
        order_nonce: nonce,
        timestamp: nowUnix()
      });
    },
    submitPlaceOrderTx(txJson) {
      return post("/bets/orders/tx", { tx: txJson });
    },
    async placeOrder(args) {
      const envelope = await this.buildPlaceOrderTx(args);
      const receipt = await this.submitPlaceOrderTx(envelope.txJson);
      return {
        ...envelope,
        receipt
      };
    },
    async buildSettleEventTx({
      eventId,
      winningOutcome,
      source = "operator_attested"
    }) {
      return buildEnvelope(3, {
        event_id: eventId,
        winning_outcome: winningOutcome,
        source,
        timestamp: nowUnix()
      });
    },
    submitSettleEventTx(txJson) {
      return post("/bets/settlements/tx", { tx: txJson });
    },
    async settleEvent(args) {
      const envelope = await this.buildSettleEventTx(args);
      const receipt = await this.submitSettleEventTx(envelope.txJson);
      return {
        ...envelope,
        receipt
      };
    },
    requestRegulatoryReconcile({ eventId, reason, authorityRef }) {
      return post("/bets/reconcile-requests", {
        event_id: eventId,
        reason,
        authority_ref: authorityRef,
        timestamp: nowUnix()
      });
    },
    createFundingIntent(args, options = {}) {
      return wireClient.createIssueIntent(args, options);
    },
    createPayoutIntent(args, options = {}) {
      return wireClient.createRedeemIntent(args, options);
    },
    buildRegisterSettlementAccount(args) {
      return wireClient.buildRegisterAccount(args);
    },
    submitRegisterSettlementAccount(txJson) {
      return wireClient.submitRegisterAccount(txJson);
    },
    registerSettlementAccount(args) {
      return wireClient.registerAccount(args);
    },
    transferStake(args) {
      return wireClient.wireSubmission(args);
    }
  };
}

export function initializeFromShyConfig(shyconfig, options = {}) {
  assertBetsManifest(shyconfig);

  const requiresAuth =
    shyconfig.api?.requires_auth === true ||
    (shyconfig.api?.auth_scheme && shyconfig.api.auth_scheme !== "none");

  if (requiresAuth && typeof options.getAuthHeaders !== "function") {
    throw new Error(
      "shyconfig requires authenticated shybets API access, but no auth header provider was supplied."
    );
  }

  return createBetsClient({
    defaultBase: shyconfig.api?.base_url ?? "/api",
    storageKey:
      shyconfig.api?.storage_key ??
      options.storageKey ??
      "shyware_bets_api_base",
    fetchImpl: options.fetchImpl,
    getAuthHeaders: options.getAuthHeaders,
    manifest: shyconfig,
    operatorMode: options.operatorMode === true
  });
}

export function formatBetsError(error) {
  return error?.message || "Bets operation failed.";
}
