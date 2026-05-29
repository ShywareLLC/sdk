/**
 * App-facing web SDK for the shyshares governance embodiment.
 *
 * Apps should treat this client as the only entrypoint into governance flows:
 * organization lookup, membership snapshots, proposal lifecycle, weighted
 * ballot submission, tally reads, and queued action dispatch.
 *
 * IMPORTANT: The sealer (AES-GCM encryption, two-party oracle) is ONLY for PII/high-risk payloads, as specified in shyconfig.sealer. Default is structural anonymity via invariant.
 * Uses shared sealer logic from shywareSealer.js for PII/high-risk payloads. Accepts async deriveSealerKey for idempotent, ephemeral key derivation. All gating is driven by the 'sealer' block in config.
 */
import { sealPayload, openPayload } from "../../protocol/sealer.js";

import { createIdentityResolver } from "../../protocol/identity/identityClient.js";

export const SHARES_MANIFEST_CONTRACT_VERSION = "shyshares-v1";

function requiredWebCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API is required by the shyshares client.");
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

async function sha256hex(value) {
  const payload = typeof value === "string" ? value : JSON.stringify(value);
  const bytes = new TextEncoder().encode(payload);
  const digest = await requiredWebCrypto().subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function assertSharesManifest(shyconfig) {
  if (shyconfig?.contract_version !== SHARES_MANIFEST_CONTRACT_VERSION) {
    throw new Error(
      `shyconfig must declare contract_version=${SHARES_MANIFEST_CONTRACT_VERSION} for shyshares apps.`
    );
  }

  if (shyconfig?.app?.product_type !== "shyshares") {
    throw new Error(
      "shyconfig product_type must be shyshares for shyshares apps."
    );
  }

  if (!shyconfig?.anon_layer?.black_box_required) {
    throw new Error(
      "shyconfig must require the anonymous layer as a black box."
    );
  }

  if (!shyconfig.signing?.required || shyconfig.signing.backend === "none") {
    throw new Error(
      "shyconfig must require protocol signing for shyshares apps."
    );
  }

  if (!shyconfig.governance || !shyconfig.execution) {
    throw new Error(
      "shyconfig must declare governance and execution settings for shyshares apps."
    );
  }

  if (shyconfig.governance.transfer_layer && shyconfig.governance.transfer_layer !== "shywire") {
    throw new Error(
      'shyconfig governance.transfer_layer must be "shywire" when declared. Omit it to use your own transfer rail.'
    );
  }

  const requiredFlows = new Set(shyconfig.anon_layer.required_flows ?? []);
  for (const flow of [
    "organization_read",
    "membership_snapshot_read",
    "proposal_create",
    "weighted_ballot_submit",
    "tally_read",
    "action_queue_read",
    "action_dispatch"
  ]) {
    if (!requiredFlows.has(flow)) {
      throw new Error(`shyconfig is missing required shyshares flow: ${flow}`);
    }
  }
}

export function createSharesClient({
  defaultBase = "/api",
  defaultSubmitBase = null,
  storageKey = "shyware_shares_api_base",
  fetchImpl = globalThis.fetch?.bind(globalThis),
  getAuthHeaders = null,
  manifest = null,
  deriveSealerKey = null // async () => provider-issued secret (string or ArrayBuffer)
} = {}) {
  if (!fetchImpl) {
    throw new Error("fetch is required by the shyshares client.");
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

  function listPath(basePath, filters = {}) {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(filters)) {
      if (value != null && value !== "") params.set(key, String(value));
    }
    const query = params.toString();
    return query ? `${basePath}?${query}` : basePath;
  }

  // Sealing helpers for PII/high-risk payloads (gated by manifest.sealer)
  async function sealSharesPayload(payload) {
    if (manifest?.sealer?.enabled === true) {
      if (typeof deriveSealerKey !== "function") {
        throw new Error(
          "Production sealer requires async deriveSealerKey() for idempotent, ephemeral key derivation"
        );
      }
      return sealPayload(payload, deriveSealerKey);
    }
    // If not PII/high-risk, return plaintext (structural anonymity only)
    return payload;
  }

  async function openSharesPayload(sealedPayload) {
    if (manifest?.sealer?.enabled === true) {
      if (typeof deriveSealerKey !== "function") {
        throw new Error(
          "Production sealer requires async deriveSealerKey() for idempotent, ephemeral key derivation"
        );
      }
      return openPayload(sealedPayload, deriveSealerKey);
    }
    // If not PII/high-risk, return as-is
    return sealedPayload;
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
        governance: manifest?.governance ?? null,
        execution: manifest?.execution ?? null,
        requiredFlows: manifest?.anon_layer?.required_flows ?? []
      };
    },
    getBase,
    setBase,
    getSubmitBase,
    getManifest: () => manifest,

    // ...existing API methods...
    sealSharesPayload,
    openSharesPayload,
    // ...existing API methods...
    createIdentityCommitment(input, options = {}) {
      return identityResolver.createCommitment(input, options);
    },
    createIdentityProofHash(input, options = {}) {
      return identityResolver.createProofHash(input, options);
    },
    listOrganizations: () => get("/organizations"),
    getOrganization: (organizationId) =>
      get(`/organizations/${organizationId}`),
    getMembershipSnapshot: (accountCommitment) =>
      get(`/memberships/${accountCommitment}`),
    listProposals(filters = {}) {
      return get(listPath("/proposals", filters));
    },
    getProposal: (proposalId) => get(`/proposals/${proposalId}`),
    getTally: (proposalId) => get(`/tallies/${proposalId}`),
    listActions(filters = {}) {
      return get(listPath("/actions", filters));
    },
    getAction: (actionId) => get(`/actions/${actionId}`),
    async createAccountCommitment(input) {
      return identityResolver.createCommitment(input, { namespace: "account" });
    },
    async createProposal(payload) {
      // Example: seal the proposal if PII/high-risk
      const sealedPayload = await sealSharesPayload(payload);
      return post("/proposals", sealedPayload);
    },
    async closeProposal(proposalId, payload = {}) {
      return post(`/proposals/${proposalId}/close`, payload);
    },
    async submitWeightedBallot(payload) {
      // Example: seal the ballot if PII/high-risk
      const sealedPayload = await sealSharesPayload(payload);
      return post("/ballots", {
        ...sealedPayload,
        submitted_at: payload.submitted_at ?? nowUnix()
      });
    },
    async dispatchAction(actionId, payload = {}) {
      return post(`/actions/${actionId}/dispatch`, payload);
    }
  };
}

export function initializeFromShyConfig(shyconfig, options = {}) {
  assertSharesManifest(shyconfig);

  if (
    shyconfig.api?.requires_auth &&
    typeof options.getAuthHeaders !== "function"
  ) {
    throw new Error(
      "shyconfig requires authenticated shares API access, but no auth header provider was supplied."
    );
  }

  return createSharesClient({
    defaultBase: shyconfig.api?.base_url ?? "/api",
    defaultSubmitBase: shyconfig.api?.submit_base_url ?? null,
    storageKey:
      shyconfig.api?.storage_key ??
      options.storageKey ??
      "shyware_shares_api_base",
    fetchImpl: options.fetchImpl,
    getAuthHeaders: options.getAuthHeaders,
    manifest: shyconfig
  });
}
