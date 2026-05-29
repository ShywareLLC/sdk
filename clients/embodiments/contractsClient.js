/**
 * App-facing web SDK for the shyware anonymous contracts platform.
 *
 * Supports arbitrary bilateral/multilateral contracts with anonymous parties,
 * off-chain terms binding, and optional shywire value transfer rail.
 */

import { createIdentityResolver } from "../../protocol/identity/identityClient.js";
import { createWalletProofBase64 } from "../../protocol/walletProof.js";

export const CONTRACTS_MANIFEST_CONTRACT_VERSION = "shycontracts-v1";

function requiredWebCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API is required by the shyware contracts client.");
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
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256hex(value) {
  const payload = typeof value === "string" ? value : JSON.stringify(value);
  const bytes = new TextEncoder().encode(payload);
  const digest = await requiredWebCrypto().subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function normalizeParties(parties = []) {
  return parties
    .filter((p) => p && p.commitment)
    .map((p, index) => ({
      role:          p.role ?? `party_${index}`,
      commitment:    p.commitment,
      allocation_bps: Number(p.allocation_bps ?? 0),
      seniority:     Number(p.seniority ?? index)
    }));
}

async function buildEnvelope(type, data) {
  return { txJson: JSON.stringify({ type, signature: "AQ==", data }), type, data };
}

function getContractsBlock(shyconfig) {
  return shyconfig?.contracts ?? shyconfig?.financing ?? null;
}

export function assertContractsManifest(shyconfig) {
  if (shyconfig?.contract_version !== CONTRACTS_MANIFEST_CONTRACT_VERSION) {
    throw new Error(`shyconfig must declare contract_version=${CONTRACTS_MANIFEST_CONTRACT_VERSION} for shycontracts apps.`);
  }
  if (shyconfig?.app?.product_type !== "shycontracts") {
    throw new Error("shyconfig product_type must be shycontracts for shycontracts apps.");
  }
  if (!shyconfig?.anon_layer?.black_box_required) {
    throw new Error("shyconfig must require the anonymous layer as a black box.");
  }
  const requiredFlows = new Set(shyconfig.anon_layer.required_flows ?? []);
  for (const flow of ["contract_register", "contract_activate", "contract_execute"]) {
    if (!requiredFlows.has(flow)) {
      throw new Error(`shyconfig is missing required shycontracts flow: ${flow}`);
    }
  }
  if (!shyconfig.signing?.required || shyconfig.signing.backend === "none") {
    throw new Error("shyconfig must require protocol signing for shycontracts apps.");
  }
  if (["aws_kms", "aws_kms_x_aws_cloudhsm"].includes(shyconfig.signing.backend) && !shyconfig.signing.contract_key_id) {
    throw new Error("Managed KMS shycontracts apps must declare contract_key_id.");
  }
  const block = getContractsBlock(shyconfig);
  if (!block) {
    throw new Error("shyconfig must declare a `contracts` (or `financing`) block for shycontracts apps.");
  }
  if (block.transfer_layer && block.transfer_layer !== "shywire") {
    throw new Error('shyconfig contracts.transfer_layer must be "shywire" when declared.');
  }
}

export function createContractsClient({
  defaultBase = "/api",
  defaultSubmitBase = null,
  storageKey = "shyware_contracts_api_base",
  fetchImpl = globalThis.fetch?.bind(globalThis),
  getAuthHeaders = null,
  manifest = null
} = {}) {
  if (!fetchImpl) throw new Error("fetch is required by the shyware contracts client.");

  const identityResolver = createIdentityResolver(manifest);

  function getBase() {
    if (typeof localStorage === "undefined") return defaultBase;
    return localStorage.getItem(storageKey) || defaultBase;
  }
  function setBase(url) {
    if (typeof localStorage === "undefined") return;
    if (!url) { localStorage.removeItem(storageKey); return; }
    localStorage.setItem(storageKey, url);
  }
  function getSubmitBase() {
    return defaultSubmitBase == null ? getBase() : defaultSubmitBase;
  }
  async function resolveHeaders(extra = {}) {
    if (!getAuthHeaders) return extra;
    return { ...(await getAuthHeaders()), ...extra };
  }
  async function get(path) {
    let res;
    try {
      res = await fetchImpl(joinBaseAndPath(getBase(), path), { headers: await resolveHeaders() });
    } catch {
      throw new Error("API not reachable - check Settings or your network connection.");
    }
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error ?? `HTTP ${res.status}`);
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
      throw new Error("API not reachable - check Settings or your network connection.");
    }
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error ?? `HTTP ${res.status}`);
    return res.json();
  }

  return {
    initialize() {
      return {
        contractVersion: manifest?.contract_version ?? null,
        appId:           manifest?.app?.id ?? null,
        chainId:         manifest?.app?.chain_id ?? null,
        apiBase:         getBase(),
        submitBase:      getSubmitBase(),
        identity:        manifest?.identity ?? null,
        identityProfile: identityResolver.profile,
        signing:         manifest?.signing ?? null,
        deployment:      manifest?.deployment ?? null,
        contracts:       getContractsBlock(manifest),
        requiredFlows:   manifest?.anon_layer?.required_flows ?? []
      };
    },
    getBase, setBase, getSubmitBase,
    getManifest: () => manifest,
    createWalletProof:        (args) => createWalletProofBase64(args),
    createIdentityCommitment: (input, options = {}) => identityResolver.createCommitment(input, options),
    createIdentityProofHash:  (input, options = {}) => identityResolver.createProofHash(input, options),

    // ---- wire read surface ----
    getAsset:   (assetId) => get(`/assets/${assetId}`),
    getSupply:  (assetId) => get(`/supply/${assetId}`),
    getBalance: (assetId, accountCommitment) => get(`/balance/${assetId}/${accountCommitment}`),

    // ---- contract read surface ----
    getContract:        (contractId)  => get(`/contracts/${contractId}`),
    getContractExecution: (executionId) => get(`/contracts/executions/${executionId}`),

    // ---- asset + account setup ----
    async buildRegisterAsset({ assetId, name, decimals = 2 }) {
      return buildEnvelope(1, { asset_id: assetId, name, decimals: Number(decimals) });
    },
    submitRegisterAsset: (txJson) => post("/assets", { tx: txJson }),
    async registerAsset(args) {
      const e = await this.buildRegisterAsset(args);
      await this.submitRegisterAsset(e.txJson);
      return e;
    },

    async buildRegisterAccount({
      walletAddress = "", identityInput = null, accountCommitment = null,
      walletProofBase64 = "", enrollmentToken = "", enrollmentProofBase64 = ""
    }) {
      const addr = walletAddress || (typeof identityInput === "string" ? identityInput.trim() : "");
      const commitment = accountCommitment ??
        (await identityResolver.createCommitment(identityInput ?? addr, { namespace: "account" }));
      const proof = walletProofBase64 ||
        (addr ? await createWalletProofBase64({ accountCommitment: commitment, walletAddress: addr }) : "");
      if (!proof) throw new Error("walletProofBase64 is required for account registration.");
      return {
        ...(await buildEnvelope(5, {
          account_commitment: commitment, wallet_proof: proof,
          enrollment_token: enrollmentToken, enrollment_proof: enrollmentProofBase64
        })),
        accountCommitment: commitment
      };
    },
    submitRegisterAccount: (txJson) => post("/accounts", { tx: txJson }),
    async registerAccount(args) {
      const e = await this.buildRegisterAccount(args);
      await this.submitRegisterAccount(e.txJson);
      return e;
    },

    async buildMint({ assetId, accountCommitment, amount, timestamp = nowUnix() }) {
      return buildEnvelope(2, { asset_id: assetId, account_commitment: accountCommitment, amount: Number(amount), timestamp });
    },
    submitMint: (txJson) => post("/mint", { tx: txJson }),
    async mint(args) {
      const e = await this.buildMint(args);
      await this.submitMint(e.txJson);
      return e;
    },

    // ---- contract lifecycle ----

    /**
     * Register an anonymous contract on-chain.
     *
     * parties      — [{ role, commitment, allocation_bps?, seniority? }]
     * contractType — arbitrary string identifying the domain (e.g. "rbf", "escrow", "grant")
     * offchainTerms — hashed into contractHash; not written to canonical state
     * metadata     — written to canonical state as-is; domain-specific
     */
    async buildRegisterContract({
      assetId,
      parties = [],
      contractType = "general",
      offchainTerms = {},
      metadata = {},
      pendingCondition = false,
      expiryTimestamp = 0,
      timestamp = nowUnix()
    }) {
      const normalizedParties = normalizeParties(parties);
      const contractHash = await sha256hex({ contractType, ...offchainTerms, parties: normalizedParties, metadata, expiryTimestamp: Number(expiryTimestamp) });
      const contractId = await sha256hex(`${contractHash}:${timestamp}:${randomHex(16)}`);
      return {
        ...(await buildEnvelope(7, {
          contract_id:       contractId,
          asset_id:          assetId ?? null,
          contract_type:     contractType,
          contract_hash:     contractHash,
          parties:           normalizedParties,
          metadata:          Object.keys(metadata).length ? metadata : undefined,
          pending_condition: pendingCondition || undefined,
          expiry_timestamp:  Number(expiryTimestamp),
          timestamp
        })),
        contractId,
        contractHash
      };
    },
    submitRegisterContract: (txJson) => post("/contracts", { tx: txJson }),
    async registerContract(args) {
      const e = await this.buildRegisterContract(args);
      await this.submitRegisterContract(e.txJson);
      return e;
    },

    /**
     * Transition a contract from pending_condition to active.
     *
     * evidence     — arbitrary string (e.g. goal attestation, counter-signature ref)
     * evidenceType — arbitrary string (e.g. "goal_achievement", "counter_signature")
     */
    async buildActivateContract({
      contractId,
      evidence = "",
      evidenceType = "operator_attestation",
      activatedAt = nowUnix()
    }) {
      const evidenceHash = await sha256hex(evidence);
      return {
        ...(await buildEnvelope(9, {
          contract_id:   contractId,
          evidence_hash: evidenceHash,
          evidence_type: evidenceType,
          activated_at:  activatedAt
        })),
        evidenceHash
      };
    },
    submitActivateContract: (txJson) => post("/contracts/activate", { tx: txJson }),
    async activateContract(args) {
      const e = await this.buildActivateContract(args);
      await this.submitActivateContract(e.txJson);
      return e;
    },

    /**
     * Record a contract execution event on-chain.
     *
     * sourceRef              — idempotency key. Nullifier = H(partyCommitment:contractId:sourceRef).
     *                          Same sourceRef submitted twice is rejected as duplicate.
     * executionType          — arbitrary string (e.g. "remittance", "settlement", "milestone")
     * payload                — arbitrary metadata committed to canonical state
     * assetId / amount       — include when value moves alongside the execution record
     * counterpartyCommitment — recipient account for value-bearing executions
     */
    async buildContractExecution({
      contractId,
      assetId,
      partyCommitment,
      counterpartyCommitment,
      executionType = "execution",
      sourceRef,
      amount,
      payload = {}
    }) {
      const transferNonce = randomHex(32);
      const nullifier = await sha256hex(`${partyCommitment}:${contractId}:${sourceRef}`);
      const executionId = await sha256hex(transferNonce);
      return {
        ...(await buildEnvelope(8, {
          contract_id:             contractId,
          asset_id:                assetId ?? null,
          party_commitment:        partyCommitment,
          counterparty_commitment: counterpartyCommitment ?? null,
          execution_type:          executionType,
          source_ref:              sourceRef,
          amount:                  amount != null ? Number(amount) : null,
          payload:                 Object.keys(payload).length ? payload : undefined,
          nullifier,
          transfer_nonce:          transferNonce,
          timestamp:               nowUnix()
        })),
        executionId,
        nullifier
      };
    },
    submitContractExecution: (txJson) => post("/contracts/executions", { tx: txJson }),
    async executeContract(args) {
      const e = await this.buildContractExecution(args);
      await this.submitContractExecution(e.txJson);
      return e;
    }
  };
}

export function initializeFromShyConfig(shyconfig, options = {}) {
  assertContractsManifest(shyconfig);
  if (shyconfig.api?.requires_auth && typeof options.getAuthHeaders !== "function") {
    throw new Error("shyconfig requires authenticated contracts API access, but no auth header provider was supplied.");
  }
  return createContractsClient({
    defaultBase:      shyconfig.api?.base_url ?? "/api",
    defaultSubmitBase: shyconfig.api?.submit_base_url ?? null,
    storageKey:       shyconfig.api?.storage_key ?? options.storageKey ?? "shyware_contracts_api_base",
    fetchImpl:        options.fetchImpl,
    getAuthHeaders:   options.getAuthHeaders,
    manifest:         shyconfig
  });
}
