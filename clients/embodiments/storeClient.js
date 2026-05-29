/**
 * App-facing web SDK for shystore-v1 confidential secret storage.
 *
 * Provides the full shyware two-list protocol for secret storage:
 * - BucketCreate (bucket open)
 * - SecretStore (atomic List 1 + List 2 write via ABCI broadcast)
 * - SecretReveal (emit reveal_requested event; receive sealed payload from reconcile authority)
 * - SecretRotate (List 1 direction change; recoverable posture only)
 * - BucketClose (period close + HSM-signed ClosureRecord)
 * - Local sealing helpers for PII/high-risk payloads (optional; gated by shyconfig.store.sealer)
 *
 * IMPORTANT: SealedPayload is AES-GCM encrypted by the caller using a participant-derived key
 * before the tx is broadcast. The ABCI layer stores ciphertext verbatim in List 1 and never
 * has access to plaintext. Local sealing (sealSecret / openSecret) uses shywareSealer.js.
 */
import { sealPayload, openPayload } from "../../protocol/sealer.js";
import {
  applyStoreAnonLayerDefaults,
  assertStoreBackedAnonLayer
} from "../../protocol/anonLayer.js";

export const STORE_MANIFEST_CONTRACT_VERSION = "shystore-v1";

// Tx type discriminators — must match shyware/tx/store.go constants.
const StoreTxTypeSecretStore = 1;
const StoreTxTypeSecretReveal = 2;
const StoreTxTypeSecretRotate = 3;
const StoreTxTypeBucketClose = 4;

function normalizeBase(base) {
  if (base == null || base === "") return "";
  return String(base).endsWith("/") ? String(base).slice(0, -1) : String(base);
}

function joinBaseAndPath(base, path) {
  return `${normalizeBase(base)}${path}`;
}

async function parseJson(res) {
  return res.json().catch(() => ({}));
}

async function sha256hex(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  const entries = keys.map(
    (key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`
  );
  return `{${entries.join(",")}}`;
}

function resolveIdentifierDerivationMode(manifest) {
  const mode =
    manifest?.anon_layer?.submission_identifier_derivation ?? "nonce_only";
  if (mode === "nonce_only" || mode === "nonce_plus_payload") {
    return mode;
  }
  return "nonce_only";
}

async function deriveSecretIdentifier({ nonceHex, payload, manifest }) {
  const mode = resolveIdentifierDerivationMode(manifest);
  if (mode === "nonce_plus_payload") {
    const canonicalPayload = stableStringify(payload);
    return sha256hex(`${nonceHex}:${canonicalPayload}`);
  }
  return sha256hex(nonceHex);
}

export function assertStoreManifest(shyconfig) {
  applyStoreAnonLayerDefaults(shyconfig);

  if (shyconfig?.contract_version !== STORE_MANIFEST_CONTRACT_VERSION) {
    throw new Error(
      `shyconfig must declare contract_version=${STORE_MANIFEST_CONTRACT_VERSION} for shystore apps.`
    );
  }
  if (shyconfig?.app?.product_type !== "shystore") {
    throw new Error(
      "shyconfig product_type must be shystore for shystore apps."
    );
  }
  if (!shyconfig?.store) {
    throw new Error(
      "shyconfig must include a store block for contract_version=shystore-v1."
    );
  }
  if (!shyconfig?.domains?.private?.console) {
    throw new Error(
      "shyconfig must declare a private console domain for shystore apps."
    );
  }

  assertStoreBackedAnonLayer(shyconfig, "shystore");
}

/**
 * createStoreClient returns a fully-wired shystore-v1 SDK client.
 *
 * @param {object} options
 * @param {string}   options.defaultBase          - API base URL (default "/api")
 * @param {string}   options.storageKey           - localStorage key for base URL override
 * @param {Function} options.fetchImpl            - fetch implementation
 * @param {Function} options.getAuthHeaders       - async () => {Authorization: ...}
 * @param {object}   options.manifest             - shyconfig object
 * @param {Function} options.deriveSealerKey      - async () => key material for AES-GCM local sealing
 * @param {Function} options.signMessage          - async (message: Uint8Array) => {pubKeyHex, sigBytes}
 *                                                  Provides device-side Ed25519 signing for oracle-forgery prevention.
 * @param {Function} options.getIdentityAttestation - async (scope) => {idv_attestation_sig?}
 *                                                  Provides IDV attestation for List 2 identity binding.
 */
export function createStoreClient({
  defaultBase = "/api",
  storageKey = "shyware_store_api_base",
  fetchImpl = globalThis.fetch?.bind(globalThis),
  getAuthHeaders = null,
  manifest = null,
  deriveSealerKey = null,
  signMessage = null,
  getIdentityAttestation = null
} = {}) {
  if (!fetchImpl) {
    throw new Error("fetch is required by the shystore client.");
  }

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

  async function resolveHeaders(extraHeaders = {}) {
    if (!getAuthHeaders) return extraHeaders;
    const authHeaders = await getAuthHeaders();
    return { ...authHeaders, ...extraHeaders };
  }

  async function get(path) {
    let res;
    try {
      res = await fetchImpl(joinBaseAndPath(getBase(), path), {
        headers: await resolveHeaders()
      });
    } catch {
      throw new Error(
        "API not reachable — check Settings or your network connection."
      );
    }
    const body = await parseJson(res);
    if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
    return body;
  }

  async function post(path, body) {
    let res;
    try {
      res = await fetchImpl(joinBaseAndPath(getBase(), path), {
        method: "POST",
        headers: await resolveHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(body)
      });
    } catch {
      throw new Error(
        "API not reachable — check Settings or your network connection."
      );
    }
    const payload = await parseJson(res);
    if (!res.ok) throw new Error(payload.error ?? `HTTP ${res.status}`);
    return payload;
  }

  /**
   * broadcastTx submits a shyware tx envelope to the ABCI broadcast endpoint.
   * The server relays it to the CometBFT mempool via broadcast_tx_sync.
   */
  async function broadcastTx(txType, data) {
    return post("/store/broadcast", {
      type: txType,
      signature: [1], // placeholder — real implementations sign the tx envelope
      data
    });
  }

  // ---- Local sealing (optional; gated by manifest.store.sealer) ----

  function sealingEnabled() {
    return (
      manifest?.store?.sealer?.mode === "sealed_storage" ||
      manifest?.store?.payload_encryption?.mode === "participant_derived_key"
    );
  }

  /**
   * sealSecret encrypts a secret payload using AES-GCM with the participant-derived key.
   * Returns the sealed envelope as a JSON object suitable for SecretStoreData.sealed_payload.
   */
  async function sealSecret(plaintext) {
    if (!sealingEnabled()) return plaintext;
    if (typeof deriveSealerKey !== "function") {
      throw new Error(
        "Production sealer requires async deriveSealerKey() for idempotent key derivation."
      );
    }
    return sealPayload(plaintext, deriveSealerKey);
  }

  /**
   * openSecret decrypts a sealed envelope returned by the reconciling authority.
   */
  async function openSecret(sealedEnvelope) {
    if (!sealingEnabled()) return sealedEnvelope;
    if (typeof deriveSealerKey !== "function") {
      throw new Error(
        "Production sealer requires async deriveSealerKey() for idempotent key derivation."
      );
    }
    return openPayload(sealedEnvelope, deriveSealerKey);
  }

  // ---- Device signature helpers ----

  /**
   * deviceSignDispatch produces the oracle-forgery-prevention signature for SecretStore:
   *   SenderSig = Ed25519.Sign(sk_s, secretNonce + ":" + bucketID)
   */
  async function deviceSignDispatch(secretNonce, bucketID) {
    if (typeof signMessage !== "function") {
      throw new Error("signMessage() is required for store operations.");
    }
    const msg = new TextEncoder().encode(`${secretNonce}:${bucketID}`);
    return signMessage(msg);
  }

  async function deviceSignRotate(newSecretNonce, bucketID) {
    if (typeof signMessage !== "function") {
      throw new Error("signMessage() is required for store operations.");
    }
    const msg = new TextEncoder().encode(
      `rotate:${newSecretNonce}:${bucketID}`
    );
    return signMessage(msg);
  }

  async function deviceSignReveal(secretID, bucketID) {
    if (typeof signMessage !== "function") {
      throw new Error("signMessage() is required for store operations.");
    }
    const msg = new TextEncoder().encode(`${secretID}:${bucketID}`);
    return signMessage(msg);
  }

  // ---- Public API ----

  return {
    initialize() {
      return {
        contractVersion: manifest?.contract_version ?? null,
        appId: manifest?.app?.id ?? null,
        apiBase: getBase(),
        domains: manifest?.domains ?? null,
        identity: manifest?.identity ?? null,
        deployment: manifest?.deployment ?? null,
        secretCategories: manifest?.store?.secret_categories ?? [],
        payloadEncryption: manifest?.store?.payload_encryption ?? null,
        recoveryMode: manifest?.store?.recovery_mode ?? null,
        selectiveDisclosure: manifest?.store?.selective_disclosure ?? false,
        enumerationProtection:
          manifest?.store?.enumeration_protection ?? "structural"
      };
    },

    getBase,
    setBase,
    getManifest: () => manifest,

    // ---- Sealing ----
    sealPayload: sealSecret,
    openPayload: openSecret,

    // ---- Bucket lifecycle ----

    async createBucket({ scopingId, allowedCategories = [] }) {
      return post("/store/buckets", {
        scoping_id: scopingId,
        allowed_categories: allowedCategories
      });
    },

    listBuckets: async () => {
      const body = await get("/store/buckets");
      return body.buckets ?? [];
    },

    getBucket: async (scopingId) => {
      const body = await get(`/store/buckets/${scopingId}`);
      return body.bucket ?? null;
    },

    // ---- storeSubmission — atomic two-list write ----

    async storeSubmission({
      scopingId,
      plaintext,
      category,
      partitionID = "sealed"
    }) {
      const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
      const submissionNonce = Array.from(nonceBytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      const submissionId = await deriveSecretIdentifier({
        nonceHex: submissionNonce,
        payload: plaintext,
        manifest
      });

      const submissionIdentifierDerivation =
        resolveIdentifierDerivationMode(manifest);

      const sealedPayload = await sealSecret(plaintext);

      const { pubKeyHex, sigBytes } = await deviceSignDispatch(
        submissionNonce,
        scopingId
      );
      const attestation =
        typeof getIdentityAttestation === "function"
          ? await getIdentityAttestation(scopingId)
          : {};

      const result = await broadcastTx(StoreTxTypeSecretStore, {
        scoping_id: scopingId,
        submission_nonce: submissionNonce,
        submission_identifier_derivation: submissionIdentifierDerivation,
        timestamp: Math.floor(Date.now() / 1000),
        partition_id: partitionID,
        category,
        sealed_payload: sealedPayload,
        sender_pub_key: pubKeyHex,
        sender_sig: Array.from(sigBytes),
        ...attestation
      });

      return { submissionId, submissionNonce, result };
    },

    // ---- revealStore — emit on-chain reveal event; receive sealed payload off-chain ----

    async revealStore({ scopingId, submissionId }) {
      const { pubKeyHex, sigBytes } = await deviceSignReveal(
        submissionId,
        scopingId
      );
      const attestation =
        typeof getIdentityAttestation === "function"
          ? await getIdentityAttestation(scopingId)
          : {};

      await broadcastTx(StoreTxTypeSecretReveal, {
        scoping_id: scopingId,
        submission_id: submissionId,
        timestamp: Math.floor(Date.now() / 1000),
        sender_pub_key: pubKeyHex,
        sender_sig: Array.from(sigBytes),
        ...attestation
      });

      const body = await get(
        `/store/buckets/${scopingId}/secrets/${submissionId}/receipt`
      );
      return body.sealed_payload ?? null;
    },

    async revealAndDecryptStore({ scopingId, submissionId }) {
      const sealedPayload = await this.revealStore({ scopingId, submissionId });
      if (!sealedPayload) return null;
      return openSecret(sealedPayload);
    },

    // ---- rotateStore — replace List 1 entry ----

    async rotateStore({ scopingId, submissionId: oldSubmissionId, newPlaintext }) {
      const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
      const submissionNonce = Array.from(nonceBytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      const submissionId = await deriveSecretIdentifier({
        nonceHex: submissionNonce,
        payload: newPlaintext,
        manifest
      });

      const submissionIdentifierDerivation =
        resolveIdentifierDerivationMode(manifest);

      const newSealedPayload = await sealSecret(newPlaintext);
      const { pubKeyHex, sigBytes } = await deviceSignRotate(
        submissionNonce,
        scopingId
      );
      const attestation =
        typeof getIdentityAttestation === "function"
          ? await getIdentityAttestation(scopingId)
          : {};

      const result = await broadcastTx(StoreTxTypeSecretRotate, {
        scoping_id: scopingId,
        old_submission_id: oldSubmissionId,
        new_submission_nonce: submissionNonce,
        submission_identifier_derivation: submissionIdentifierDerivation,
        new_sealed_payload: newSealedPayload,
        timestamp: Math.floor(Date.now() / 1000),
        sender_pub_key: pubKeyHex,
        sender_sig: Array.from(sigBytes),
        ...attestation
      });

      if (result && typeof result === "object" && !Array.isArray(result)) {
        return { ...result, submissionId, submissionNonce };
      }
      return { result, submissionId, submissionNonce };
    },

    // ---- closeBucket — operator-initiated snapshot + HSM attestation ----

    async closeBucket({ scopingId, closingHeight }) {
      return broadcastTx(StoreTxTypeBucketClose, {
        scoping_id: scopingId,
        closing_height: closingHeight
      });
    },

    getBucketClosure: async (scopingId) => {
      const body = await get(`/store/buckets/${scopingId}/closure`);
      return body.closure ?? null;
    },

    // ---- Receipt store ----

    writeRecoveryReceipt: async (scopingId, submissionId) => {
      const body = await post(
        `/store/buckets/${scopingId}/secrets/${submissionId}/receipt`,
        {}
      );
      return body.receipt ?? null;
    },

    readRecoveryReceipt: async (scopingId, submissionId) => {
      const body = await get(
        `/store/buckets/${scopingId}/secrets/${submissionId}/receipt`
      );
      return body.receipt ?? null;
    }
  };
}

export function initializeFromShyConfig(shyconfig, options = {}) {
  applyStoreAnonLayerDefaults(shyconfig);
  assertStoreManifest(shyconfig);

  const requiresAuth =
    shyconfig.api?.requires_auth === true ||
    (shyconfig.api?.auth_scheme && shyconfig.api.auth_scheme !== "none");

  if (requiresAuth && typeof options.getAuthHeaders !== "function") {
    throw new Error(
      "shyconfig requires authenticated store API access, but no auth header provider was supplied."
    );
  }

  return createStoreClient({
    defaultBase: shyconfig.api?.base_url ?? "/api",
    storageKey:
      shyconfig.api?.storage_key ??
      options.storageKey ??
      "shyware_store_api_base",
    fetchImpl: options.fetchImpl,
    getAuthHeaders: options.getAuthHeaders,
    manifest: shyconfig,
    deriveSealerKey: options.deriveSealerKey,
    signMessage: options.signMessage,
    getIdentityAttestation: options.getIdentityAttestation
  });
}

export function formatStoreError(error) {
  return error?.message || "Store operation failed.";
}
