/**
 * App-facing web SDK for the shyware anonymous submission protocol layer.
 *
 * Apps should treat this client as the only entrypoint into the protocol:
 * submission type reads, submission construction, payload submission, and receipt policy all flow
 * through this module so product surfaces cannot silently skip steps.
 */

import { createIdentityResolver } from "../../protocol/identity/identityClient.js";

export const SUBMISSION_MANIFEST_CONTRACT_VERSION = "shyvoting-v1"; // For compatibility, but protocol is general
export const VOTING_MANIFEST_CONTRACT_VERSION = "shyvoting-v1";

function requiredWebCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API is required by the shyware voting client.");
  }
  return globalThis.crypto;
}

function normalizeBase(base) {
  if (base == null || base === "") return "";
  return String(base).endsWith("/") ? String(base).slice(0, -1) : String(base);
}

function joinBaseAndPath(base, path) {
  const normalizedBase = normalizeBase(base);
  return `${normalizedBase}${path}`;
}

async function sha256hex(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await requiredWebCrypto().subtle.digest("SHA-256", buf);
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

function resolveSubmissionIdentifierDerivationMode(manifest) {
  const mode =
    manifest?.anon_layer?.submission_identifier_derivation ?? "nonce_only";
  if (mode === "nonce_only" || mode === "nonce_plus_payload") {
    return mode;
  }
  return "nonce_only";
}

async function deriveSubmissionIdentifier({ nonceHex, payload, manifest }) {
  const mode = resolveSubmissionIdentifierDerivationMode(manifest);
  if (mode === "nonce_plus_payload") {
    const canonicalPayload = stableStringify(payload);
    return sha256hex(`${nonceHex}:${canonicalPayload}`);
  }
  return sha256hex(nonceHex);
}

async function buildVoteEnvelope({
  manifest,
  scopingId,
  payload,
  personId,
  identityInput = null,
  proofHash = null
}) {
  const nonceBytes = requiredWebCrypto().getRandomValues(new Uint8Array(32));
  const hexNonce = Array.from(nonceBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const submissionId = await deriveSubmissionIdentifier({
    nonceHex: hexNonce,
    payload,
    manifest
  });
  const submissionIdentifierDerivation =
    resolveSubmissionIdentifierDerivationMode(manifest);
  const identityResolver = createIdentityResolver(manifest);
  const identityCommitment = await identityResolver.createCommitment(
    identityInput ?? personId,
    {
      namespace: "stable_identity"
    }
  );
  const identityHash = await sha256hex(identityCommitment + scopingId);
  const resolvedProofHash =
    proofHash ??
    (await identityResolver.createProofHash(identityInput ?? personId, {
      scope: scopingId,
      audience: manifest?.app?.id ?? "shyprotocol"
    }));

  const data = {
    scoping_id: scopingId,
    identity_hash: identityHash,
    choices: Array.isArray(payload) ? payload : [payload],
    submission_nonce: hexNonce,
    submission_identifier_derivation: submissionIdentifierDerivation,
    timestamp: Math.floor(Date.now() / 1000),
    ...(resolvedProofHash ? { idv_proof_hash: resolvedProofHash } : {})
  };

  return {
    txJson: JSON.stringify({ type: 2, signature: "AQ==", data }),
    submissionId,
    hexNonce,
    identityHash
  };
}

// Generalized: verifyReceipt for submission
async function verifyReceipt(
  hexNonce,
  expectedPayload,
  submissions,
  { manifest = null } = {}
) {
  const submissionId = await deriveSubmissionIdentifier({
    nonceHex: hexNonce,
    payload: expectedPayload,
    manifest
  });
  return submissions.some(
    (sub) =>
      sub.submission_id === submissionId && sub.payload === expectedPayload
  );
}

function normalizeRuntimeSignals(runtimeSignals = {}) {
  const rawWebSession = runtimeSignals.webSession ?? {};
  const webSessionExpiry = Number(
    rawWebSession.expiresAt ?? rawWebSession.expires_at ?? 0
  );
  const webSessionApproved =
    Boolean(rawWebSession.approved) &&
    (!Number.isFinite(webSessionExpiry) ||
      webSessionExpiry <= 0 ||
      webSessionExpiry > Date.now());

  return {
    playIntegrity: {
      available: Boolean(runtimeSignals.playIntegrity?.available),
      passed: Boolean(runtimeSignals.playIntegrity?.passed)
    },
    deviceAttestation: {
      trusted: Boolean(runtimeSignals.deviceAttestation?.trusted)
    },
    network: {
      hostile: Boolean(runtimeSignals.network?.hostile)
    },
    hsm: {
      available: runtimeSignals.hsm?.available !== false
    },
    webSession: {
      approved: webSessionApproved,
      expiresAt:
        Number.isFinite(webSessionExpiry) && webSessionExpiry > 0
          ? webSessionExpiry
          : null,
      allowedFunctions: Array.isArray(
        rawWebSession.allowedFunctions ?? rawWebSession.allowed_functions
      )
        ? [
            ...(rawWebSession.allowedFunctions ??
              rawWebSession.allowed_functions)
          ]
        : []
    }
  };
}

function parseRuntimeValue(raw) {
  if (raw == null || raw === "") return null;
  if (typeof raw === "object") return raw;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function normalizeWebSessionMode(rawValue) {
  const value = parseRuntimeValue(rawValue);
  if (value == null) return { approved: false };
  if (typeof value === "object") {
    const approved = Boolean(value.approved);
    const expiresAt = Number(value.expiresAt ?? value.expires_at ?? 0);
    if (
      approved &&
      Number.isFinite(expiresAt) &&
      expiresAt > 0 &&
      expiresAt <= Date.now()
    ) {
      return { approved: false, expiresAt };
    }
    return {
      approved,
      expiresAt: Number.isFinite(expiresAt) && expiresAt > 0 ? expiresAt : null,
      allowedFunctions: Array.isArray(
        value.allowedFunctions ?? value.allowed_functions
      )
        ? [...(value.allowedFunctions ?? value.allowed_functions)]
        : []
    };
  }

  const normalized = String(value).toLowerCase();
  return {
    approved:
      normalized === "approved" ||
      normalized === "pass" ||
      normalized === "trusted"
  };
}

export function readBrowserRuntimeSignals(
  manifest = null,
  {
    globalKeys = ["__SHYWARE_RUNTIME_SIGNALS__"],
    storagePrefix = "shyware_runtime",
    legacyStorageKeys = {},
    query = null
  } = {}
) {
  if (typeof window === "undefined") {
    return {};
  }

  const params = query ?? new URLSearchParams(window.location.search);
  const appId = manifest?.app?.id ?? "default";
  const globalSignals =
    globalKeys
      .map((key) => window[key])
      .find((value) => value && typeof value === "object") ?? {};

  const getStoredMode = (suffix) => {
    const scopedKey = `${storagePrefix}:${appId}:${suffix}`;
    const legacyKey = legacyStorageKeys[suffix];
    const readStore = (store) => {
      if (!store || typeof store.getItem !== "function") return null;
      return (
        store.getItem(scopedKey) ??
        (legacyKey ? store.getItem(legacyKey) : null)
      );
    };

    return (
      readStore(globalThis.sessionStorage) ?? readStore(globalThis.localStorage)
    );
  };

  const playIntegrityMode =
    params.get("pi") ??
    getStoredMode("play_integrity") ??
    globalSignals.playIntegrity?.mode ??
    "unavailable";

  const deviceIntegrityMode =
    params.get("device") ??
    getStoredMode("device_attestation") ??
    globalSignals.deviceAttestation?.mode ??
    "untrusted";

  const networkMode =
    params.get("network") ??
    getStoredMode("network") ??
    globalSignals.network?.mode ??
    "public";

  const hsmMode =
    params.get("hsm") ??
    getStoredMode("hsm") ??
    globalSignals.hsm?.mode ??
    globalSignals.hsm?.available ??
    "available";

  const webSessionMode = params.get("web") ??
    params.get("web_session") ??
    getStoredMode("web_session_approval") ??
    globalSignals.webSession ??
    globalSignals.webSession?.mode ?? { approved: false };

  return {
    playIntegrity: {
      available: playIntegrityMode !== "unavailable",
      passed: playIntegrityMode === "pass"
    },
    deviceAttestation: {
      trusted: deviceIntegrityMode === "trusted"
    },
    network: {
      hostile: networkMode === "hostile"
    },
    hsm: {
      available: !(
        hsmMode === false ||
        String(hsmMode).toLowerCase() === "unavailable" ||
        String(hsmMode).toLowerCase() === "false"
      )
    },
    webSession: normalizeWebSessionMode(webSessionMode)
  };
}

function buildFallbackReasons(fallbacks, normalized) {
  const reasons = [];

  if (
    fallbacks.write_only_on_missing_play_integrity &&
    (!normalized.playIntegrity.available || !normalized.playIntegrity.passed)
  ) {
    reasons.push("missing_play_integrity");
  }

  if (fallbacks.write_only_on_hostile_network && normalized.network.hostile) {
    reasons.push("hostile_network");
  }

  if (
    fallbacks.write_only_on_untrusted_device_attestation &&
    !normalized.deviceAttestation.trusted
  ) {
    reasons.push("untrusted_device_attestation");
  }

  if (fallbacks.write_only_on_hsm_unavailable && !normalized.hsm.available) {
    reasons.push("hsm_unavailable");
  }

  if (
    fallbacks.write_only_on_missing_web_session_approval &&
    !normalized.webSession.approved
  ) {
    reasons.push("missing_web_session_approval");
  }

  return reasons;
}

export function resolveEffectivePosture(manifest, runtimeSignals = {}) {
  const normalized = normalizeRuntimeSignals(runtimeSignals);
  const deployment = manifest?.deployment ?? null;
  const defaultPosture = deployment?.default_posture ?? "recoverable";
  const fallbacks = deployment?.runtime_fallbacks ?? {};
  const fallbackReasons = buildFallbackReasons(fallbacks, normalized);

  // Claim 9 — Browser write-only enforcement (attestation-unavailable instantiation
  // of Claim 3). In a browser environment, Play Integrity and native device
  // attestation (App Attest, Play Integrity API) are structurally unavailable: there
  // is no attested execution environment capable of suppressing readback at the OS
  // layer. When neither trust signal is present the SDK enforces write-only posture
  // regardless of the manifest's runtime_fallbacks configuration — suppressing all
  // participant-facing receipt-readback and payload-visibility paths.
  // If the caller supplies explicit attestation signals (e.g. via a native web-view
  // bridge that proxies Play Integrity), those signals are respected and the
  // manifest-governed fallback logic takes over as normal.
  const isBrowser = typeof window !== "undefined";
  const browserAttestationUnavailable =
    isBrowser &&
    !normalized.playIntegrity.available &&
    !normalized.playIntegrity.passed &&
    !normalized.deviceAttestation.trusted;

  const effectiveFallbackReasons = [...fallbackReasons];
  if (
    browserAttestationUnavailable &&
    !effectiveFallbackReasons.includes("browser_attestation_unavailable")
  ) {
    effectiveFallbackReasons.push("browser_attestation_unavailable");
  }

  let effectivePosture =
    defaultPosture === "coercion_resistant" ? "write_only" : "recoverable";
  if (effectiveFallbackReasons.length > 0) {
    effectivePosture = "write_only";
  }

  return {
    configuredPosture: defaultPosture,
    effectivePosture,
    fallbackActive: effectiveFallbackReasons.length > 0,
    fallbackReasons: effectiveFallbackReasons,
    runtimeSignals: normalized,
    writeOnly: effectivePosture === "write_only"
  };
}

function resolveEffectiveReceiptPolicy(manifest, runtimeSignals = {}) {
  const posture = resolveEffectivePosture(manifest, runtimeSignals);
  const receipts = manifest?.receipts ?? null;
  if (!receipts) return null;

  if (!posture.writeOnly) {
    return {
      ...receipts,
      effective_user_access: receipts.user_access,
      write_only: false
    };
  }

  return {
    ...receipts,
    match_store: "none",
    user_access: "never",
    effective_user_access: "never",
    write_only: true
  };
}

function isManagedReceiptStore(matchStore) {
  return [
    "firestore_plaintext",
    "firestore_encrypted",
    "cockroach_plaintext",
    "cockroach_encrypted"
  ].includes(matchStore);
}

function buildAuthorityMatrix(manifest, runtimeSignals = {}) {
  const posture = resolveEffectivePosture(manifest, runtimeSignals);

  return [
    {
      authority: "voter_hostile_state",
      canonical_blockchain_read: "anonymous_public_state_only",
      canonical_blockchain_write: "ballot_submission_only",
      private_reconcile_read: posture.writeOnly ? "none" : "policy_gated",
      private_reconcile_write: "none"
    },
    {
      authority: "voter_safe_recovery_context",
      canonical_blockchain_read: "anonymous_public_state_only",
      canonical_blockchain_write: "none",
      private_reconcile_read: posture.writeOnly ? "none" : "policy_gated",
      private_reconcile_write: "none"
    },
    {
      authority: "reconciling_authority",
      canonical_blockchain_read: "anonymous_public_state_only",
      canonical_blockchain_write: "none",
      private_reconcile_read: posture.writeOnly ? "disabled" : "read_only",
      private_reconcile_write: "none"
    },
    {
      authority: "adversary_public_chain_only",
      canonical_blockchain_read: "anonymous_public_state_only",
      canonical_blockchain_write: "none",
      private_reconcile_read: "none",
      private_reconcile_write: "none"
    }
  ];
}

export function assertVotingManifest(shyconfig) {
  if (shyconfig?.contract_version !== VOTING_MANIFEST_CONTRACT_VERSION) {
    throw new Error(
      `shyconfig must declare contract_version=${VOTING_MANIFEST_CONTRACT_VERSION} for voting apps.`
    );
  }

  if (!shyconfig?.anon_layer?.black_box_required) {
    throw new Error(
      "shyconfig must require the anonymous layer as a black box."
    );
  }

  const requiredFlows = new Set(shyconfig.anon_layer.required_flows ?? []);
  for (const flow of [
    "poll_read",
    "ballot_build",
    "ballot_submit",
    "receipt_verify"
  ]) {
    if (!requiredFlows.has(flow)) {
      throw new Error(`shyconfig is missing required voting flow: ${flow}`);
    }
  }

  if (!shyconfig.identity || shyconfig.identity.provider === "none") {
    throw new Error(
      "shyconfig must declare a real identity provider for voting apps."
    );
  }

  if (!shyconfig.signing?.required) {
    throw new Error("shyconfig must require protocol signing for voting apps.");
  }

  if (shyconfig.signing.backend === "none") {
    throw new Error("shyconfig cannot disable signing for voting apps.");
  }

  if (["aws_kms", "aws_kms_x_aws_cloudhsm"].includes(shyconfig.signing.backend)) {
    if (
      !shyconfig.signing.validator_key_id ||
      !shyconfig.signing.tally_key_id
    ) {
      throw new Error(
        "Managed KMS voting apps must declare validator and tally key IDs."
      );
    }
  }

  if (!shyconfig.receipts?.match_store) {
    throw new Error("shyconfig must declare receipt handling for voting apps.");
  }

  if (!shyconfig.receipts?.double_vote_enforcement) {
    throw new Error(
      "shyconfig must declare duplicate-vote enforcement for voting apps."
    );
  }

  if (!shyconfig.deployment?.default_posture) {
    throw new Error(
      "shyconfig must declare deployment posture for voting apps."
    );
  }

  if (!shyconfig.deployment?.runtime_fallbacks) {
    throw new Error(
      "shyconfig must declare runtime fallback posture rules for voting apps."
    );
  }
}

export function createVotingClient({
  defaultBase = "/api",
  defaultSubmitBase = null,
  storageKey = "shyware_api_base",
  fetchImpl = globalThis.fetch?.bind(globalThis),
  getAuthHeaders = null,
  manifest = null
} = {}) {
  if (!fetchImpl) {
    throw new Error("fetch is required by the shyware voting client.");
  }

  let runtimeSignals = normalizeRuntimeSignals();
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

  async function get(path, { allowEmptyPolls = false } = {}) {
    let res;
    try {
      res = await fetchImpl(joinBaseAndPath(getBase(), path), {
        headers: await resolveHeaders()
      });
    } catch {
      if (allowEmptyPolls) return { polls: [] };
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

  async function buildUpdateFields({ scopingId, personId = "", identityInput = null, proofHash = null }) {
    const identityCommitment = await identityResolver.createCommitment(
      identityInput ?? personId,
      { namespace: "stable_identity" }
    );
    const identityHash = await sha256hex(identityCommitment + scopingId);
    const resolvedProofHash = proofHash ??
      (await identityResolver.createProofHash(identityInput ?? personId, {
        scope: scopingId,
        audience: manifest?.app?.id ?? "shyprotocol"
      }));
    const nonceBytes = requiredWebCrypto().getRandomValues(new Uint8Array(32));
    const submissionNonce = Array.from(nonceBytes).map(b => b.toString(16).padStart(2, "0")).join("");
    return {
      scoping_id: scopingId,
      new_submission_nonce: submissionNonce,
      identity_hash: identityHash,
      ...(resolvedProofHash ? { idv_proof_hash: resolvedProofHash } : {})
    };
  }

  return {
    initialize() {
      const posture = resolveEffectivePosture(manifest, runtimeSignals);
      return {
        contractVersion: manifest?.contract_version ?? null,
        appId: manifest?.app?.id ?? null,
        chainId: manifest?.app?.chain_id ?? null,
        apiBase: getBase(),
        submitBase: getSubmitBase(),
        storageKey,
        identity: manifest?.identity ?? null,
        identityProfile: identityResolver.profile,
        signing: manifest?.signing ?? null,
        deployment: manifest?.deployment ?? null,
        receipts: resolveEffectiveReceiptPolicy(manifest, runtimeSignals),
        posture,
        requiredFlows: manifest?.anon_layer?.required_flows ?? []
      };
    },
    getBase,
    setBase,
    getSubmitBase,
    setRuntimeSignals(signals = {}) {
      runtimeSignals = normalizeRuntimeSignals(signals);
      return this.getEffectivePosture();
    },
    getRuntimeSignals: () => runtimeSignals,
    getManifest: () => manifest,
    getConfiguredPosture: () => manifest?.deployment?.default_posture ?? null,
    getEffectivePosture: () =>
      resolveEffectivePosture(manifest, runtimeSignals),
    getReceiptPolicy: () =>
      resolveEffectiveReceiptPolicy(manifest, runtimeSignals),
    getAuthorityMatrix: () => buildAuthorityMatrix(manifest, runtimeSignals),
    identityResolver,
    createIdentityCommitment(input, options = {}) {
      return identityResolver.createCommitment(input, options);
    },
    createIdentityProofHash(input, options = {}) {
      return identityResolver.createProofHash(input, options);
    },
    normalizeManagedIdentity(status) {
      return identityResolver.normalizeManagedIdentity(status);
    },
    normalizeByoid(input) {
      return identityResolver.normalizeByoid(input);
    },
    getAllSubmissions: (type = "polls") =>
      get(`/${type}`, { allowEmptyPolls: true }),
    getSubmission: (type, id) => get(`/${type}/${id}`),
    getSubmissionTally: (type, id) => get(`/${type}/${id}/tally`),
    getSubmissionRecords: (type, id) => get(`/${type}/${id}/records`),
    getSubmissionParticipantCount: (type, id) =>
      get(`/${type}/${id}/participants`),
    getSubmissionConfirmedCount: (type, id) => get(`/${type}/${id}/confirms`),

    async buildVote({
      scopingId,
      payload,
      personId = "",
      identityInput = null,
      proofHash = null
    }) {
      if (!scopingId || !payload || (!personId?.trim() && !identityInput)) {
        throw new Error(
          "scopingId, payload, and a personId or identityInput are required."
        );
      }
      const envelope = await buildVoteEnvelope({
        manifest,
        scopingId,
        payload,
        personId: personId.trim(),
        identityInput,
        proofHash
      });
      const posture = resolveEffectivePosture(manifest, runtimeSignals);
      if (posture.writeOnly) {
        return { submissionId: envelope.submissionId, writeOnly: true };
      }
      return envelope;
    },

    submitVote: (txJson, type = "submissions") =>
      post(`/${type}`, { tx: txJson }),

    flushQueuedSubmissions: (type, id) => post(`/${type}/${id}/flush`, {}),

    async voteSubmission({
      scopingId,
      payload,
      personId = "",
      identityInput = null,
      proofHash = null
    }) {
      const envelope = await buildVoteEnvelope({
        manifest,
        scopingId,
        payload,
        personId: (personId ?? "").trim(),
        identityInput,
        proofHash
      });
      await post("/submissions", { tx: envelope.txJson });
      const posture = resolveEffectivePosture(manifest, runtimeSignals);
      if (posture.writeOnly) {
        return { submissionId: envelope.submissionId, writeOnly: true };
      }
      return envelope;
    },

    async rescindVote({ scopingId, personId = "", identityInput = null, proofHash = null }) {
      const fields = await buildUpdateFields({ scopingId, personId, identityInput, proofHash });
      return post("/ballots/update", { ...fields, new_choices: [] });
    },

    async replaceVote({ scopingId, newPayload, personId = "", identityInput = null, proofHash = null }) {
      const fields = await buildUpdateFields({ scopingId, personId, identityInput, proofHash });
      return post("/ballots/update", { ...fields, new_choices: [newPayload] });
    },
    verifyReceipt: (hexNonce, expectedPayload, submissions, options = {}) =>
      verifyReceipt(hexNonce, expectedPayload, submissions, {
        manifest,
        ...options
      }),
    async getPrivateReceipt(scopingId) {
      const posture = resolveEffectivePosture(manifest, runtimeSignals);
      if (posture.writeOnly) return null;
      const receiptPolicy = resolveEffectiveReceiptPolicy(
        manifest,
        runtimeSignals
      );
      if (!isManagedReceiptStore(receiptPolicy?.match_store)) {
        return null;
      }
      return get(`/submission/receipt/${scopingId}`);
    },
    async savePrivateReceipt(scopingId, receipt) {
      const posture = resolveEffectivePosture(manifest, runtimeSignals);
      if (posture.writeOnly) return null;
      const receiptPolicy = resolveEffectiveReceiptPolicy(
        manifest,
        runtimeSignals
      );
      if (!isManagedReceiptStore(receiptPolicy?.match_store)) {
        return null;
      }
      return post("/submission/receipt", {
        scopingId,
        payload: receipt.payload,
        submissionId: receipt.submissionId,
        submissionNonce: receipt.submissionNonce,
        identityHash: receipt.identityHash,
        submittedAt: receipt.submittedAt
      });
    },
    confirmReceipt: (scopingId) =>
      post("/submission/confirm", { scopingId }),

    checkSubmissionPresence: (submissionId) => get(`/vote_exists/${submissionId}`),

    getReattestationAudit: (scopingId) => get(`/reattestation_audit/${scopingId}`),

    getIdvAudit: (scopingId) => get(`/idv_audit/${scopingId}`),

    async getEligibilityActions({ scopingId, identityInput = null, personId = "" }) {
      const identityCommitment = await identityResolver.createCommitment(
        identityInput ?? personId,
        { namespace: "stable_identity" }
      );
      const identityHash = await sha256hex(identityCommitment + scopingId);
      return get(`/authority_actions/${scopingId}/${identityHash}`);
    }
  };
}

export function initializeFromShyConfig(shyconfig, options = {}) {
  assertVotingManifest(shyconfig);

  if (
    shyconfig.api?.requires_auth &&
    typeof options.getAuthHeaders !== "function"
  ) {
    throw new Error(
      "shyconfig requires authenticated voting API access, but no auth header provider was supplied."
    );
  }

  const client = createVotingClient({
    defaultBase: shyconfig.api?.base_url ?? "/api",
    defaultSubmitBase: shyconfig.api?.submit_base_url ?? null,
    storageKey:
      shyconfig.api?.storage_key ?? options.storageKey ?? "shyware_api_base",
    fetchImpl: options.fetchImpl,
    getAuthHeaders: options.getAuthHeaders,
    manifest: shyconfig
  });

  if (options.runtimeSignals) {
    client.setRuntimeSignals(options.runtimeSignals);
  }

  return client;
}
