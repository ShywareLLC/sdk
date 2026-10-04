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

// Fetches a fresh beacon (recent canonical block hash + height) from the
// relay's own CometBFT-backed /health endpoint. Required on every ballot:
// the Go core's ValidateBeacon does an exact (post-lowercasing) string
// comparison against its own beacon window, and rejects anything stale or
// malformed (ShywareLLC/core domain/state -- see VotingClient.swift's
// fetchBeacon for the exact iOS-side equivalent this mirrors).
async function fetchBeacon(getFn) {
  const status = await getFn("/health");
  const height = Number(status?.result?.sync_info?.latest_block_height);
  if (!Number.isFinite(height)) {
    throw new Error("Invalid latest_block_height in /health response");
  }
  const hash = String(status?.result?.sync_info?.latest_block_hash ?? "").toLowerCase();
  return { hash, height };
}

// Requests idv_attestation_sig from the deployment's own IDV attestation
// enclave (identity.attestation_service_base_url) -- an independent service
// that re-verifies the Didit session against Didit's real API before
// signing, so this device/app never holds (and the Populist backend never
// needs to hold) the enclave's private signing key. Mirrors
// EnclaveAttestationClient.attest in ShywareLLC/sdk-ios exactly, except:
// browsers have no public API for certificate/public-key pinning on a
// fetch() call, so unlike the iOS client this cannot pin the enclave's
// certificate -- it relies on ordinary browser TLS/CA trust instead. That
// is a real, accepted limitation of the browser platform, not an oversight;
// note it rather than silently claiming parity with the pinned iOS path.
// Returns { idvAttestationSigHex, identityHash } or null if no enclave/
// session is configured. identityHash is the enclave's own person-stable
// value (sha256(didit_document_key || poll_id), computed inside the
// enclave from Didit's id_verification document data -- Didit's API has no
// "person_id" field, see ShywareLLC/idv-enclave's /attest implementation)
// -- it must be echoed back on the wire as data.identity_hash so the chain
// can verify the enclave's signature, which covers it; the chain has no
// way to recompute this value itself.
async function attestWithEnclave({ manifest, sessionId, voterPubKeyHex, pollId }) {
  const baseURL = manifest?.identity?.attestation_service_base_url;
  if (!baseURL || !sessionId) return null;
  const res = await fetch(`${baseURL.replace(/\/$/, "")}/attest`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_id: sessionId,
      voter_pub_key: voterPubKeyHex,
      poll_id: pollId
    })
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error ?? `Enclave attestation HTTP ${res.status}`);
  }
  const decoded = await res.json();
  return { idvAttestationSigHex: decoded.idv_attestation_sig, identityHash: decoded.identity_hash };
}

function hexToBase64(hexStr) {
  const bytes = new Uint8Array(hexStr.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hexStr.substr(i * 2, 2), 16);
  }
  return btoa(String.fromCharCode(...bytes));
}

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

/// Builds a TxTypeBallotCast envelope matching the real server's wire schema
/// exactly (ShywareLLC/core protocol/tx/tx.go BallotCastData) -- field names,
/// the oracle-forgery-prevention device signature, the beacon, and the IDV
/// attestation are all required by the Go core's validateBallotCast; a
/// previous version of this function sent none of them (a client-computed
/// identity_hash instead, which the server never reads off the wire -- it
/// always re-derives identity_hash itself from voter_pub_key) and would
/// have been rejected outright by the real relay. Mirrors
/// VotingClient.buildBallot in ShywareLLC/sdk-ios field-for-field.
async function buildVoteEnvelope({
  manifest,
  scopingId,
  payload,
  diditSessionId = null,
  partitionId = undefined,
  getFn,
  keypair = null
}) {
  const nonceBytes = requiredWebCrypto().getRandomValues(new Uint8Array(32));
  const hexNonce = bufToHex(nonceBytes);
  const choices = Array.isArray(payload) ? payload : [payload];

  // Per-poll Ed25519 keypair -- the IDV provider never holds this private
  // key (oracle-forgery prevention), only the resulting voter_pub_key/
  // voter_sig ever leave this function.
  //
  // Pass an existing keypair (e.g. persisted in localStorage, one per
  // (user, poll)) rather than relying on the default fresh-every-call
  // generation below whenever a call might be retried -- generating a new
  // keypair on every attempt means every retry after a transient failure
  // (network blip, an unrelated downstream error) looks like a *different*
  // voter to the IDV attestation enclave's one-time-use-per-poll replay
  // guard, permanently orphaning that poll for the underlying Didit
  // session on the very first failed attempt. Found live 2026-10-03 on the
  // iOS client, which had exactly this bug (VotingClient.buildBallot
  // generated Curve25519.Signing.PrivateKey() fresh every call) --
  // mirroring it here would just move the same bug to the web client.
  if (!keypair) {
    keypair = await requiredWebCrypto().subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"]
    );
  }
  const pubKeyRaw = await requiredWebCrypto().subtle.exportKey("raw", keypair.publicKey);
  const voterPubKeyHex = bufToHex(pubKeyRaw);
  const deviceMsg = new TextEncoder().encode(`${hexNonce}:${scopingId}`);
  const voterSigBuf = await requiredWebCrypto().subtle.sign("Ed25519", keypair.privateKey, deviceMsg);
  const voterSigBase64 = bufToBase64(voterSigBuf);

  const beacon = await fetchBeacon(getFn);

  const data = {
    scoping_id: scopingId,
    choices,
    submission_nonce: hexNonce,
    beacon_block_hash: beacon.hash,
    beacon_block_height: beacon.height,
    timestamp: Math.floor(Date.now() / 1000),
    voter_pub_key: voterPubKeyHex,
    voter_sig: voterSigBase64,
    ...(partitionId ? { partition_id: partitionId } : {})
  };

  // identity_hash is enclave-attested (sha256(didit_document_key || poll_id),
  // computed inside the enclave -- this client never sees the document data
  // behind it), required on the wire for the chain to verify
  // idv_attestation_sig, which covers it: the chain has no way to recompute
  // this value itself. Also used for local receipt bookkeeping, same value.
  let identityHash = null;
  if (diditSessionId) {
    const attestation = await attestWithEnclave({
      manifest,
      sessionId: diditSessionId,
      voterPubKeyHex,
      pollId: scopingId
    });
    if (attestation?.idvAttestationSigHex) {
      data.idv_attestation_sig = hexToBase64(attestation.idvAttestationSigHex);
      data.didit_session_id = diditSessionId;
      data.identity_hash = attestation.identityHash;
      identityHash = attestation.identityHash;
    }
  }

  return {
    txJson: JSON.stringify({ type: 2, signature: "AQ==", data }),
    submissionId: await sha256hex(hexNonce),
    hexNonce,
    identityHash,
    voterPubKeyHex
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

  // serverPosture is set by the app after calling the public posture endpoint
  // (GET /api/v1/posture), which resolves the participant's country from IP and
  // returns the operator-configured posture for that country. Pass
  // { serverPosture: 'write_only' } when the server reports a write-only country.
  // 'write_only' escalates over the manifest default; 'recoverable' does not
  // downgrade a manifest coercion_resistant default.
  const serverPosture =
    runtimeSignals.serverPosture === 'write_only' ? 'write_only' : null;

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
    serverPosture,
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

  // Server-reported country posture: escalates to write_only when the operator
  // has configured this country as write-only via the posture dashboard.
  // Never downgrades — a manifest coercion_resistant default is unchanged.
  if (normalized.serverPosture === "write_only") {
    effectivePosture = "write_only";
  }

  return {
    configuredPosture: defaultPosture,
    effectivePosture,
    fallbackActive: effectiveFallbackReasons.length > 0,
    fallbackReasons: effectiveFallbackReasons,
    runtimeSignals: normalized,
    serverPostureActive: normalized.serverPosture === "write_only",
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

  // Claim 56 — operator-separation enforcement.
  // The RA must be a different legal and operational entity from the canonical ledger operator.
  // Two symmetric failure modes exist:
  //   (a) self_hosted: the deployment operator runs the ABCI node. If the same entity also
  //       runs the RA (ledger_operator), or omits the RA declaration, the chain collapses.
  //       Valid RA operators: 'shyware' or 'independent_third_party'.
  //   (b) community/hosted_dedicated: Shyware runs the canonical ledger. If Shyware also
  //       runs the RA ('shyware'), the chain collapses. The RA must be the deployment
  //       operator ('operator') or a contracted third party ('independent_third_party').
  const tier = shyconfig.deployment?.deployment_tier;
  const raOperator = shyconfig.deployment?.reconcile_authority?.operator;

  if (tier === "self_hosted") {
    if (!raOperator) {
      throw new Error(
        "self_hosted voting deployments must declare deployment.reconcile_authority.operator. " +
        "The RA must be a different entity from the canonical ledger operator (Claim 56). " +
        "Use 'shyware' (Shyware hosts your RA) or 'independent_third_party'."
      );
    }
    if (raOperator === "ledger_operator" || raOperator === "operator") {
      throw new Error(
        `self_hosted voting deployments cannot set reconcile_authority.operator to '${raOperator}'. ` +
        "The deployment operator is the ledger operator in a BYOL configuration. " +
        "An entity running both the ABCI node and the RA can join identity_hash → submission_id " +
        "without any collusion event, eliminating anonymity-to-operator. " +
        "Use 'shyware' or 'independent_third_party'."
      );
    }
  }

  if (tier === "community" || tier === "hosted_dedicated") {
    if (raOperator === "shyware") {
      throw new Error(
        `${tier} voting deployments cannot set reconcile_authority.operator to 'shyware'. ` +
        "Shyware is the canonical ledger operator in this tier. " +
        "An entity running both the canonical chain and the RA can join identity_hash → submission_id " +
        "without any collusion event, eliminating anonymity-to-operator. " +
        "Use 'operator' (you run your own RA) or 'independent_third_party'."
      );
    }
    if (raOperator === "ledger_operator") {
      throw new Error(
        `${tier} voting deployments cannot set reconcile_authority.operator to 'ledger_operator'. ` +
        "Use 'operator' or 'independent_third_party'."
      );
    }
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

  /// Builds a TxTypeUpdateBallot envelope matching the real server's wire
  /// schema (ShywareLLC/core protocol/tx/tx.go BallotUpdateData). The
  /// previous version (buildUpdateFields) had the exact same bug
  /// buildVoteEnvelope had before being fixed: no voter_pub_key/voter_sig/
  /// beacon, a client-computed identity_hash the server never reads off
  /// BallotUpdateData at all. `newChoices: []` represents a rescission.
  ///
  /// `keypair` is required (not optional, unlike buildVoteEnvelope's default
  /// generate-if-absent) -- it must be the SAME keypair used for the
  /// original cast, since the chain re-derives identity_hash from
  /// voter_pub_key; a different key here would register as a different
  /// voter, not an update to the existing one.
  async function buildUpdateEnvelope({
    manifest,
    scopingId,
    oldSubmissionId,
    newChoices,
    diditSessionId = null,
    getFn,
    keypair
  }) {
    if (!keypair) {
      throw new Error("buildUpdateEnvelope requires the same keypair used to cast the original ballot.");
    }
    const nonceBytes = requiredWebCrypto().getRandomValues(new Uint8Array(32));
    const hexNonce = bufToHex(nonceBytes);
    const pubKeyRaw = await requiredWebCrypto().subtle.exportKey("raw", keypair.publicKey);
    const voterPubKeyHex = bufToHex(pubKeyRaw);
    // "update:" prefix -- matches ballotrules.BallotUpdateDeviceSigMessage
    // in ShywareLLC/core/protocol/ballotrules/ballotrules.go, distinguishing
    // an update signature from a cast signature so one can't be replayed as
    // the other.
    const deviceMsg = new TextEncoder().encode(`update:${hexNonce}:${scopingId}`);
    const voterSigBuf = await requiredWebCrypto().subtle.sign("Ed25519", keypair.privateKey, deviceMsg);

    const beacon = await fetchBeacon(getFn);

    const data = {
      scoping_id: scopingId,
      old_submission_id: oldSubmissionId,
      new_submission_nonce: hexNonce,
      beacon_block_hash: beacon.hash,
      beacon_block_height: beacon.height,
      new_choices: newChoices,
      timestamp: Math.floor(Date.now() / 1000),
      voter_pub_key: voterPubKeyHex,
      voter_sig: bufToBase64(voterSigBuf)
    };

    // identity_hash is enclave-attested -- see buildVoteEnvelope's identical
    // comment above.
    if (diditSessionId) {
      const attestation = await attestWithEnclave({
        manifest,
        sessionId: diditSessionId,
        voterPubKeyHex,
        pollId: scopingId
      });
      if (attestation?.idvAttestationSigHex) {
        data.idv_attestation_sig = hexToBase64(attestation.idvAttestationSigHex);
        data.didit_session_id = diditSessionId;
        data.identity_hash = attestation.identityHash;
      }
    }

    return {
      txJson: JSON.stringify({ type: 6, signature: "AQ==", data }),
      submissionId: await sha256hex(hexNonce),
      hexNonce
    };
  }

  return {
    initialize() {
      const posture = resolveEffectivePosture(manifest, runtimeSignals);
      const ra = manifest?.deployment?.reconcile_authority ?? null;
      return {
        contractVersion: manifest?.contract_version ?? null,
        appId: manifest?.app?.id ?? null,
        chainId: manifest?.app?.chain_id ?? null,
        apiBase: getBase(),
        submitBase: getSubmitBase(),
        raEndpoint: ra?.endpoint ?? getBase(),
        raOperator: ra?.operator ?? null,
        deploymentTier: manifest?.deployment?.deployment_tier ?? null,
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
    // Path suffixes below are matched against the real relay's actual routes
    // (ShywareLLC/core api/server/router.go) -- "/records" and
    // "/participants" were never real routes on this relay; the real ones
    // are "/votes" and "/voters".
    getAllSubmissions: (type = "polls") =>
      get(`/${type}`, { allowEmptyPolls: true }),
    getSubmission: (type, id) => get(`/${type}/${id}`),
    getSubmissionTally: (type, id) => get(`/${type}/${id}/tally`),
    getSubmissionRecords: (type, id) => get(`/${type}/${id}/votes`),
    getSubmissionParticipantCount: (type, id) =>
      get(`/${type}/${id}/voters`),
    getSubmissionConfirmedCount: (type, id) => get(`/${type}/${id}/confirms`),

    // personId/identityInput/proofHash were accepted here historically but
    // never actually reached the wire -- the Go core's BallotCastData has no
    // identity_hash field at all; it always re-derives identity_hash itself
    // from voter_pub_key. For the default Didit-attestation embodiment
    // (identity.provider: "didit"), the real identity-binding input the
    // server needs is diditSessionId, passed to the IDV attestation enclave.
    // Other identity modes (wallet, identus) are not yet wired into this
    // corrected envelope -- narrowing this fix to the embodiment this
    // deployment actually uses rather than guessing at the other two.
    async buildVote({ scopingId, payload, diditSessionId = null, partitionId, keypair = null }) {
      if (!scopingId || !payload) {
        throw new Error("scopingId and payload are required.");
      }
      const envelope = await buildVoteEnvelope({
        manifest,
        scopingId,
        payload,
        diditSessionId,
        partitionId,
        getFn: get,
        keypair
      });
      const posture = resolveEffectivePosture(manifest, runtimeSignals);
      if (posture.writeOnly) {
        return { writeOnly: true };
      }
      return envelope;
    },

    // Defaults to "ballots" -- the real relay's actual route
    // (ShywareLLC/core api/server/router.go: POST /ballots). The previous
    // default, "submissions", is not a route this relay has at all.
    submitVote: (txJson, type = "ballots") =>
      post(`/${type}`, { tx: txJson }),

    flushQueuedSubmissions: (type, id) => post(`/${type}/${id}/flush`, {}),

    // Recovery index: looks up every (poll_id, identity_hash) pair the
    // CALLER'S OWN Firebase account has used (server-verified from the
    // caller's own auth header, not a client-supplied id) -- a recovery aid
    // for the rare case where Didit's id_verification document matching
    // produces a different identity_hash for the same real person on a
    // later device. See ShywareLLC/core's UserIdentityIndexer.
    listMyIdentities: () => post("/recovery/identities", {}),

    async voteSubmission({ scopingId, payload, diditSessionId = null, partitionId, keypair = null }) {
      const envelope = await buildVoteEnvelope({
        manifest,
        scopingId,
        payload,
        diditSessionId,
        partitionId,
        getFn: get,
        keypair
      });
      await post("/ballots", { tx: envelope.txJson });
      const posture = resolveEffectivePosture(manifest, runtimeSignals);
      if (posture.writeOnly) {
        return { writeOnly: true };
      }
      return envelope;
    },

    // Device-receipt path (matches the real relay's two supported paths for
    // POST /ballots/update): the client already holds oldSubmissionId from
    // its own local receipt, so it builds and signs the full envelope
    // itself rather than sending bare fields for the server to reconcile.
    async rescindVote({ scopingId, oldSubmissionId, diditSessionId = null, keypair }) {
      const envelope = await buildUpdateEnvelope({ manifest, scopingId, oldSubmissionId, newChoices: [], diditSessionId, getFn: get, keypair });
      await post("/ballots/update", { tx: envelope.txJson });
      return envelope;
    },

    async replaceVote({ scopingId, oldSubmissionId, newPayload, diditSessionId = null, keypair }) {
      const envelope = await buildUpdateEnvelope({ manifest, scopingId, oldSubmissionId, newChoices: [newPayload], diditSessionId, getFn: get, keypair });
      await post("/ballots/update", { tx: envelope.txJson });
      return envelope;
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
    // Matches the real route exactly: POST /polls/{poll_id}/confirm, no
    // request body (scopingId is the path parameter, not a body field).
    // The previous version posted to a path ("/submission/confirm") that
    // isn't a route this relay has at all.
    confirmReceipt: (scopingId) => post(`/polls/${scopingId}/confirm`, {}),

    // checkSubmissionPresence / getReattestationAudit / getIdvAudit /
    // getEligibilityActions below call routes that do not exist anywhere in
    // the currently deployed relay (ShywareLLC/core api/server/router.go's
    // route list is exhaustive: /health, /polls, /polls/{id}[/tally|/votes|
    // /voters|/confirms|/confirm|/flush], /ballots, /ballots/update -- no
    // /vote_exists, /reattestation_audit, /idv_audit, or /authority_actions
    // route exists). These are left in place rather than silently pointed
    // at a guessed path, since no server-side equivalent exists yet to
    // guess at; calling any of them today will 404. Building the
    // corresponding Go endpoints is a separate, larger task, not a client-
    // side wiring fix.
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
