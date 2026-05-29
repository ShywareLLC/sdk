import { normalizeByoidIdentity } from '../../providers/byoid.js'

function requiredWebCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API is required by the shyware identity client.")
  }
  return globalThis.crypto
}

async function sha256hex(value) {
  const payload = typeof value === "string" ? value : JSON.stringify(value)
  const bytes = new TextEncoder().encode(payload)
  const digest = await requiredWebCrypto().subtle.digest("SHA-256", bytes)
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("")
}

function trim(value) {
  return typeof value === "string" ? value.trim() : ""
}

function normalizeObjectInput(input = {}) {
  return {
    value: trim(input.value),
    walletAddress: trim(input.walletAddress),
    journeyId: trim(input.journeyId),
    personId: trim(input.personId),
    issuerDid: trim(input.issuerDid),
    presentationNonce: trim(input.presentationNonce),
    sourceProvider: trim(input.sourceProvider),
    proofHash: trim(input.proofHash),
    verificationStatus: trim(input.verificationStatus),
  }
}

function getManifestIdentity(manifest = {}) {
  return manifest.identity ?? { provider: "none", mode: "manual_demo" }
}

export function getIdentityProfile(manifest = {}) {
  const identity = getManifestIdentity(manifest)
  const provider = identity.provider ?? "none"
  const mode = identity.mode ?? "manual_demo"
  const issuerDid = trim(identity.issuer_did)
  const workflowId = trim(identity.workflow_id)
  const recommendedIdv = trim(identity.recommended_idv || "none")
  const byoidPolicy = trim(identity.byoid_policy || "disallowed")
  const kycRequired = Boolean(identity.kyc_required)
  const byoidLabel = trim(identity.byoid_label || "Bring your own verified identity")
  const policy = {
    recommendedIdv,
    byoidPolicy,
    kycRequired,
    byoidLabel,
    canBypassWithByoid: byoidPolicy === "allowed" || byoidPolicy === "required",
    requiresManagedIdv: kycRequired && recommendedIdv !== "none" && byoidPolicy !== "required",
  }

  if (provider === "wallet") {
    return {
      provider,
      mode,
      workflowId,
      issuerDid,
      inputLabel: "Wallet address",
      placeholder: "0xabc123...",
      proofLabel: "Wallet proof",
      supportsAttestedIdentity: false,
      ...policy,
    }
  }

  return {
    provider,
    mode,
    workflowId,
    issuerDid,
    inputLabel: "Verified person or journey id",
    placeholder: "journey-id or stable person id",
    proofLabel: "Verification proof",
    supportsAttestedIdentity: true,
    ...policy,
  }
}

export function getIdentityPolicy(manifest = {}) {
  const profile = getIdentityProfile(manifest)
  return {
    provider: profile.provider,
    recommendedIdv: profile.recommendedIdv,
    byoidPolicy: profile.byoidPolicy,
    kycRequired: profile.kycRequired,
    byoidLabel: profile.byoidLabel,
    canBypassWithByoid: profile.canBypassWithByoid,
    requiresManagedIdv: profile.requiresManagedIdv,
  }
}

function requireIdentityValue(provider, value, fallbackError) {
  if (!value) {
    throw new Error(fallbackError ?? `${provider} identity input is required.`)
  }
  return value
}

function normalizeProviderInput(manifest = {}, input) {
  const normalized = typeof input === "string" ? null : normalizeObjectInput(input)

  if (normalized?.sourceProvider === "byoid") {
    return normalizeByoidIdentity(normalized)
  }

  if (typeof input === "string") {
    const value = trim(input)
    const provider = getManifestIdentity(manifest).provider ?? "none"
    if (provider === "wallet") return { walletAddress: value }
    return { personId: value, journeyId: value }
  }

  return normalized ?? normalizeObjectInput(input)
}

function buildStableIdentitySource(manifest = {}, input = {}) {
  const provider = (getManifestIdentity(manifest).provider ?? "none")
  const normalized = normalizeProviderInput(manifest, input)

  if (provider === "wallet") {
    return requireIdentityValue(
      provider,
      trim(normalized.walletAddress || normalized.value).toLowerCase(),
      "walletAddress is required for wallet commitments.",
    )
  }

  return requireIdentityValue(
    provider,
    trim(normalized.personId || normalized.journeyId || normalized.value),
    "personId or journeyId is required for verified identity commitments.",
  )
}

export async function createIdentityCommitment(manifest = {}, input, { scope = "", namespace = "identity" } = {}) {
  const identity = getManifestIdentity(manifest)
  const provider = identity.provider ?? "none"
  const stableSource = buildStableIdentitySource(manifest, input)
  const parts = [namespace, provider, stableSource]
  if (scope) parts.push(String(scope))
  return sha256hex(parts.join(":"))
}

export async function createIdentityProofHash(manifest = {}, input, { scope = "", audience = "" } = {}) {
  const identity = getManifestIdentity(manifest)
  const provider = identity.provider ?? "none"
  const normalized = normalizeProviderInput(manifest, input)

  if (provider === "wallet" || provider === "none") return null

  const stableSource = buildStableIdentitySource(manifest, normalized)
  const issuerDid = trim(normalized.issuerDid || identity.issuer_did)
  const workflowId = trim(identity.workflow_id)
  const presentationNonce = trim(normalized.presentationNonce)
  return sha256hex(["proof", provider, stableSource, workflowId, issuerDid, scope, audience, presentationNonce].join(":"))
}

export function normalizeIdentityInput(manifest = {}, input, { byoid = false } = {}) {
  const policy = getIdentityPolicy(manifest)

  if (byoid) {
    if (!policy.canBypassWithByoid) {
      throw new Error("BYOID is not allowed by this deployment.")
    }
    return normalizeByoidIdentity(input)
  }

  return normalizeProviderInput(manifest, input)
}

export function createIdentityResolver(manifest = {}) {
  const profile = getIdentityProfile(manifest)
  const policy = getIdentityPolicy(manifest)
  return {
    profile,
    policy,
    createCommitment(input, options = {}) {
      return createIdentityCommitment(manifest, normalizeIdentityInput(manifest, input), options)
    },
    createProofHash(input, options = {}) {
      return createIdentityProofHash(manifest, normalizeIdentityInput(manifest, input), options)
    },
    normalizeManagedIdentity(status) {
      // Call your IDV provider's extraction function before passing status here.
      // e.g. extractDiditIdentity(rawStatus) → pass result to this method.
      return normalizeIdentityInput(manifest, status)
    },
    normalizeByoid(input) {
      return normalizeIdentityInput(manifest, input, { byoid: true })
    },
  }
}
