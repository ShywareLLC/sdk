export function resolveFetch(fetchImpl = globalThis.fetch?.bind(globalThis)) {
  if (!fetchImpl) {
    throw new Error("fetch is required for Didit identity operations.")
  }
  return fetchImpl
}

function trim(value) {
  return typeof value === "string" ? value.trim() : ""
}

function normalizeBase(baseUrl = "") {
  return String(baseUrl || "").endsWith("/") ? String(baseUrl).slice(0, -1) : String(baseUrl || "")
}

function buildHeaders(idToken, extraHeaders = {}) {
  return {
    ...extraHeaders,
    ...(idToken ? { Authorization: `Bearer ${idToken}` } : {}),
  }
}

export async function createDiditSession(
  {
    baseUrl,
    idToken,
    verificationType = "id_verification",
    metadata = {},
    platform = "web",
  },
  { fetchImpl } = {},
) {
  const response = await resolveFetch(fetchImpl)(`${normalizeBase(baseUrl)}/api/didit/create-session`, {
    method: "POST",
    headers: buildHeaders(idToken, { "Content-Type": "application/json" }),
    body: JSON.stringify({
      idToken,
      verificationType,
      metadata,
      platform,
    }),
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({}))
    throw new Error(error.error || "Failed to create Didit verification session.")
  }

  const data = await response.json()
  return {
    sessionId: data.sessionId,
    sessionUrl: data.sessionUrl,
    raw: data,
  }
}

export async function getDiditSessionStatus(
  {
    baseUrl,
    idToken,
    sessionId,
  },
  { fetchImpl } = {},
) {
  const response = await resolveFetch(fetchImpl)(`${normalizeBase(baseUrl)}/api/didit/status/${sessionId}`, {
    method: "GET",
    headers: buildHeaders(idToken),
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({}))
    throw new Error(error.error || "Failed to fetch Didit verification status.")
  }

  return response.json()
}

export function extractDiditIdentity(status = {}) {
  const stableId =
    trim(status.personId) ||
    trim(status.person_id) ||
    trim(status.stablePersonId) ||
    trim(status.user?.personId) ||
    trim(status.user?.person_id) ||
    trim(status.subjectId)

  const journeyId =
    trim(status.journeyId) ||
    trim(status.journey_id) ||
    trim(status.sessionId) ||
    trim(status.session_id)

  const proofHash =
    trim(status.didit_proof_hash) ||
    trim(status.proofHash) ||
    trim(status.proof_hash)

  return {
    sourceProvider: "didit",
    personId: stableId,
    journeyId,
    proofHash,
    verificationStatus: trim(status.status) || "unknown",
    raw: status,
  }
}
