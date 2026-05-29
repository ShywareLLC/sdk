function trim(value) {
  return typeof value === "string" ? value.trim() : ""
}

export function normalizeByoidIdentity(input = {}) {
  if (typeof input === "string") {
    return {
      sourceProvider: "byoid",
      value: trim(input),
    }
  }

  return {
    sourceProvider: "byoid",
    value: trim(input.value),
    subjectId: trim(input.subjectId),
    credentialId: trim(input.credentialId),
    walletAddress: trim(input.walletAddress),
    personId: trim(input.personId),
    journeyId: trim(input.journeyId),
    proofHash: trim(input.proofHash),
    issuerDid: trim(input.issuerDid),
  }
}
