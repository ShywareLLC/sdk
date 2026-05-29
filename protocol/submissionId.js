/**
 * Claim 10: Beacon-conditioned submission identifier.
 *
 * The payload-free submission identifier is derived as:
 *   submissionId = H(canonicalBlockHash || submissionNonce)
 *
 * This ensures that any party with the canonical ledger can verify the identifier
 * was conditioned on a block hash committed before the submission session began —
 * meaning the identifier could not have been fabricated before that block was known.
 * A fabricated identifier (derived before the referenced block hash was public) is
 * structurally distinguishable from a legitimately derived one.
 *
 * The nonce is caller-generated (device random). The beacon is the latest committed
 * block hash at submission time, fetched from the ledger adapter.
 *
 * Claim 24: The submissionId derivation path shares no input with the identity
 * commitment derivation path (H(uid || scopingId)). Independence is enforced at the
 * call site — never pass uid or identity material into deriveSubmissionId.
 */

/**
 * Derive a beacon-conditioned submission identifier.
 * @param {string} canonicalBlockHash  — latest committed block hash (hex string)
 * @param {Uint8Array|string} nonce    — per-submission random nonce (32 bytes recommended)
 * @returns {Promise<string>}          — hex-encoded submission identifier
 */
export async function deriveSubmissionId(canonicalBlockHash, nonce) {
  const nonceHex = nonce instanceof Uint8Array
    ? Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join('')
    : String(nonce);
  const input = `${canonicalBlockHash}:${nonceHex}`;
  const buf = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Derive the identity commitment for a participant within a specific scoping identifier.
 * Claim 25: includes scopingId so the same participant's commitment is unlinkable
 * across different transaction-scoping identifiers.
 *
 * @param {string} participantId  — stable participant identifier (e.g. uid from IDV)
 * @param {string} scopingId      — transaction-scoping identifier (e.g. dispatch ID)
 * @returns {Promise<string>}     — hex-encoded identity hash
 */
export async function deriveIdentityHash(participantId, scopingId) {
  const input = `${participantId}|${scopingId}`;
  const buf = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Generate a fresh submission nonce.
 * @returns {Uint8Array} 32 random bytes
 */
export function generateSubmissionNonce() {
  return crypto.getRandomValues(new Uint8Array(32));
}
