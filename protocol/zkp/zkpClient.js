/**
 * Browser ZK client for the shyware NullifierCircuit.
 *
 * Wraps the Go WASM prover (zk-prover.wasm) and exposes a clean async API
 * for device-secret management, commitment/nullifier computation, and ZK
 * submission envelope construction.
 *
 * Setup (one-time per page load):
 *
 *   import { initZKProver, buildZKSubmissionEnvelope, getOrCreatePersonSecret } from "./zkpClient.js"
 *
 *   // Requires wasm_exec.js loaded in the page first:
 *   //   <script src="/static/wasm_exec.js"></script>
 *   await initZKProver("/static/zk-prover.wasm", "/static/nullifier_pk.bin")
 *
 * Enrollment (once per participant, before first submission):
 *
 *   const personSecret = getOrCreatePersonSecret()
 *   const commitment   = await computeCommitment(personSecret)
 *   // Submit commitment to Didit — Didit signs sha256(commitment || submission_id)
 *   // and returns diditCommitmentSig (Ed25519, base64) for each submission.
 *
 * Submission:
 *
 *   const envelope = await buildZKSubmissionEnvelope({
 *     submissionId, payload, personSecret, diditCommitmentSigBase64
 *   })
 *   await fetch("/api/submissions", { method: "POST", body: JSON.stringify({ tx: envelope.txJson }) })
 */

const PERSON_SECRET_PREFIX = "shyware_zk_person_secret";
const PROVER_READY_POLL_INTERVAL_MS = 50;
const PROVER_READY_TIMEOUT_MS = 30_000;

let _provingKeyBase64 = null;
let _wasmInitialized = false;

// ── Internal helpers ────────────────────────────────────────────────────────

function requiredWebCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API is required by zkpClient.");
  }
  return globalThis.crypto;
}

async function sha256hex(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await requiredWebCrypto().subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function assertProverReady() {
  if (!_wasmInitialized || !globalThis.shywareZKReady) {
    throw new Error(
      "ZK prover not initialized. Call initZKProver(wasmUrl, pkUrl) before using zkpClient."
    );
  }
}

function callWasm(fn, ...args) {
  assertProverReady();
  const result = fn(...args);
  if (!result.ok) {
    throw new Error("ZK WASM error: " + result.error);
  }
  return result.value;
}

// ── WASM loader ──────────────────────────────────────────────────────────────

async function loadGoWasm(wasmUrl) {
  if (typeof Go === "undefined") {
    throw new Error(
      'Go WASM runtime not found. Add <script src="/static/wasm_exec.js"></script> before zkpClient.'
    );
  }
  const go = new Go();
  const result = await WebAssembly.instantiateStreaming(
    fetch(wasmUrl),
    go.importObject
  );
  go.run(result.instance); // non-blocking: WASM runs in event loop

  // Wait until the WASM sets shywareZKReady = true (or timeout).
  const deadline = Date.now() + PROVER_READY_TIMEOUT_MS;
  await new Promise((resolve, reject) => {
    const check = () => {
      if (globalThis.shywareZKReady) return resolve();
      if (Date.now() > deadline)
        return reject(new Error("ZK WASM failed to become ready within 30s."));
      setTimeout(check, PROVER_READY_POLL_INTERVAL_MS);
    };
    check();
  });
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Initialize the ZK prover. Must be called once before any other zkpClient
 * function. Loads the WASM binary and the Groth16 proving key.
 *
 * @param {string} wasmUrl       - URL to zk-prover.wasm
 * @param {string} provingKeyUrl - URL to nullifier_pk.bin
 */
export async function initZKProver(wasmUrl, provingKeyUrl) {
  await loadGoWasm(wasmUrl);

  const pkRes = await fetch(provingKeyUrl);
  if (!pkRes.ok) {
    throw new Error(
      `Failed to fetch proving key from ${provingKeyUrl}: HTTP ${pkRes.status}`
    );
  }
  const pkBytes = await pkRes.arrayBuffer();
  // Convert to base64 for the WASM prove() call.
  _provingKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(pkBytes)));
  _wasmInitialized = true;
}

/**
 * Generate a fresh person_secret. Never stored to localStorage.
 *
 * In the preferred embodiment the secret is encrypted under a biometric_key
 * derived by the IDV provider and stored in the receipt store (enc_secret).
 * Recovery on any device: re-authenticate biometrically → IDV re-derives
 * biometric_key → decrypt enc_secret → recover person_secret.
 *
 * @returns {string} Hex-encoded 32-byte person_secret.
 */
export function generatePersonSecret() {
  const bytes = requiredWebCrypto().getRandomValues(new Uint8Array(32));
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Encrypt person_secret under biometric_key (AES-256-GCM).
 *
 * biometric_key is a 32-byte hex string derived by the IDV provider from the
 * voter's biometric template. It is re-derivable by the IDV provider on any
 * subsequent device — the voter need not memorize or retain it.
 *
 * @param {string} personSecret   - Hex-encoded 32-byte secret.
 * @param {string} biometricKey   - Hex-encoded 32-byte AES key from IDV provider.
 * @returns {Promise<string>}       Base64-encoded ciphertext (IV prepended).
 */
export async function encryptPersonSecret(personSecret, biometricKey) {
  const crypto = requiredWebCrypto();
  const keyBytes = Uint8Array.from(
    biometricKey.match(/.{2}/g).map((b) => parseInt(b, 16))
  );
  const secretBytes = Uint8Array.from(
    personSecret.match(/.{2}/g).map((b) => parseInt(b, 16))
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    secretBytes
  );
  // Prepend IV to ciphertext for storage.
  const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.byteLength);
  return btoa(String.fromCharCode(...combined));
}

/**
 * Decrypt enc_secret from the receipt store using biometric_key.
 *
 * Called on any device after biometric re-authentication with the IDV provider.
 * Also called by a court-authorized party after compelled disclosure of both
 * biometric_key (from IDV provider) and enc_secret (from receipt store).
 *
 * @param {string} encSecretBase64 - Base64-encoded ciphertext (IV prepended).
 * @param {string} biometricKey    - Hex-encoded 32-byte AES key from IDV provider.
 * @returns {Promise<string>}        Hex-encoded person_secret.
 */
export async function decryptPersonSecret(encSecretBase64, biometricKey) {
  const crypto = requiredWebCrypto();
  const keyBytes = Uint8Array.from(
    biometricKey.match(/.{2}/g).map((b) => parseInt(b, 16))
  );
  const combined = Uint8Array.from(atob(encSecretBase64), (c) =>
    c.charCodeAt(0)
  );
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const aesKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    ciphertext
  );
  return Array.from(new Uint8Array(plaintext))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Compute MiMC(personSecret) — the value submitted to Didit at enrollment.
 * Didit signs sha256(commitment || submission_id) with its Ed25519 key.
 *
 * @param {string} personSecret - Hex-encoded device-bound secret.
 * @returns {string} Hex-encoded commitment.
 */
export function computeCommitment(personSecret) {
  return callWasm(globalThis.shywareZKComputeCommitment, personSecret);
}

/**
 * Compute MiMC(personSecret, submissionId) — the per-submission nullifier stored on-chain
 * as identity_hash. Unlinkable to the commitment without the person_secret.
 *
 * @param {string} personSecret
 * @param {string} submissionId
 * @returns {string} Hex-encoded nullifier.
 */
export function computeNullifier(personSecret, submissionId) {
  return callWasm(
    globalThis.shywareZKComputeNullifier,
    personSecret,
    submissionId
  );
}

/**
 * Generate a Groth16 proof that F(personSecret)==commitment AND
 * F(personSecret,submissionId)==nullifier, without revealing personSecret.
 *
 * Returns { proof: "<base64>", commitment: "<hex>", nullifier: "<hex>" }.
 *
 * @param {string} personSecret
 * @param {string} submissionId
 */
export function generateProof(personSecret, submissionId) {
  return callWasm(
    globalThis.shywareZKProve,
    personSecret,
    submissionId,
    _provingKeyBase64
  );
}

/**
 * Build a fully-signed ZK submission transaction envelope for the shyware ABCI.
 *
 * Preferred embodiment: commitment and diditCommitmentSig are private circuit
 * witnesses and do NOT appear in the transaction payload. The ABCI verifies
 * only the Groth16 proof against (nullifier, submission_id, didit_pub_key).
 *
 * NOTE: Until the circuit is hardened to include Ed25519 verification as a
 * constraint (gnark/std/algebra/emulated + gnark/std/hash/sha2), commitment
 * and didit_commitment_sig are included as interim fields so the ABCI can
 * verify the Didit binding on-chain. Remove them once the circuit change lands.
 *
 * @param {object} args
 * @param {string}   args.submissionId              - Submission identifier.
 * @param {any}      args.payload                   - Submission payload (protocol-specific).
 * @param {string}   args.personSecret              - From decryptPersonSecret() after biometric re-auth.
 * @param {string}   args.diditCommitmentSigBase64  - Ed25519 sig from Didit: sign(sha256(commitment||submission_id)).
 * @param {string}  [args.encSecret]                - Base64 enc_secret from receipt store (for receipt).
 * @param {number}  [args.timestamp]                - Unix seconds; defaults to now.
 *
 * @returns {Promise<{
 *   txJson:      string,  // JSON-encoded Tx — post as { tx: txJson }
 *   submissionId: string, // H(submissionNonce) — for local receipt
 *   submissionNonce: string, // random hex; store in receipt for self-verification
 *   nullifier:   string,  // on-chain identity_hash
 *   encSecret:   string,  // enc_secret to store/update in receipt store
 * }>}
 */
export async function buildZKSubmissionEnvelope({
  submissionId,
  payload,
  personSecret,
  diditCommitmentSigBase64,
  encSecret = null,
  timestamp = Math.floor(Date.now() / 1000)
}) {
  assertProverReady();

  const { proof, commitment, nullifier } = generateProof(
    personSecret,
    submissionId
  );

  // submission_nonce is random and INDEPENDENT of the ZK nullifier.
  // submission_id = SHA-256(submissionNonce) — unlinkable to the participant without the receipt.
  const nonceBytes = requiredWebCrypto().getRandomValues(new Uint8Array(32));
  const submissionNonce = Array.from(nonceBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const submissionIdHash = await sha256hex(submissionNonce);

  // Decode diditCommitmentSig from base64 to a byte array for the wire format.
  const diditSigBytes = Array.from(atob(diditCommitmentSigBase64), (c) =>
    c.charCodeAt(0)
  );

  // TODO: remove zk_commitment and didit_commitment_sig once circuit includes
  // Ed25519 verification as a constraint (private witness path).
  const data = {
    submission_id: submissionId,
    zk_nullifier: nullifier,
    zk_nullifier_proof: Array.from(atob(proof), (c) => c.charCodeAt(0)),
    zk_commitment: commitment, // interim: remove after circuit hardening
    didit_commitment_sig: diditSigBytes, // interim: remove after circuit hardening
    payload,
    submission_nonce: submissionNonce,
    timestamp
  };

  return {
    txJson: JSON.stringify({ type: 2, signature: "AQ==", data }),
    submissionId: submissionIdHash,
    submissionNonce,
    nullifier,
    encSecret // pass-through for receipt store write; generated at enrollment via encryptPersonSecret()
  };
}
// Voting-specific aliases for compatibility
export const buildZKBallotEnvelope = buildZKSubmissionEnvelope;
