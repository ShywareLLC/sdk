/**
 * Registered-credential embodiment, web side: a P-256 ECDSA keypair, once
 * generated, is registered against a person-stable Firebase UID (via the
 * IDV attestation enclave's POST /register-browser-credential, plus a
 * TxTypeRegisterIdentity chain tx) and then signs every future ballot
 * cast/update -- no further Didit session needed per vote, and
 * identity_hash becomes sha256(firebaseUID || pollID) instead of
 * per-device, which is what lets the already-live CockroachDB reconcile
 * store serve cross-device vote recovery (see
 * ShywareLLC/core/services/identity/registered_credential.go).
 *
 * SCOPE NOTE -- read before assuming this is "WebAuthn support":
 * a real WebAuthn/passkey assertion signs
 * `authenticatorData || SHA-256(clientDataJSON)`, with the challenge
 * embedded inside clientDataJSON.challenge -- verifying that shape
 * requires a real WebAuthn library server-side (e.g. go-webauthn). The
 * chain's registered-credential verifier
 * (services/identity/registered_credential.go) does not implement that; it
 * only checks a direct ECDSA-P256 signature over
 * sha256("vote:" + voter_pub_key + ":" + poll_id), ASN.1 DER-encoded. This
 * module therefore generates a non-extractable WebCrypto ECDSA P-256
 * keypair held in IndexedDB (origin-bound; once generated, the private key
 * is never readable/exportable by page script again) -- real key
 * isolation, just not a platform passkey. Upgrading to a true WebAuthn
 * authenticator later is additive (a chain-side verifier change), not a
 * rewrite of the registration/vote wiring here.
 */

const DB_NAME = "shyware_registered_credential";
const DB_VERSION = 1;
const STORE_NAME = "keys";
const RECORD_KEY = "keypair";

function requiredIndexedDB() {
  if (typeof indexedDB === "undefined") {
    throw new Error("IndexedDB is required for the registered-credential embodiment.");
  }
  return indexedDB;
}

function openDb() {
  return new Promise((resolve, reject) => {
    const req = requiredIndexedDB().open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE_NAME)) {
        req.result.createObjectStore(STORE_NAME);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet(key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const req = tx.objectStore(STORE_NAME).get(key);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}

async function idbSet(key, value) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBase64(hexStr) {
  const bytes = new Uint8Array(hexStr.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hexStr.substr(i * 2, 2), 16);
  }
  return btoa(String.fromCharCode(...bytes));
}

// Converts a WebCrypto ECDSA signature (raw IEEE P1363 r||s, 64 bytes for
// P-256 -- crypto.subtle.sign never produces anything else) into ASN.1 DER,
// the format Go's ecdsa.VerifyASN1 expects
// (services/identity/registered_credential.go's decodeP256PubKeyHex +
// VerifyRegisteredCredentialVote/Update).
function rawSigToDer(sigBuf) {
  const raw = new Uint8Array(sigBuf);
  const r = raw.slice(0, 32);
  const s = raw.slice(32, 64);

  function encodeInt(bytes) {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    bytes = bytes.slice(i);
    if (bytes[0] & 0x80) {
      const padded = new Uint8Array(bytes.length + 1);
      padded.set(bytes, 1);
      bytes = padded;
    }
    return bytes;
  }

  const rEnc = encodeInt(r);
  const sEnc = encodeInt(s);
  const body = new Uint8Array(2 + rEnc.length + 2 + sEnc.length);
  let o = 0;
  body[o++] = 0x02;
  body[o++] = rEnc.length;
  body.set(rEnc, o);
  o += rEnc.length;
  body[o++] = 0x02;
  body[o++] = sEnc.length;
  body.set(sEnc, o);
  o += sEnc.length;

  const der = new Uint8Array(2 + body.length);
  der[0] = 0x30;
  der[1] = body.length;
  der.set(body, 2);
  return der;
}

/// Returns the existing registered credential (if this browser profile
/// already registered one) or generates and persists a new non-extractable
/// P-256 keypair. The returned privateKey is a CryptoKey handle only -- the
/// raw key material cannot be exported again once extractable: false.
export async function getOrCreateRegisteredCredential() {
  const existing = await idbGet(RECORD_KEY);
  if (existing?.privateKey && existing?.publicKeyHex) {
    return existing;
  }

  const keypair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false, // not extractable
    ["sign", "verify"]
  );
  const pubRaw = await crypto.subtle.exportKey("raw", keypair.publicKey);
  const publicKeyHex = bufToHex(pubRaw);
  const record = {
    privateKey: keypair.privateKey,
    publicKey: keypair.publicKey,
    publicKeyHex
  };
  await idbSet(RECORD_KEY, record);
  return record;
}

export async function hasRegisteredCredential() {
  if (typeof indexedDB === "undefined") return false;
  try {
    const existing = await idbGet(RECORD_KEY);
    return Boolean(existing?.publicKeyHex);
  } catch {
    return false;
  }
}

export async function getRegisteredCredentialPubKeyHex() {
  const existing = await idbGet(RECORD_KEY).catch(() => null);
  return existing?.publicKeyHex ?? null;
}

/// Signs `message` (a plain string, UTF-8 encoded) with the registered
/// credential's private key, returning an ASN.1 DER-encoded signature. Used
/// for both the "vote:" and "update:" prefixed messages
/// (registeredVoteSigMessage/registeredUpdateSigMessage in
/// services/identity/registered_credential.go).
export async function signWithRegisteredCredential(privateKey, message) {
  const sigBuf = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(message)
  );
  return rawSigToDer(sigBuf);
}

/// Registers this browser's credential against a Firebase UID:
///  1. Calls the IDV attestation enclave's /register-browser-credential
///     (re-verifies the Didit session_id AND the Firebase ID token
///     independently -- see idv-enclave/server.js's
///     verifyFirebaseIdToken/checkDiditSession -- so a forged request
///     cannot produce a valid registration_binding_sig).
///  2. Submits TxTypeRegisterIdentity to the chain via the relay's
///     POST /identity/register (api/server/router.go's registerIdentity),
///     carrying the enclave's resulting registration_binding_sig.
///
/// `postFn` is the same low-level POST helper votingClient.js's internal
/// `post()` uses (base-URL-aware, auth-header-aware) -- passed in rather
/// than imported, so this module stays decoupled from any one client's
/// transport setup.
export async function registerDeviceCredential({
  manifest,
  sessionId,
  firebaseIdToken,
  postFn
}) {
  if (!sessionId) {
    throw new Error("registerDeviceCredential requires an approved Didit session_id.");
  }
  if (!firebaseIdToken) {
    throw new Error("registerDeviceCredential requires a Firebase ID token.");
  }
  const baseURL = manifest?.identity?.attestation_service_base_url;
  if (!baseURL) {
    throw new Error("shyconfig identity.attestation_service_base_url is required to register a credential.");
  }

  const { publicKeyHex } = await getOrCreateRegisteredCredential();

  const res = await fetch(`${baseURL.replace(/\/$/, "")}/register-browser-credential`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_id: sessionId,
      registration_pub_key: publicKeyHex,
      firebase_id_token: firebaseIdToken
    })
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error ?? `Enclave registration HTTP ${res.status}`);
  }
  const decoded = await res.json();

  const data = {
    registration_pub_key: decoded.registration_pub_key ?? publicKeyHex,
    firebase_uid: decoded.firebase_uid,
    didit_session_id: decoded.session_id ?? sessionId,
    timestamp: Math.floor(Date.now() / 1000),
    registration_binding_sig: hexToBase64(decoded.registration_binding_sig)
  };

  const txJson = JSON.stringify({ type: 11, signature: "AQ==", data });
  await postFn("/identity/register", { tx: txJson });
  return { registrationPubKeyHex: data.registration_pub_key, firebaseUid: data.firebase_uid, txJson };
}
