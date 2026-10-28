// shywareSealer.js
// Shared sealer logic for all PII-handling protocol SDKs
// Provides HKDF-based, idempotent, ephemeral AES-256-GCM sealing for PII/high-risk payloads
// Only required for PII/high-risk data as specified in shyconfig. Default is structural anonymity via the two-list invariant.

export async function hkdf(
  secret,
  salt = new Uint8Array(32),
  info = "shyware-sealer",
  length = 32
) {
  // HKDF-SHA256 to derive a key from the provider secret
  const enc = new TextEncoder();
  const keyMaterial = await globalThis.crypto.subtle.importKey(
    "raw",
    typeof secret === "string" ? enc.encode(secret) : secret,
    "HKDF",
    false,
    ["deriveKey"]
  );
  return globalThis.crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: enc.encode(info)
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function sealPayload(payload, deriveSealerKey) {
  const key = await getMasterKey(deriveSealerKey);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );
  return {
    alg: "aes-256-gcm",
    iv: Array.from(iv),
    ciphertext: Array.from(new Uint8Array(ciphertext))
  };
}

export async function openPayload(sealedPayload, deriveSealerKey) {
  if (sealedPayload?.alg !== "aes-256-gcm" ||
      !Array.isArray(sealedPayload.iv) || sealedPayload.iv.length !== 12 ||
      !Array.isArray(sealedPayload.ciphertext) || sealedPayload.ciphertext.length < 16 ||
      ![...sealedPayload.iv, ...sealedPayload.ciphertext].every(
        value => Number.isInteger(value) && value >= 0 && value <= 255
      )) {
    throw new Error("Invalid AES-256-GCM sealed envelope");
  }
  const key = await getMasterKey(deriveSealerKey);
  const iv = new Uint8Array(sealedPayload.iv);
  const ciphertext = new Uint8Array(sealedPayload.ciphertext);
  const decrypted = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );
  const decoded = new TextDecoder().decode(decrypted);
  return JSON.parse(decoded);
}

async function getMasterKey(deriveSealerKey) {
  if (typeof deriveSealerKey !== "function") {
    throw new Error(
      "Production sealer requires async deriveSealerKey() for idempotent, ephemeral key derivation"
    );
  }
  const secret = await deriveSealerKey();
  return hkdf(secret);
}
