function requiredWebCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API is required for wallet registration proofs.")
  }
  return globalThis.crypto
}

function normalizeHex(hex) {
  const raw = String(hex || "").trim()
  return raw.startsWith("0x") ? raw.slice(2) : raw
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("")
}

function bytesToBase64(bytes) {
  if (typeof btoa === "function") {
    let binary = ""
    for (const byte of bytes) binary += String.fromCharCode(byte)
    return btoa(binary)
  }
  return Buffer.from(bytes).toString("base64")
}

async function sha256Bytes(value) {
  const payload = typeof value === "string" ? new TextEncoder().encode(value) : value
  const digest = await requiredWebCrypto().subtle.digest("SHA-256", payload)
  return new Uint8Array(digest)
}

export async function buildRegisterAccountMessageBytes(accountCommitment) {
  return sha256Bytes(`shyware-register-account:${accountCommitment}`)
}

export async function createWalletProofBase64({
  accountCommitment,
  walletAddress,
  ethereumProvider = globalThis.ethereum,
}) {
  if (!walletAddress) {
    throw new Error("walletAddress is required to create a wallet proof.")
  }
  if (!ethereumProvider?.request) {
    throw new Error("An injected Ethereum provider is required to create a wallet proof.")
  }

  const accounts = await ethereumProvider.request({ method: "eth_requestAccounts" })
  const normalizedWallet = String(walletAddress).toLowerCase()
  const hasMatch = Array.isArray(accounts) && accounts.some((account) => String(account).toLowerCase() === normalizedWallet)
  if (!hasMatch) {
    throw new Error("Connected wallet does not match the requested wallet address.")
  }

  const messageBytes = await buildRegisterAccountMessageBytes(accountCommitment)
  const messageHex = `0x${bytesToHex(messageBytes)}`

  let signatureHex
  try {
    signatureHex = await ethereumProvider.request({
      method: "personal_sign",
      params: [messageHex, walletAddress],
    })
  } catch (primaryError) {
    try {
      signatureHex = await ethereumProvider.request({
        method: "personal_sign",
        params: [walletAddress, messageHex],
      })
    } catch {
      throw primaryError
    }
  }

  const normalizedSig = normalizeHex(signatureHex)
  if (normalizedSig.length !== 130) {
    throw new Error("Wallet returned an invalid registration signature.")
  }

  const bytes = new Uint8Array(normalizedSig.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)))
  return bytesToBase64(bytes)
}
