import { SigningInterface } from './interface.js';

/**
 * VaultSigningInterface — signs period-close attestations using HashiCorp Vault
 * Transit secrets engine (sign/{key} endpoint, P-256 / SHA-256).
 *
 * Works on any platform (on-prem, multi-cloud, HCP Vault). No cloud vendor lock-in.
 *
 * Required env vars:
 *   VAULT_ADDR         — Vault server URL (default: http://127.0.0.1:8200)
 *   VAULT_TOKEN        — Vault token with transit sign/verify capabilities
 *   SIGNING_KEY_ID     — Transit key name (or VAULT_TRANSIT_KEY)
 *
 * The transit key must be type 'ecdsa-p256' and have 'allow_plaintext_backup: false'.
 * Vault signs the SHA-256 digest; signatures are DER-encoded ECDSA, returned base64.
 */
export class VaultSigningInterface extends SigningInterface {
  constructor({
    addr    = process.env.VAULT_ADDR         || 'http://127.0.0.1:8200',
    token   = process.env.VAULT_TOKEN,
    keyName = process.env.SIGNING_KEY_ID     || process.env.VAULT_TRANSIT_KEY,
    mount   = process.env.VAULT_TRANSIT_MOUNT || 'transit',
  } = {}) {
    super();
    if (!token)   throw new Error('VaultSigningInterface requires VAULT_TOKEN');
    if (!keyName) throw new Error('VaultSigningInterface requires SIGNING_KEY_ID or VAULT_TRANSIT_KEY');
    this._addr    = addr.replace(/\/$/, '');
    this._token   = token;
    this._keyName = keyName;
    this._mount   = mount;
    this._publicKeyPem = null;
  }

  get name() { return 'vault'; }
  get publicKeyPem() { return this._publicKeyPem; }

  async _request(method, path, body = null) {
    const res = await fetch(`${this._addr}/v1/${path}`, {
      method,
      headers: {
        'X-Vault-Token': this._token,
        'Content-Type': 'application/json',
      },
      body: body ? JSON.stringify(body) : null,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(`Vault ${method} ${path} failed (${res.status}): ${JSON.stringify(err.errors)}`);
    }
    return res.json();
  }

  async _ensurePublicKey() {
    if (this._publicKeyPem) return;
    // Vault Transit exposes the public key via the key info endpoint
    const data = await this._request('GET', `${this._mount}/keys/${this._keyName}`);
    const latestVersion = data.data.latest_version;
    const keyData = data.data.keys[String(latestVersion)];
    // keyData.public_key is a PEM-encoded EC public key
    this._publicKeyPem = keyData.public_key;
    this._keyVersion = latestVersion;
  }

  async sign(message) {
    await this._ensurePublicKey();
    const { createHash } = await import('crypto');
    const digest = createHash('sha256').update(message, 'utf8').digest('base64');
    const data = await this._request('POST', `${this._mount}/sign/${this._keyName}`, {
      input: digest,
      hash_algorithm: 'sha2-256',
      prehashed: true,
      signature_algorithm: 'pkcs1v15', // Vault uses this field name; for EC keys it's ignored
    });
    // Vault returns "vault:v1:<base64-DER-signature>"
    const raw = data.data.signature;
    return raw.replace(/^vault:v\d+:/, '');
  }

  async verify(message, signatureB64) {
    await this._ensurePublicKey();
    const { createVerify } = await import('crypto');
    const v = createVerify('sha256');
    v.update(message, 'utf8');
    return v.verify(this._publicKeyPem, Buffer.from(signatureB64, 'base64'));
  }
}
