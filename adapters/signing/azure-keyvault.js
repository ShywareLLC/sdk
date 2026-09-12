import { SigningInterface } from './interface.js';

/**
 * AzureKeyVaultSigningInterface — signs period-close attestations using
 * Azure Key Vault (EC P-256, ES256 algorithm).
 *
 * Key URI format:
 *   https://{vault-name}.vault.azure.net/keys/{key-name}/{key-version}
 *   (key-version may be omitted to always use the latest version)
 *
 * Required env vars:
 *   SIGNING_KEY_ID       — full key URI (takes precedence)
 *   AZURE_VAULT_NAME     — vault hostname prefix (alternative to full URI)
 *   AZURE_KEY_NAME       — key name within the vault
 *   AZURE_KEY_VERSION    — key version (optional; omit for latest)
 *
 * Auth: uses DefaultAzureCredential from @azure/identity — works with
 * Managed Identity, environment variables (AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
 * / AZURE_TENANT_ID), Azure CLI, and VS Code credentials automatically.
 *
 * Peer deps: @azure/keyvault-keys @azure/identity
 */
export class AzureKeyVaultSigningInterface extends SigningInterface {
  constructor({
    keyId    = process.env.SIGNING_KEY_ID || _buildKeyId(),
    vaultUrl = process.env.AZURE_VAULT_URL
               || (process.env.AZURE_VAULT_NAME
                   ? `https://${process.env.AZURE_VAULT_NAME}.vault.azure.net`
                   : null),
    keyName    = process.env.AZURE_KEY_NAME,
    keyVersion = process.env.AZURE_KEY_VERSION || '',
  } = {}) {
    super();
    // Accept either a full key URI in keyId or separate vault/key/version parts.
    if (keyId) {
      // Parse vault URL, key name, and version from the full URI.
      const m = keyId.match(/^(https:\/\/[^/]+)\/keys\/([^/]+)\/?([^/]*)$/);
      if (!m) throw new Error(`AzureKeyVaultSigningInterface: invalid key URI: ${keyId}`);
      this._vaultUrl   = m[1];
      this._keyName    = m[2];
      this._keyVersion = m[3] || '';
    } else if (vaultUrl && keyName) {
      this._vaultUrl   = vaultUrl.replace(/\/$/, '');
      this._keyName    = keyName;
      this._keyVersion = keyVersion;
    } else {
      throw new Error(
        'AzureKeyVaultSigningInterface requires SIGNING_KEY_ID (full key URI) ' +
        'or AZURE_VAULT_NAME + AZURE_KEY_NAME'
      );
    }
    this._client     = null;
    this._cryptoClient = null;
    this._publicKeyPem = null;
  }

  get name() { return 'azure-keyvault'; }
  get publicKeyPem() { return this._publicKeyPem; }

  async _getClients() {
    if (this._client) return;
    const { KeyClient, CryptographyClient } = await import('@azure/keyvault-keys');
    const { DefaultAzureCredential }        = await import('@azure/identity');
    const credential = new DefaultAzureCredential();
    this._client = new KeyClient(this._vaultUrl, credential);
    // CryptographyClient needs the full key URI including version.
    const keyUri = this._keyVersion
      ? `${this._vaultUrl}/keys/${this._keyName}/${this._keyVersion}`
      : `${this._vaultUrl}/keys/${this._keyName}`;
    this._cryptoClient = new CryptographyClient(keyUri, credential);
  }

  async _ensurePublicKey() {
    if (this._publicKeyPem) return;
    await this._getClients();
    const key = this._keyVersion
      ? await this._client.getKey(this._keyName, { version: this._keyVersion })
      : await this._client.getKey(this._keyName);
    // key.key is a JsonWebKey; export as PEM via SubtleCrypto.
    const jwk = key.key;
    if (!jwk || jwk.kty !== 'EC') {
      throw new Error('AzureKeyVaultSigningInterface: key must be an EC key (P-256)');
    }
    // Import JWK → SubtleCrypto CryptoKey → export as SPKI DER → PEM.
    const subtle = globalThis.crypto?.subtle ?? (await import('crypto')).webcrypto.subtle;
    const cryptoKey = await subtle.importKey(
      'jwk', { ...jwk, key_ops: ['verify'] },
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, ['verify']
    );
    const spki = await subtle.exportKey('spki', cryptoKey);
    const b64  = Buffer.from(spki).toString('base64');
    this._publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
  }

  async sign(message) {
    await this._ensurePublicKey();
    // Azure signs a digest; we SHA-256 the message first.
    const subtle  = globalThis.crypto?.subtle ?? (await import('crypto')).webcrypto.subtle;
    const msgBuf  = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
    const digest  = Buffer.from(await subtle.digest('SHA-256', msgBuf));
    const result  = await this._cryptoClient.sign('ES256', digest);
    return Buffer.from(result.result).toString('base64');
  }

  async verify(message, signatureB64) {
    await this._ensurePublicKey();
    const { createVerify } = await import('crypto');
    const v = createVerify('sha256');
    v.update(typeof message === 'string' ? message : message.toString('utf8'), 'utf8');
    return v.verify(this._publicKeyPem, Buffer.from(signatureB64, 'base64'));
  }
}

function _buildKeyId() { return null; }
