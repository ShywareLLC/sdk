import { SigningInterface } from './interface.js';
import { createPublicKey } from 'crypto';

/**
 * GcpKmsSigningInterface — signs period-close attestations using Google Cloud KMS
 * (asymmetric EC_SIGN_P256_SHA256 key version).
 *
 * Key name format:
 *   projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}/cryptoKeyVersions/{version}
 *
 * Set SIGNING_KEY_ID to the full resource name, or set individual
 * GCP_PROJECT / GCP_LOCATION / GCP_KEY_RING / GCP_KEY_NAME / GCP_KEY_VERSION vars.
 *
 * Auth: uses Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS,
 * Workload Identity, or gcloud auth). No SDK-level credential config needed.
 */
export class GcpKmsSigningInterface extends SigningInterface {
  constructor({
    keyName  = process.env.SIGNING_KEY_ID || _buildKeyName(),
    project  = process.env.GCP_PROJECT,
    location = process.env.GCP_LOCATION   || 'global',
    keyRing  = process.env.GCP_KEY_RING,
    keyId    = process.env.GCP_KEY_NAME,
    version  = process.env.GCP_KEY_VERSION || '1',
  } = {}) {
    super();
    this._keyName = keyName || (project && keyRing && keyId
      ? `projects/${project}/locations/${location}/keyRings/${keyRing}/cryptoKeys/${keyId}/cryptoKeyVersions/${version}`
      : null);
    if (!this._keyName) throw new Error(
      'GcpKmsSigningInterface requires SIGNING_KEY_ID (full resource name) or GCP_PROJECT + GCP_KEY_RING + GCP_KEY_NAME'
    );
    this._client = null;
    this._publicKeyPem = null;
  }

  get name() { return 'gcp-kms'; }
  get publicKeyPem() { return this._publicKeyPem; }

  async _getClient() {
    if (!this._client) {
      const { KeyManagementServiceClient } = await import('@google-cloud/kms');
      this._client = new KeyManagementServiceClient();
    }
    return this._client;
  }

  async _ensurePublicKey() {
    if (this._publicKeyPem) return;
    const client = await this._getClient();
    const [pk] = await client.getPublicKey({ name: this._keyName });
    this._publicKeyPem = pk.pem;
  }

  async sign(message) {
    await this._ensurePublicKey();
    const client = await this._getClient();
    const digest = await _sha256(message);
    const [res] = await client.asymmetricSign({
      name: this._keyName,
      digest: { sha256: digest },
    });
    return Buffer.from(res.signature).toString('base64');
  }

  async verify(message, signatureB64) {
    await this._ensurePublicKey();
    const { createVerify } = await import('crypto');
    const v = createVerify('sha256');
    v.update(message, 'utf8');
    return v.verify(this._publicKeyPem, Buffer.from(signatureB64, 'base64'));
  }
}

function _buildKeyName() { return null; }

async function _sha256(message) {
  const { createHash } = await import('crypto');
  return createHash('sha256').update(message, 'utf8').digest();
}
