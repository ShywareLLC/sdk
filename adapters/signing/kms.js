import { SigningInterface } from './interface.js';

export class AwsKmsSigningInterface extends SigningInterface {
  constructor({ keyId = process.env.SIGNING_KEY_ID || process.env.KMS_KEY_ID, region = process.env.CLOUD_REGION || process.env.AWS_REGION || 'us-east-1' } = {}) {
    super();
    if (!keyId) throw new Error('AwsKmsSigningInterface requires keyId or SIGNING_KEY_ID (or KMS_KEY_ID) env var');
    this._keyId = keyId;
    this._region = region;
    this._publicKeyPem = null;
    this._kms = null;
  }

  get name() { return 'aws-kms'; }
  get publicKeyPem() { return this._publicKeyPem; }

  async _client() {
    if (!this._kms) {
      const { KMSClient } = await import('@aws-sdk/client-kms');
      this._kms = new KMSClient({ region: this._region });
    }
    return this._kms;
  }

  async sign(message) {
    const { SignCommand } = await import('@aws-sdk/client-kms');
    const kms = await this._client();
    const res = await kms.send(new SignCommand({ KeyId: this._keyId, Message: Buffer.from(message, 'utf8'), MessageType: 'RAW', SigningAlgorithm: 'ECDSA_SHA_256' }));
    return Buffer.from(res.Signature).toString('base64');
  }

  async verify(message, signatureB64) {
    const { VerifyCommand } = await import('@aws-sdk/client-kms');
    const kms = await this._client();
    const res = await kms.send(new VerifyCommand({ KeyId: this._keyId, Message: Buffer.from(message, 'utf8'), MessageType: 'RAW', Signature: Buffer.from(signatureB64, 'base64'), SigningAlgorithm: 'ECDSA_SHA_256' }));
    return res.SignatureValid === true;
  }
}

// Backward-compatible alias
export { AwsKmsSigningInterface as KmsSigningInterface };
