import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'crypto';
import { SigningInterface } from './interface.js';

export class SoftwareSigningInterface extends SigningInterface {
  constructor(privateKeyPem = null) {
    super();
    if (privateKeyPem) {
      this._privateKey = createPrivateKey(privateKeyPem);
      this._publicKey = createPublicKey(this._privateKey);
    } else {
      const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      this._privateKey = privateKey;
      this._publicKey = publicKey;
    }
    this._publicKeyPem = this._publicKey.export({ type: 'spki', format: 'pem' });
  }

  get name() { return 'software'; }
  get publicKeyPem() { return this._publicKeyPem; }

  async sign(message) {
    return sign('sha256', Buffer.from(message, 'utf8'), this._privateKey).toString('base64');
  }

  async verify(message, signatureB64) {
    return verify('sha256', Buffer.from(message, 'utf8'), this._publicKey, Buffer.from(signatureB64, 'base64'));
  }
}
