export class SigningInterface {
  get name() { throw new Error('SigningInterface.name not implemented'); }
  get publicKeyPem() { throw new Error('SigningInterface.publicKeyPem not implemented'); }
  async sign(_message) { throw new Error('SigningInterface.sign not implemented'); }
  async verify(_message, _signatureB64) { throw new Error('SigningInterface.verify not implemented'); }
}
