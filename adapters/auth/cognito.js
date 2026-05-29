import { createRequire } from 'module';
import { AuthInterface } from './interface.js';

const require = createRequire(import.meta.url);

/**
 * CognitoAuthInterface — verifies Cognito access tokens via aws-jwt-verify.
 * Works with Cognito User Pools regardless of whether the hosted UI is
 * fronted by Cloudflare Access, CloudFront, or direct.
 *
 * Upgrade path: swap for JwksAuthInterface when moving to a different OIDC
 * provider (Auth0, Okta, Amplify custom domain, etc.).
 */
export class CognitoAuthInterface extends AuthInterface {
  constructor({
    userPoolId = process.env.AUTH_USER_POOL_ID || process.env.COGNITO_USER_POOL_ID,
    clientId   = process.env.AUTH_CLIENT_ID    || process.env.COGNITO_CLIENT_ID,
    tokenUse   = 'access',
    region     = process.env.CLOUD_REGION || process.env.AWS_REGION || 'us-east-2',
  } = {}) {
    super();
    if (!userPoolId) throw new Error('CognitoAuthInterface requires userPoolId or COGNITO_USER_POOL_ID');
    if (!clientId)   throw new Error('CognitoAuthInterface requires clientId or COGNITO_CLIENT_ID');
    this._userPoolId = userPoolId;
    this._clientId   = clientId;
    this._tokenUse   = tokenUse;
    this._region     = region;
    this._verifier   = null;
  }

  get name() { return 'cognito'; }

  _getVerifier() {
    if (this._verifier) return this._verifier;
    const { CognitoJwtVerifier } = require('aws-jwt-verify');
    this._verifier = CognitoJwtVerifier.create({
      userPoolId: this._userPoolId,
      clientId:   this._clientId,
      tokenUse:   this._tokenUse,
    });
    return this._verifier;
  }

  async verify(token) {
    const payload = await this._getVerifier().verify(token);
    return { uid: payload.sub, email: payload.email, payload };
  }
}
