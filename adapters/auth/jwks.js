import { AuthInterface } from './interface.js';

/**
 * JwksAuthInterface — verifies JWTs from any OIDC-compliant provider
 * using the provider's JWKS endpoint. Provider-agnostic.
 *
 * Works with: AWS Cognito, AWS Amplify, Auth0, Okta, Keycloak,
 *             Google Identity Platform, Cloudflare Access JWT, etc.
 *
 * Config:
 *   jwksUri   — e.g. https://cognito-idp.us-east-2.amazonaws.com/POOL_ID/.well-known/jwks.json
 *               or   https://accounts.google.com/.well-known/openid-configuration
 *   issuer    — expected iss claim (optional but recommended)
 *   audience  — expected aud claim (optional)
 *
 * Uses the `jose` library (zero-dep, browser+Node, no AWS-specific code).
 * Install: npm add jose  (in the consumer workspace, not the SDK itself)
 */
export class JwksAuthInterface extends AuthInterface {
  constructor({
    jwksUri  = process.env.AUTH_JWKS_URI,
    issuer   = process.env.AUTH_ISSUER   || undefined,
    audience = process.env.AUTH_AUDIENCE || undefined,
  } = {}) {
    super();
    if (!jwksUri) throw new Error('JwksAuthInterface requires jwksUri or AUTH_JWKS_URI');
    this._jwksUri  = jwksUri;
    this._issuer   = issuer;
    this._audience = audience;
    this._jwks     = null;
  }

  get name() { return `jwks:${new URL(this._jwksUri).hostname}`; }

  async _getJwks() {
    if (this._jwks) return this._jwks;
    // Dynamic import of jose — consumer installs it; SDK does not bundle it
    const { createRemoteJWKSet } = await import('jose');
    this._jwks = createRemoteJWKSet(new URL(this._jwksUri));
    return this._jwks;
  }

  async verify(token) {
    const { jwtVerify } = await import('jose');
    const jwks = await this._getJwks();
    const opts = {};
    if (this._issuer)   opts.issuer   = this._issuer;
    if (this._audience) opts.audience = this._audience;
    const { payload } = await jwtVerify(token, jwks, opts);
    return { uid: payload.sub, email: payload.email, payload };
  }
}

