import { AuthInterface } from './interface.js';

/**
 * FirebaseAuthInterface — verifies Firebase ID tokens issued by the Firebase
 * Authentication service and extracts the uid claim.
 *
 * Works with any Firebase project. Does not require the Firebase Admin SDK —
 * verifies tokens using the JWKS endpoint Firebase publishes publicly.
 *
 * Required env vars:
 *   FIREBASE_PROJECT_ID  — Firebase project ID (e.g. "my-project-12345")
 *
 * The verifyToken() method:
 *   1. Fetches Google's Firebase JWKS (cached per instance).
 *   2. Verifies the ID token signature and standard claims (iss, aud, exp, iat).
 *   3. Returns { uid, email, payload } on success, matching the same shape
 *      as CognitoAuthInterface/JwksAuthInterface (see adapters/auth/interface.js).
 *
 * Peer deps: jose  (npm install jose)
 */
export class FirebaseAuthInterface extends AuthInterface {
  constructor({
    projectId = process.env.FIREBASE_PROJECT_ID,
  } = {}) {
    super();
    if (!projectId) throw new Error('FirebaseAuthInterface requires FIREBASE_PROJECT_ID env var');
    this._projectId = projectId;
    this._jwks      = null; // lazy-initialised JWKS remote key set
  }

  get name() { return 'firebase'; }

  async _getJwks() {
    if (this._jwks) return this._jwks;
    const { createRemoteJWKSet } = await import('jose');
    // Firebase publishes its public keys as a JWKS at this well-known endpoint.
    this._jwks = createRemoteJWKSet(
      new URL('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com')
    );
    return this._jwks;
  }

  async verifyToken(bearerToken) {
    const { jwtVerify } = await import('jose');
    const jwks = await this._getJwks();
    try {
      const { payload } = await jwtVerify(bearerToken, jwks, {
        issuer:   `https://securetoken.google.com/${this._projectId}`,
        audience: this._projectId,
      });
      if (!payload.sub) throw new Error('FirebaseAuthInterface: token missing sub claim');
      return { uid: payload.sub, email: payload.email, payload };
    } catch (err) {
      throw new Error(`FirebaseAuthInterface: token verification failed: ${err.message}`);
    }
  }
}
