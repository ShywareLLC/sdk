/**
 * AuthInterface — verify a bearer token and return { uid: string }.
 *
 * Implementations: CognitoAuthInterface, JwksAuthInterface
 * Swap the adapter in loadAdapters() to switch providers with zero
 * changes to route or business logic code.
 */
export class AuthInterface {
  get name() { throw new Error('AuthInterface.name not implemented'); }

  /**
   * Verify a raw bearer token string.
   * Returns { uid } on success, throws on invalid/expired token.
   * @param {string} token
   * @returns {Promise<{ uid: string, [key: string]: any }>}
   */
  async verify(_token) {
    throw new Error('AuthInterface.verify not implemented');
  }
}
