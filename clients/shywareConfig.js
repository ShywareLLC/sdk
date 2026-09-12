/**
 * shywareConfig.js — shared shyconfig utility for the Shyware web SDK.
 *
 * Provides warnFoldedAuthority(), called by every embodiment client's
 * initializeFromShyConfig() before any write operations begin.
 */

/**
 * Emit a console.warn if the shyconfig describes a folded-authority
 * configuration — one where the same entity operates both the canonical
 * ledger and the reconciling authority.
 *
 * Folded authority collapses the three-party attribution chain, giving a
 * single operator the ability to link participant submissions to identities.
 * This check mirrors the server-side enforcement in config/validate.go so
 * that operators receive an early warning in the browser console before any
 * writes reach the ledger.
 *
 * @param {object} shyconfig — parsed shyconfig manifest object
 */
export function warnFoldedAuthority(shyconfig) {
  const ra   = shyconfig?.deployment?.reconcile_authority;
  const tier = shyconfig?.deployment?.deployment_tier ?? '';

  if (!ra) return;

  const op = ra.operator ?? '';

  // Case 1: "ledger_operator" is an explicit fold — rejected unconditionally.
  if (op === 'ledger_operator') {
    console.warn(
      '[Shyware SDK] reconcile_authority.operator "ledger_operator" creates a folded-authority ' +
      'configuration. When the same entity controls both the canonical ledger and the reconciling ' +
      'authority, participant submissions can be linked to identities, removing the anonymity ' +
      'guarantee. This configuration is rejected at the server validation layer. ' +
      'Set reconcile_authority.operator to "operator", "shyware", or "independent_third_party".'
    );
    return;
  }

  // Case 2: self_hosted + operator RA — deployment operator runs both chain and RA.
  if (op === 'operator' && tier === 'self_hosted') {
    console.warn(
      '[Shyware SDK] deployment_tier "self_hosted" with reconcile_authority.operator "operator" ' +
      'creates a folded-authority configuration. In a self-hosted deployment you operate the ' +
      'canonical ledger, so operating the reconciling authority as well gives a single entity ' +
      'the ability to link participant submissions to identities. ' +
      'This configuration is rejected at the server validation layer. ' +
      'Use reconcile_authority.operator "shyware" or "independent_third_party".'
    );
    return;
  }

  // Case 3: community or hosted_dedicated + shyware RA — Shyware runs both chain and RA.
  if (op === 'shyware' && (tier === 'community' || tier === 'hosted_dedicated')) {
    console.warn(
      '[Shyware SDK] deployment_tier "' + tier + '" with reconcile_authority.operator "shyware" ' +
      'creates a folded-authority configuration. Shyware operates the canonical ledger in this ' +
      'tier, so Shyware operating the reconciling authority as well would give a single entity ' +
      'the ability to link participant submissions to identities. ' +
      'This configuration is rejected at the server validation layer. ' +
      'Use reconcile_authority.operator "operator" or "independent_third_party".'
    );
  }
}
