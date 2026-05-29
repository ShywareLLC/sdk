/**
 * Shared helpers for store-backed SDK manifests.
 *
 * Rule: when a store block is present, SDK usage requires anon_layer to be
 * active and at least one store-driving capability toggle enabled.
 */

export function applyStoreAnonLayerDefaults(shyconfig) {
  if (!shyconfig?.store) return shyconfig;

  if (!shyconfig.anon_layer || typeof shyconfig.anon_layer !== "object") {
    shyconfig.anon_layer = {};
  }

  if (typeof shyconfig.anon_layer.black_box_required !== "boolean") {
    shyconfig.anon_layer.black_box_required = true;
  }

  const hasShyPayload = shyconfig.anon_layer.shyPayload === true;
  const hasShyIDV = shyconfig.anon_layer.shyIDV === true;

  // Default to shyPayload when neither toggle is explicitly enabled.
  if (!hasShyPayload && !hasShyIDV) {
    shyconfig.anon_layer.shyPayload = true;
  }

  return shyconfig;
}

export function assertStoreBackedAnonLayer(
  shyconfig,
  surfaceName = "store-backed SDK"
) {
  if (!shyconfig?.store) return;

  if (!shyconfig?.anon_layer?.black_box_required) {
    throw new Error(
      `${surfaceName} requires anon_layer.black_box_required=true when store is present.`
    );
  }

  const hasShyPayload = shyconfig?.anon_layer?.shyPayload === true;
  const hasShyIDV = shyconfig?.anon_layer?.shyIDV === true;

  if (!hasShyPayload && !hasShyIDV) {
    throw new Error(
      `${surfaceName} requires anon_layer.shyPayload=true or anon_layer.shyIDV=true when store is present.`
    );
  }
}
