/**
 * Shared utility client primitives for shyware utility modules.
 *
 * Utilities (shyhop, shycam, shyIoT) reuse shystore semantics through storeClient
 * and stay independent from any single domain surface such as shystream.
 */

import { createStoreClient, formatStoreError } from "../embodiments/storeClient.js";
import {
  applyStoreAnonLayerDefaults,
  assertStoreBackedAnonLayer
} from "../../protocol/anonLayer.js";

export function assertUtilityManifest(shyconfig, utilityName = "utility") {
  applyStoreAnonLayerDefaults(shyconfig);

  if (!shyconfig?.app?.id) {
    throw new Error(`${utilityName} requires app.id in shyconfig.`);
  }

  if (!shyconfig?.anon_layer?.black_box_required) {
    throw new Error(
      `${utilityName} requires anon_layer.black_box_required=true.`
    );
  }

  if (!shyconfig?.signing?.required || shyconfig?.signing?.backend === "none") {
    throw new Error(`${utilityName} requires protocol signing.`);
  }

  if (!shyconfig?.store) {
    throw new Error(`${utilityName} requires a store block.`);
  }

  assertStoreBackedAnonLayer(shyconfig, utilityName);
}

export function createUtilityClient({
  utilityName = "utility",
  utilityConfigKey = "utility",
  defaultBase = "/api",
  storageKey = "shyware_utility_api_base",
  fetchImpl = globalThis.fetch?.bind(globalThis),
  getAuthHeaders = null,
  manifest = null,
  deriveSealerKey = null,
  signMessage = null,
  getIdentityAttestation = null
} = {}) {
  if (!fetchImpl) {
    throw new Error(`fetch is required by ${utilityName}.`);
  }

  const storeClient = createStoreClient({
    defaultBase,
    storageKey,
    fetchImpl,
    getAuthHeaders,
    manifest,
    deriveSealerKey,
    signMessage,
    getIdentityAttestation
  });

  return {
    initialize() {
      const base = storeClient.initialize();
      return {
        ...base,
        chainId: manifest?.app?.chain_id ?? null,
        productType: manifest?.app?.product_type ?? null,
        deployment: manifest?.deployment ?? null,
        signing: manifest?.signing ?? null,
        [utilityConfigKey]: manifest?.[utilityConfigKey] ?? null,
        requiredFlows: manifest?.anon_layer?.required_flows ?? []
      };
    },

    getBase: storeClient.getBase,
    setBase: storeClient.setBase,
    getManifest: storeClient.getManifest,

    createBucket: storeClient.createBucket,
    listBuckets: storeClient.listBuckets,
    getBucket: storeClient.getBucket,
    closeBucket: storeClient.closeBucket,
    getBucketClosure: storeClient.getBucketClosure,

    sealPayload: storeClient.sealSecret,
    openPayload: storeClient.openSecret,

    writeUtilityRecord({
      bucketID,
      payload,
      category = "utility_event",
      partitionID = "sealed"
    }) {
      return storeClient.storeSecret({
        bucketID,
        plaintext: payload,
        category,
        partitionID
      });
    },

    readUtilityRecord({ bucketID, secretID }) {
      return storeClient.revealAndDecryptSecret({ bucketID, secretID });
    },

    rotateUtilityRecord({ bucketID, oldSecretID, payload }) {
      return storeClient.rotateSecret({
        bucketID,
        oldSecretID,
        newPlaintext: payload
      });
    }
  };
}

export function initializeUtilityFromShyConfig(
  shyconfig,
  {
    utilityName = "utility",
    storageKey = "shyware_utility_api_base",
    ...options
  } = {}
) {
  applyStoreAnonLayerDefaults(shyconfig);
  assertUtilityManifest(shyconfig, utilityName);

  const requiresAuth =
    shyconfig.api?.requires_auth === true ||
    (shyconfig.api?.auth_scheme && shyconfig.api.auth_scheme !== "none");

  if (requiresAuth && typeof options.getAuthHeaders !== "function") {
    throw new Error(
      `${utilityName} manifest requires authenticated API access, but no auth header provider was supplied.`
    );
  }

  return createUtilityClient({
    defaultBase: shyconfig.api?.base_url ?? "/api",
    storageKey: shyconfig.api?.storage_key ?? options.storageKey ?? storageKey,
    fetchImpl: options.fetchImpl,
    getAuthHeaders: options.getAuthHeaders,
    manifest: shyconfig,
    deriveSealerKey: options.deriveSealerKey,
    signMessage: options.signMessage,
    getIdentityAttestation: options.getIdentityAttestation,
    utilityName,
    utilityConfigKey: options.utilityConfigKey ?? utilityName
  });
}

export function formatUtilityError(error) {
  return formatStoreError(error) || "Utility operation failed.";
}
