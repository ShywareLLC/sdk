/**
 * App-facing web SDK for shycam utility flows.
 *
 * shycam stores attested observation proofs (for example liveness/proof-of-presence
 * artifacts) as sealed utility records using shyware store semantics.
 */

import {
  createUtilityClient,
  formatUtilityError,
  initializeUtilityFromShyConfig
} from "./utilityClient.js";

const REQUIRED_FLOWS = [
  "cam_attest_store",
  "cam_attest_reveal",
  "biometric_rederive"
];

function normalizeObservationPayload({
  observationID,
  streamRef,
  locationID = null,
  operatorID = null,
  digest,
  timestamp = Date.now(),
  metadata = null
}) {
  if (!observationID) throw new Error("observationID is required.");
  if (!streamRef) throw new Error("streamRef is required.");
  if (!digest || typeof digest !== "string")
    throw new Error("digest is required.");

  return {
    schema: "shycam.observation.v1",
    observation_id: observationID,
    stream_ref: streamRef,
    location_id: locationID,
    operator_id: operatorID,
    digest,
    timestamp,
    metadata: metadata ?? {}
  };
}

export function assertCamManifest(shyconfig) {
  const productType = shyconfig?.app?.product_type;
  const validProductTypes = new Set([
    "shycam",
    "shycustody",
    "shystream",
    "shyhop"
  ]);
  if (!validProductTypes.has(productType)) {
    throw new Error(
      "shycam utility requires app.product_type to be one of: shycam, shycustody, shystream, shyhop."
    );
  }

  if (!shyconfig?.store) {
    throw new Error("shycam utility requires a store block.");
  }

  const activeFlows = new Set(shyconfig?.anon_layer?.required_flows ?? []);
  for (const flow of REQUIRED_FLOWS) {
    if (!activeFlows.has(flow)) {
      throw new Error(`shycam manifest missing required flow: ${flow}`);
    }
  }
}

export function createCamClient({
  defaultBase = "/api",
  storageKey = "shyware_cam_api_base",
  fetchImpl = globalThis.fetch?.bind(globalThis),
  getAuthHeaders = null,
  manifest = null,
  deriveSealerKey = null,
  signMessage = null,
  getIdentityAttestation = null
} = {}) {
  const utilityClient = createUtilityClient({
    utilityName: "shycam",
    utilityConfigKey: "cam",
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
      return {
        ...utilityClient.initialize(),
        utilityType: "shycam"
      };
    },
    getBase: utilityClient.getBase,
    setBase: utilityClient.setBase,
    getManifest: utilityClient.getManifest,
    createBucket: utilityClient.createBucket,
    listBuckets: utilityClient.listBuckets,
    getBucket: utilityClient.getBucket,
    closeBucket: utilityClient.closeBucket,
    getBucketClosure: utilityClient.getBucketClosure,
    sealPayload: utilityClient.sealPayload,
    openPayload: utilityClient.openPayload,

    sealObservationProof({ bucketID, partitionID = "sealed", ...args }) {
      const payload = normalizeObservationPayload(args);
      return utilityClient.writeUtilityRecord({
        bucketID,
        payload,
        category: "cam_attestation",
        partitionID
      });
    },

    revealObservationProof({ bucketID, secretID }) {
      return utilityClient.readUtilityRecord({ bucketID, secretID });
    },

    rotateObservationProof({ bucketID, oldSecretID, ...args }) {
      const payload = normalizeObservationPayload(args);
      return utilityClient.rotateUtilityRecord({
        bucketID,
        oldSecretID,
        payload
      });
    }
  };
}

export function initializeFromShyConfig(shyconfig, options = {}) {
  assertCamManifest(shyconfig);
  initializeUtilityFromShyConfig(shyconfig, {
    utilityName: "shycam",
    utilityConfigKey: "cam",
    storageKey: "shyware_cam_api_base",
    ...options
  });

  return createCamClient({
    defaultBase: shyconfig.api?.base_url ?? "/api",
    storageKey:
      shyconfig.api?.storage_key ??
      options.storageKey ??
      "shyware_cam_api_base",
    fetchImpl: options.fetchImpl,
    getAuthHeaders: options.getAuthHeaders,
    manifest: shyconfig,
    deriveSealerKey: options.deriveSealerKey,
    signMessage: options.signMessage,
    getIdentityAttestation: options.getIdentityAttestation
  });
}

export function formatCamError(error) {
  return formatUtilityError(error) || "Cam operation failed.";
}

export const createCamUtility = createCamClient;
