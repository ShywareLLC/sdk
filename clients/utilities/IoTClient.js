/**
 * App-facing web SDK for shyIoT utility flows.
 *
 * shyIoT seals telemetry and device event records as utility payloads over
 * shyware store semantics.
 */

import {
  createUtilityClient,
  formatUtilityError,
  initializeUtilityFromShyConfig
} from "./utilityClient.js";

const REQUIRED_FLOWS = [
  "iot_event_store",
  "iot_event_reveal",
  "biometric_rederive"
];

function normalizeTelemetryPayload({
  deviceID,
  eventType,
  reading,
  units = null,
  timestamp = Date.now(),
  metadata = null
}) {
  if (!deviceID) throw new Error("deviceID is required.");
  if (!eventType) throw new Error("eventType is required.");
  if (reading == null) throw new Error("reading is required.");

  return {
    schema: "shyiot.telemetry.v1",
    device_id: deviceID,
    event_type: eventType,
    reading,
    units,
    timestamp,
    metadata: metadata ?? {}
  };
}

export function assertIotManifest(shyconfig) {
  const productType = shyconfig?.app?.product_type;
  const validProductTypes = new Set(["shyiot", "shycam"]);
  if (!validProductTypes.has(productType)) {
    throw new Error(
      "shyIoT utility requires app.product_type to be one of: shyiot, shycam."
    );
  }

  if (!shyconfig?.store) {
    throw new Error("shyIoT utility requires a store block.");
  }

  const activeFlows = new Set(shyconfig?.anon_layer?.required_flows ?? []);
  for (const flow of REQUIRED_FLOWS) {
    if (!activeFlows.has(flow)) {
      throw new Error(`shyIoT manifest missing required flow: ${flow}`);
    }
  }
}

export function createIotClient({
  defaultBase = "/api",
  storageKey = "shyware_iot_api_base",
  fetchImpl = globalThis.fetch?.bind(globalThis),
  getAuthHeaders = null,
  manifest = null,
  deriveSealerKey = null,
  signMessage = null,
  getIdentityAttestation = null
} = {}) {
  const utilityClient = createUtilityClient({
    utilityName: "shyiot",
    utilityConfigKey: "iot",
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
        utilityType: "shyiot"
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

    sealTelemetryRecord({ bucketID, partitionID = "sealed", ...args }) {
      const payload = normalizeTelemetryPayload(args);
      return utilityClient.writeUtilityRecord({
        bucketID,
        payload,
        category: "iot_event",
        partitionID
      });
    },

    revealTelemetryRecord({ bucketID, secretID }) {
      return utilityClient.readUtilityRecord({ bucketID, secretID });
    },

    rotateTelemetryRecord({ bucketID, oldSecretID, ...args }) {
      const payload = normalizeTelemetryPayload(args);
      return utilityClient.rotateUtilityRecord({
        bucketID,
        oldSecretID,
        payload
      });
    }
  };
}

export function initializeFromShyConfig(shyconfig, options = {}) {
  assertIotManifest(shyconfig);
  initializeUtilityFromShyConfig(shyconfig, {
    utilityName: "shyiot",
    utilityConfigKey: "iot",
    storageKey: "shyware_iot_api_base",
    ...options
  });

  return createIotClient({
    defaultBase: shyconfig.api?.base_url ?? "/api",
    storageKey:
      shyconfig.api?.storage_key ??
      options.storageKey ??
      "shyware_iot_api_base",
    fetchImpl: options.fetchImpl,
    getAuthHeaders: options.getAuthHeaders,
    manifest: shyconfig,
    deriveSealerKey: options.deriveSealerKey,
    signMessage: options.signMessage,
    getIdentityAttestation: options.getIdentityAttestation
  });
}

export function formatIotError(error) {
  return formatUtilityError(error) || "IoT operation failed.";
}

export const createIotUtility = createIotClient;

// Backward-compat aliases from the original placeholder API.
export function submitAnonymousRecord(payload) {
  return payload;
}

export function registerDeviceIdentity(identityCommitment) {
  return identityCommitment;
}

export function recoverDeviceState(biometricKey) {
  return biometricKey;
}
