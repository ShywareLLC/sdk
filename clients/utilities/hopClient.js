/**
 * App-facing web SDK for shyhop (shyware utility).
 *
 * shyhop seals follow-up destination metadata (for example next-hop IP and route hints)
 * as utility records over shyware store semantics. This does not hide first-hop
 * network metadata from local/ISP observers; it prevents destination disclosure in
 * canonical state and app logs.
 */

import {
  createUtilityClient,
  formatUtilityError,
  initializeUtilityFromShyConfig
} from "./utilityClient.js";

const REQUIRED_FLOWS = [
  "hop_route_store",
  "hop_route_reveal",
  "biometric_rederive"
];

function isValidIPv4(value) {
  if (typeof value !== "string") return false;
  const parts = value.trim().split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d+$/.test(part)) return false;
    const n = Number(part);
    return n >= 0 && n <= 255;
  });
}

function isLikelyIPv6(value) {
  if (typeof value !== "string") return false;
  const candidate = value.trim();
  return candidate.includes(":") && /^[0-9a-fA-F:]+$/.test(candidate);
}

function assertDestinationAddress(address) {
  if (!address || typeof address !== "string") {
    throw new Error("destinationAddress is required.");
  }

  const valid = isValidIPv4(address) || isLikelyIPv6(address);
  if (!valid) {
    throw new Error("destinationAddress must be a valid IPv4 or IPv6 address.");
  }
}

function normalizeRoutePayload({
  routeID,
  destinationAddress,
  destinationPort,
  transport = "tcp",
  ttlMs = 120000,
  policyTag = null,
  metadata = null
}) {
  if (!routeID) {
    throw new Error("routeID is required.");
  }

  assertDestinationAddress(destinationAddress);

  if (
    !Number.isFinite(destinationPort) ||
    destinationPort < 1 ||
    destinationPort > 65535
  ) {
    throw new Error("destinationPort must be an integer in the range 1-65535.");
  }

  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new Error("ttlMs must be a positive number.");
  }

  return {
    schema: "shyhop.route.v1",
    route_id: routeID,
    destination_address: destinationAddress,
    destination_port: Math.trunc(destinationPort),
    transport,
    ttl_ms: Math.trunc(ttlMs),
    policy_tag: policyTag,
    metadata: metadata ?? {},
    issued_at: Date.now()
  };
}

export function assertHopManifest(shyconfig) {
  const productType = shyconfig?.app?.product_type;
  const validProductTypes = new Set([
    "shyhop",
    "shystream",
    "shycam",
    "shyiot"
  ]);
  if (!validProductTypes.has(productType)) {
    throw new Error(
      "shyhop requires app.product_type to be one of: shyhop, shystream, shycam, shyiot."
    );
  }

  if (!shyconfig?.anon_layer?.black_box_required) {
    throw new Error("shyhop requires anon_layer.black_box_required=true.");
  }

  if (!shyconfig?.signing?.required || shyconfig?.signing?.backend === "none") {
    throw new Error("shyhop requires protocol signing.");
  }

  if (!shyconfig?.store) {
    throw new Error("shyhop requires a store block.");
  }

  const activeFlows = new Set(shyconfig?.anon_layer?.required_flows ?? []);
  for (const flow of REQUIRED_FLOWS) {
    if (!activeFlows.has(flow)) {
      throw new Error(`shyhop manifest missing required flow: ${flow}`);
    }
  }
}

export function createHopClient({
  defaultBase = "/api",
  storageKey = "shyware_hop_api_base",
  fetchImpl = globalThis.fetch?.bind(globalThis),
  getAuthHeaders = null,
  manifest = null,
  deriveSealerKey = null,
  signMessage = null,
  getIdentityAttestation = null
} = {}) {
  const utilityClient = createUtilityClient({
    utilityName: "shyhop",
    utilityConfigKey: "hop",
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
      const base = utilityClient.initialize();
      return {
        ...base,
        utilityType: "shyhop"
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

    sealFollowUpDestination({
      bucketID,
      routeID,
      destinationAddress,
      destinationPort,
      transport = "tcp",
      ttlMs = 120000,
      policyTag = null,
      metadata = null,
      partitionID = "sealed"
    }) {
      const payload = normalizeRoutePayload({
        routeID,
        destinationAddress,
        destinationPort,
        transport,
        ttlMs,
        policyTag,
        metadata
      });

      return utilityClient.writeUtilityRecord({
        bucketID,
        payload,
        category: "hop_route",
        partitionID
      });
    },

    revealFollowUpDestination({ bucketID, secretID }) {
      return utilityClient.readUtilityRecord({ bucketID, secretID });
    },

    rotateFollowUpDestination({
      bucketID,
      oldSecretID,
      routeID,
      destinationAddress,
      destinationPort,
      transport = "tcp",
      ttlMs = 120000,
      policyTag = null,
      metadata = null
    }) {
      const newPayload = normalizeRoutePayload({
        routeID,
        destinationAddress,
        destinationPort,
        transport,
        ttlMs,
        policyTag,
        metadata
      });

      return utilityClient.rotateUtilityRecord({
        bucketID,
        oldSecretID,
        payload: newPayload
      });
    }
  };
}

export function initializeFromShyConfig(shyconfig, options = {}) {
  assertHopManifest(shyconfig);
  initializeUtilityFromShyConfig(shyconfig, {
    utilityName: "shyhop",
    utilityConfigKey: "hop",
    storageKey: "shyware_hop_api_base",
    ...options
  });

  return createHopClient({
    defaultBase: shyconfig.api?.base_url ?? "/api",
    storageKey:
      shyconfig.api?.storage_key ??
      options.storageKey ??
      "shyware_hop_api_base",
    fetchImpl: options.fetchImpl,
    getAuthHeaders: options.getAuthHeaders,
    manifest: shyconfig,
    deriveSealerKey: options.deriveSealerKey,
    signMessage: options.signMessage,
    getIdentityAttestation: options.getIdentityAttestation
  });
}

export function formatHopError(error) {
  return formatUtilityError(error) || "Hop operation failed.";
}

// Utility-style aliases.
export const createHopUtility = createHopClient;
export const initializeFromShywareConfig = initializeFromShyConfig;
