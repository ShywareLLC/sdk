/**
 * App-facing web SDK for shystream-v1.
 *
 * shystream reuses shystore sealed-payload semantics for stream metadata,
 * events, and optional clip/session artifacts. This module wraps storeClient
 * so stream products can remain modular from shycam while still using
 * shyPayload-style sealing.
 */

import { createStoreClient, formatStoreError } from "../embodiments/storeClient.js";
import {
  applyStoreAnonLayerDefaults,
  assertStoreBackedAnonLayer
} from "../../protocol/anonLayer.js";

export const STREAM_MANIFEST_CONTRACT_VERSION = "shystream-v1";

const REQUIRED_FLOWS = [
  "stream_event",
  "stream_clip",
  "stream_read",
  "biometric_rederive"
];

const REQUIRED_HOP_FLOWS = ["hop_route_store", "hop_route_reveal"];

function applyShystreamHopDefaults(shyconfig) {
  if (shyconfig?.contract_version !== STREAM_MANIFEST_CONTRACT_VERSION) {
    return;
  }

  if (!shyconfig.anon_layer || typeof shyconfig.anon_layer !== "object") {
    shyconfig.anon_layer = {};
  }

  const requiredFlows = new Set(shyconfig.anon_layer.required_flows ?? []);
  for (const flow of REQUIRED_HOP_FLOWS) {
    requiredFlows.add(flow);
  }
  shyconfig.anon_layer.required_flows = Array.from(requiredFlows);
}

export function assertStreamManifest(shyconfig) {
  applyStoreAnonLayerDefaults(shyconfig);
  applyShystreamHopDefaults(shyconfig);

  if (shyconfig?.contract_version !== STREAM_MANIFEST_CONTRACT_VERSION) {
    throw new Error(
      `shyconfig must declare contract_version=${STREAM_MANIFEST_CONTRACT_VERSION} for shystream apps.`
    );
  }

  if (shyconfig?.app?.product_type !== "shystream") {
    throw new Error(
      "shyconfig product_type must be shystream for shystream apps."
    );
  }

  if (!shyconfig?.anon_layer?.black_box_required) {
    throw new Error(
      "shyconfig must require the anonymous layer as a black box."
    );
  }

  if (!shyconfig?.signing?.required || shyconfig.signing.backend === "none") {
    throw new Error(
      "shyconfig must require protocol signing for shystream apps."
    );
  }

  if (!shyconfig?.store) {
    throw new Error(
      "shystream requires a store block because it reuses shystore sealed payload semantics."
    );
  }

  assertStoreBackedAnonLayer(shyconfig, "shystream");

  if (!shyconfig?.stream) {
    throw new Error(
      "shystream requires a stream block with provider and ingestion settings."
    );
  }

  if (!shyconfig?.stream?.provider) {
    throw new Error("shystream requires stream.provider in the stream block.");
  }

  if (!shyconfig?.domains?.private?.console) {
    throw new Error(
      "shystream requires domains.private.console for private operator routing."
    );
  }

  const activeFlows = new Set(shyconfig?.anon_layer?.required_flows ?? []);
  for (const flow of [...REQUIRED_FLOWS, ...REQUIRED_HOP_FLOWS]) {
    if (!activeFlows.has(flow)) {
      throw new Error(`shyconfig is missing required shystream flow: ${flow}`);
    }
  }
}

export function createStreamClient({
  defaultBase = "/api",
  storageKey = "shyware_stream_api_base",
  fetchImpl = globalThis.fetch?.bind(globalThis),
  getAuthHeaders = null,
  manifest = null,
  deriveSealerKey = null,
  signMessage = null,
  getIdentityAttestation = null
} = {}) {
  if (!fetchImpl) {
    throw new Error("fetch is required by the shystream client.");
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

  function normalizeSegmentPayload({
    streamID,
    playbackID = null,
    sequence,
    startedAt = null,
    endedAt = null,
    mimeType = "video/mp2t",
    codec = "h264",
    segment = null,
    segmentRef = null,
    metadata = null,
    mode = "live"
  }) {
    if (!streamID) {
      throw new Error("streamID is required for sealed stream segments.");
    }
    if (!Number.isFinite(sequence) || sequence < 0) {
      throw new Error("sequence must be a non-negative number.");
    }
    if (segment == null && segmentRef == null) {
      throw new Error("Either segment or segmentRef is required.");
    }

    return {
      schema: "shystream.segment.v1",
      mode,
      stream_id: streamID,
      playback_id: playbackID,
      sequence,
      started_at: startedAt ?? Date.now(),
      ended_at: endedAt,
      mime_type: mimeType,
      codec,
      segment,
      segment_ref: segmentRef,
      metadata: metadata ?? {}
    };
  }

  function createLiveQueue({
    bucketID,
    streamID,
    partitionID = "sealed",
    minBatchSize = 3,
    maxBatchSize = 25,
    flushIntervalMs = 4000,
    jitterMs = 900,
    autoFlush = true,
    onFlush = null,
    onError = null
  } = {}) {
    if (!bucketID) {
      throw new Error("bucketID is required for stream queueing.");
    }
    if (!streamID) {
      throw new Error("streamID is required for stream queueing.");
    }

    const queue = [];
    let timer = null;

    function nextDelay() {
      const jitter = Math.max(0, Number(jitterMs) || 0);
      const base = Math.max(250, Number(flushIntervalMs) || 4000);
      if (jitter === 0) return base;
      return base + Math.floor(Math.random() * (jitter + 1));
    }

    function schedule() {
      if (!autoFlush || timer != null) return;
      timer = setTimeout(async () => {
        timer = null;
        try {
          await flush();
        } catch (error) {
          if (typeof onError === "function") {
            onError(error);
          }
        } finally {
          if (autoFlush && queue.length > 0) {
            schedule();
          }
        }
      }, nextDelay());
    }

    function cancelSchedule() {
      if (timer != null) {
        clearTimeout(timer);
        timer = null;
      }
    }

    async function flush({ force = false } = {}) {
      const minimum = Math.max(1, Number(minBatchSize) || 1);
      if (!force && queue.length < minimum) {
        return {
          flushed: false,
          reason: "below_min_batch",
          queueDepth: queue.length,
          minBatchSize: minimum,
          results: []
        };
      }

      const cap = Math.max(minimum, Number(maxBatchSize) || minimum);
      const pending = queue.splice(0, cap);
      const results = [];

      for (const item of pending) {
        const result = await api.sealLiveSegment({
          bucketID,
          streamID,
          sequence: item.sequence,
          segment: item.segment ?? null,
          segmentRef: item.segmentRef ?? null,
          playbackID: item.playbackID ?? null,
          startedAt: item.startedAt ?? null,
          endedAt: item.endedAt ?? null,
          mimeType: item.mimeType ?? "video/mp2t",
          codec: item.codec ?? "h264",
          metadata: item.metadata ?? null,
          partitionID
        });

        results.push({
          ...result,
          sequence: item.sequence,
          segmentRef: item.segmentRef ?? null
        });
      }

      const summary = {
        flushed: true,
        count: results.length,
        queueDepth: queue.length,
        results
      };

      if (typeof onFlush === "function") {
        onFlush(summary);
      }

      if (autoFlush && queue.length > 0) {
        schedule();
      }

      return summary;
    }

    function enqueue(segment) {
      if (!segment || !Number.isFinite(segment.sequence)) {
        throw new Error("Queued segment requires a numeric sequence.");
      }
      if (segment.segment == null && segment.segmentRef == null) {
        throw new Error("Queued segment requires segment or segmentRef.");
      }

      queue.push(segment);
      if (autoFlush) {
        schedule();
      }

      return {
        enqueued: true,
        queueDepth: queue.length,
        nextSequence: queue[queue.length - 1]?.sequence ?? null
      };
    }

    return {
      enqueue,
      flush,
      clear() {
        queue.length = 0;
        cancelSchedule();
      },
      stop() {
        cancelSchedule();
      },
      start() {
        if (queue.length > 0) {
          schedule();
        }
      },
      status() {
        return {
          queueDepth: queue.length,
          autoFlush,
          minBatchSize: Math.max(1, Number(minBatchSize) || 1),
          flushIntervalMs: Math.max(250, Number(flushIntervalMs) || 4000),
          jitterMs: Math.max(0, Number(jitterMs) || 0)
        };
      }
    };
  }

  const api = {
    initialize() {
      const base = storeClient.initialize();
      return {
        ...base,
        chainId: manifest?.app?.chain_id ?? null,
        productType: manifest?.app?.product_type ?? null,
        signing: manifest?.signing ?? null,
        deployment: manifest?.deployment ?? null,
        identity: manifest?.identity ?? null,
        stream: manifest?.stream ?? null,
        provider: manifest?.stream?.provider ?? null,
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
    sealPayload: storeClient.sealPayload,
    openPayload: storeClient.openPayload,
    createStreamEvent({
      bucketID,
      payload,
      category = "stream_event",
      partitionID = "sealed"
    }) {
      return storeClient.storeSubmission({
        scopingId: bucketID,
        plaintext: payload,
        category,
        partitionID
      });
    },
    createStreamClip({
      bucketID,
      payload,
      category = "stream_clip",
      partitionID = "sealed"
    }) {
      return storeClient.storeSubmission({
        scopingId: bucketID,
        plaintext: payload,
        category,
        partitionID
      });
    },
    sealVideoSegment({
      bucketID,
      streamID,
      sequence,
      segment = null,
      segmentRef = null,
      playbackID = null,
      startedAt = null,
      endedAt = null,
      mimeType = "video/mp2t",
      codec = "h264",
      metadata = null,
      partitionID = "sealed"
    }) {
      const payload = normalizeSegmentPayload({
        streamID,
        playbackID,
        sequence,
        startedAt,
        endedAt,
        mimeType,
        codec,
        segment,
        segmentRef,
        metadata,
        mode: "vod"
      });

      return storeClient.storeSubmission({
        scopingId: bucketID,
        plaintext: payload,
        category: "stream_clip",
        partitionID
      });
    },
    sealLiveSegment({
      bucketID,
      streamID,
      sequence,
      segment = null,
      segmentRef = null,
      playbackID = null,
      startedAt = null,
      endedAt = null,
      mimeType = "video/mp2t",
      codec = "h264",
      metadata = null,
      partitionID = "sealed"
    }) {
      const payload = normalizeSegmentPayload({
        streamID,
        playbackID,
        sequence,
        startedAt,
        endedAt,
        mimeType,
        codec,
        segment,
        segmentRef,
        metadata,
        mode: "live"
      });

      return storeClient.storeSubmission({
        scopingId: bucketID,
        plaintext: payload,
        category: "stream_event",
        partitionID
      });
    },
    revealStreamRecord({ bucketID, submissionId }) {
      return storeClient.revealAndDecryptStore({ scopingId: bucketID, submissionId });
    },
    revealVideoSegment({ bucketID, submissionId }) {
      return storeClient.revealAndDecryptStore({ scopingId: bucketID, submissionId });
    },
    rotateStreamRecord({ bucketID, submissionId, newPayload }) {
      return storeClient.rotateStore({
        scopingId: bucketID,
        submissionId,
        newPlaintext: newPayload
      });
    },
    rotateLiveSegment({
      bucketID,
      submissionId,
      streamID,
      sequence,
      segment = null,
      segmentRef = null,
      playbackID = null,
      startedAt = null,
      endedAt = null,
      mimeType = "video/mp2t",
      codec = "h264",
      metadata = null
    }) {
      const newPayload = normalizeSegmentPayload({
        streamID,
        playbackID,
        sequence,
        startedAt,
        endedAt,
        mimeType,
        codec,
        segment,
        segmentRef,
        metadata,
        mode: "live"
      });

      return storeClient.rotateStore({
        scopingId: bucketID,
        submissionId,
        newPlaintext: newPayload
      });
    },
    createLiveQueue
  };

  return api;
}

export function initializeFromShyConfig(shyconfig, options = {}) {
  applyStoreAnonLayerDefaults(shyconfig);
  assertStreamManifest(shyconfig);

  const requiresAuth =
    shyconfig.api?.requires_auth === true ||
    (shyconfig.api?.auth_scheme && shyconfig.api.auth_scheme !== "none");

  if (requiresAuth && typeof options.getAuthHeaders !== "function") {
    throw new Error(
      "shyconfig requires authenticated stream API access, but no auth header provider was supplied."
    );
  }

  return createStreamClient({
    defaultBase: shyconfig.api?.base_url ?? "/api",
    storageKey:
      shyconfig.api?.storage_key ??
      options.storageKey ??
      "shyware_stream_api_base",
    fetchImpl: options.fetchImpl,
    getAuthHeaders: options.getAuthHeaders,
    manifest: shyconfig,
    deriveSealerKey: options.deriveSealerKey,
    signMessage: options.signMessage,
    getIdentityAttestation: options.getIdentityAttestation
  });
}

export function formatStreamError(error) {
  return formatStoreError(error) || "Stream operation failed.";
}
