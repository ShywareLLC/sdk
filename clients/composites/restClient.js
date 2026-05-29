import {
  createChatClient,
  formatChatError,
} from "../embodiments/chatClient.js";
import {
  createStoreClient,
  formatStoreError,
} from "../embodiments/storeClient.js";

export const REST_MANIFEST_CONTRACT_VERSION = "shyrest-v1";

function cloneManifest(manifest) {
  return JSON.parse(JSON.stringify(manifest ?? {}));
}

function deriveStoreManifest(manifest) {
  const storeManifest = cloneManifest(manifest);
  storeManifest.contract_version = "shystore-v1";
  storeManifest.app = {
    ...storeManifest.app,
    product_type: "shystore",
  };
  return storeManifest;
}

function deriveChatManifest(manifest) {
  const chatManifest = cloneManifest(manifest);
  chatManifest.contract_version = "shychat-v1";
  chatManifest.app = {
    ...chatManifest.app,
    product_type: "shychat",
  };
  chatManifest.identity = {
    ...(chatManifest.identity ?? {}),
    surface_model:
      chatManifest.identity?.surface_model ??
      chatManifest.messaging?.surface_model ??
      "mail",
  };
  return chatManifest;
}

export function assertRestManifest(shyconfig) {
  if (shyconfig?.contract_version !== REST_MANIFEST_CONTRACT_VERSION) {
    throw new Error(
      `shyconfig must declare contract_version=${REST_MANIFEST_CONTRACT_VERSION} for shyrest apps.`
    );
  }
  if (shyconfig?.app?.product_type !== "shyrest") {
    throw new Error("shyconfig product_type must be shyrest for shyrest apps.");
  }
  if (!shyconfig?.store || !shyconfig?.messaging) {
    throw new Error(
      "shyrest requires both store and messaging blocks in shyconfig."
    );
  }
  if (!shyconfig?.domains?.private?.console) {
    throw new Error(
      "shyrest requires domains.private.console for its regulated private surface."
    );
  }
  if (!shyconfig?.anon_layer?.black_box_required) {
    throw new Error("shyrest requires anon_layer.black_box_required=true.");
  }
}

export function createRestClient({
  defaultBase = "/api",
  storageKey = "shyware_rest_api_base",
  fetchImpl = globalThis.fetch?.bind(globalThis),
  getAuthHeaders = null,
  manifest = null,
  deriveSealerKey = null,
  signMessage = null,
  getIdentityAttestation = null,
} = {}) {
  assertRestManifest(manifest);

  const storeClient = createStoreClient({
    defaultBase,
    storageKey,
    fetchImpl,
    getAuthHeaders,
    manifest: deriveStoreManifest(manifest),
    deriveSealerKey,
    signMessage,
    getIdentityAttestation,
  });

  const chatClient = createChatClient({
    defaultBase,
    storageKey,
    fetchImpl,
    getAuthHeaders,
    manifest: deriveChatManifest(manifest),
    deriveSealerKey,
  });

  return {
    initialize() {
      return {
        contractVersion: manifest?.contract_version ?? null,
        appId: manifest?.app?.id ?? null,
        productType: manifest?.app?.product_type ?? null,
        apiBase: storeClient.getBase(),
        domains: manifest?.domains ?? null,
        identity: manifest?.identity ?? null,
        deployment: manifest?.deployment ?? null,
        store: storeClient.initialize(),
        messaging: chatClient.initialize(),
      };
    },
    getBase: storeClient.getBase,
    setBase(url) {
      storeClient.setBase(url);
      chatClient.setBase(url);
    },
    getManifest: () => manifest,

    getStoreClient: () => storeClient,
    getChatClient: () => chatClient,
    createBucket: storeClient.createBucket,
    listBuckets: storeClient.listBuckets,
    getBucket: storeClient.getBucket,
    storeSubmission: storeClient.storeSubmission,
    revealStore: storeClient.revealStore,
    revealAndDecryptStore: storeClient.revealAndDecryptStore,
    rotateStore: storeClient.rotateStore,
    closeBucket: storeClient.closeBucket,
    listMailboxes: chatClient.listMailboxes,
    getMailbox: chatClient.getMailbox,
    createMailbox: chatClient.createMailbox,
    queueDispatch: chatClient.queueDispatch,
  };
}

export function initializeFromShyConfig(shyconfig, options = {}) {
  assertRestManifest(shyconfig);

  const requiresAuth =
    shyconfig.api?.requires_auth === true ||
    (shyconfig.api?.auth_scheme && shyconfig.api.auth_scheme !== "none");

  if (requiresAuth && typeof options.getAuthHeaders !== "function") {
    throw new Error(
      "shyconfig requires authenticated shyrest API access, but no auth header provider was supplied."
    );
  }

  return createRestClient({
    defaultBase: shyconfig.api?.base_url ?? "/api",
    storageKey:
      shyconfig.api?.storage_key ??
      options.storageKey ??
      "shyware_rest_api_base",
    fetchImpl: options.fetchImpl,
    getAuthHeaders: options.getAuthHeaders,
    manifest: shyconfig,
    deriveSealerKey: options.deriveSealerKey,
    signMessage: options.signMessage,
    getIdentityAttestation: options.getIdentityAttestation,
  });
}

export function formatRestError(error) {
  return (
    formatStoreError(error) ||
    formatChatError(error) ||
    "Shyrest operation failed."
  );
}
