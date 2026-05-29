/**
 * App-facing web SDK for shybrowser-v1.
 *
 * Shybrowser is not a shywire account client. Its utility is sealed local
 * browser/session storage plus optional sealed identity-side submission for
 * operator reconciliation.
 */

import { openPayload, sealPayload } from "../../protocol/sealer.js";

export const BROWSER_MANIFEST_CONTRACT_VERSION = "shybrowser-v1";

function normalizeBase(base) {
  if (base == null || base === "") return "";
  return String(base).endsWith("/") ? String(base).slice(0, -1) : String(base);
}

function joinBaseAndPath(base, path) {
  return `${normalizeBase(base)}${path}`;
}

function randomRecordID() {
  const bytes = globalThis.crypto?.getRandomValues?.(new Uint8Array(16));
  if (!bytes) {
    return `browser-${Date.now()}`;
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function parseStoredRecords(raw) {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function assertBrowserManifest(manifest) {
  if (!manifest) {
    throw new Error("shybrowser requires a manifest/config.");
  }
  if (manifest.contract_version !== BROWSER_MANIFEST_CONTRACT_VERSION) {
    throw new Error(
      `shybrowser manifest must declare contract_version=${BROWSER_MANIFEST_CONTRACT_VERSION}`
    );
  }
  if (manifest?.app?.product_type && manifest.app.product_type !== "shybrowser") {
    throw new Error(
      "shybrowser manifest must declare app.product_type=shybrowser when product_type is present."
    );
  }
  if (!manifest.sealer || manifest.sealer.mode !== "sealed_storage") {
    throw new Error("shybrowser manifest must set sealer.mode=sealed_storage");
  }
}

export function createBrowserClient({
  defaultBase = "/api",
  storageKey = "browser_sessions",
  fetchImpl = globalThis.fetch?.bind(globalThis),
  getAuthHeaders = null,
  manifest,
  deriveSealerKey
} = {}) {
  assertBrowserManifest(manifest);

  let memoryRecords = [];

  function getBase() {
    if (typeof localStorage === "undefined") return defaultBase;
    return localStorage.getItem(`${storageKey}:api_base`) || defaultBase;
  }

  function setBase(url) {
    if (typeof localStorage === "undefined") return;
    const key = `${storageKey}:api_base`;
    if (!url) {
      localStorage.removeItem(key);
      return;
    }
    localStorage.setItem(key, url);
  }

  function readRecords() {
    if (typeof localStorage === "undefined") {
      return [...memoryRecords];
    }
    return parseStoredRecords(localStorage.getItem(storageKey));
  }

  function writeRecords(records) {
    if (typeof localStorage === "undefined") {
      memoryRecords = [...records];
      return;
    }
    localStorage.setItem(storageKey, JSON.stringify(records));
  }

  async function resolveHeaders(extraHeaders = {}) {
    if (!getAuthHeaders) return extraHeaders;
    const authHeaders = await getAuthHeaders();
    return { ...authHeaders, ...extraHeaders };
  }

  async function storeSealedBrowserData(
    data,
    category = "browser_session",
    isList2 = false
  ) {
    const sealedPayload = await sealPayload(data, deriveSealerKey);
    const record = {
      id: randomRecordID(),
      category,
      list: isList2 ? 2 : 1,
      createdAt: Date.now(),
      sealedPayload
    };
    const records = readRecords();
    records.push(record);
    writeRecords(records);
    return record;
  }

  function getStoredBrowserData(category = null) {
    const records = readRecords();
    if (!category) return records;
    return records.filter((record) => record.category === category);
  }

  async function getStoredBrowserDataDecrypted(category = null) {
    const records = getStoredBrowserData(category);
    return Promise.all(
      records.map(async (record) => ({
        ...record,
        data: await openPayload(record.sealedPayload, deriveSealerKey)
      }))
    );
  }

  async function submitList2IdentityAttribute(
    identityAttribute,
    category = "ip_address"
  ) {
    if (!fetchImpl) {
      throw new Error("fetch is required to submit List 2 identity attributes.");
    }

    const sealedPayload = await sealPayload(
      { value: identityAttribute },
      deriveSealerKey
    );

    const res = await fetchImpl(joinBaseAndPath(getBase(), "/list2-identity"), {
      method: "POST",
      headers: await resolveHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ category, sealedPayload })
    });

    if (!res.ok) {
      throw new Error("Failed to submit List 2 identity attribute");
    }

    return res.json();
  }

  return {
    initialize() {
      return {
        contractVersion: manifest.contract_version,
        productType: manifest?.app?.product_type ?? null,
        apiBase: getBase(),
        sealerMode: manifest.sealer.mode,
        storageKey
      };
    },
    getBase,
    setBase,
    getManifest: () => manifest,

    storeSealedBrowserData,
    getStoredBrowserData,
    getStoredBrowserDataDecrypted,
    submitList2IdentityAttribute
  };
}

export function initializeFromShyConfig(shyconfig, options = {}) {
  assertBrowserManifest(shyconfig);

  const requiresAuth =
    shyconfig.api?.requires_auth === true ||
    (shyconfig.api?.auth_scheme && shyconfig.api.auth_scheme !== "none");

  if (requiresAuth && typeof options.getAuthHeaders !== "function") {
    throw new Error(
      "shyconfig requires authenticated shybrowser API access, but no auth header provider was supplied."
    );
  }

  return createBrowserClient({
    defaultBase: shyconfig.api?.base_url ?? "/api",
    storageKey:
      shyconfig.api?.storage_key ??
      options.storageKey ??
      "browser_sessions",
    fetchImpl: options.fetchImpl,
    getAuthHeaders: options.getAuthHeaders,
    manifest: shyconfig,
    deriveSealerKey: options.deriveSealerKey
  });
}

export function formatBrowserError(error) {
  return error?.message || "Browser operation failed.";
}
