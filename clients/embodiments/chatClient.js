/**
 * App-facing web SDK for shychat-style confidential messaging surfaces.
 *
 * Apps should treat this client as the only entrypoint into mailbox flows:
 * mailbox creation, dispatch queueing, attested close, and recovery receipts.
 *
 * IMPORTANT: The sealer (AES-GCM encryption, two-party oracle) is ONLY for PII/high-risk payloads, as specified in shyconfig.sealer. Default is structural anonymity via invariant.
 * Uses shared sealer logic from shywareSealer.js for PII/high-risk payloads. Accepts async deriveSealerKey for idempotent, ephemeral key derivation. All gating is driven by the 'sealer' block in config.
 */
import { sealPayload, openPayload } from "../../protocol/sealer.js";

// shychat-v1 is the canonical contract version for all messaging surfaces.
export const CHAT_MANIFEST_CONTRACT_VERSION = "shychat-v1";

function normalizeBase(base) {
  if (base == null || base === "") return "";
  return String(base).endsWith("/") ? String(base).slice(0, -1) : String(base);
}

function joinBaseAndPath(base, path) {
  return `${normalizeBase(base)}${path}`;
}

async function parseJson(res) {
  return res.json().catch(() => ({}));
}

export function assertChatManifest(shyconfig) {
  const cv = shyconfig?.contract_version;
  if (cv !== CHAT_MANIFEST_CONTRACT_VERSION) {
    throw new Error(
      `shyconfig must declare contract_version=shychat-v1 for shychat apps (got: ${cv}).`
    );
  }

  const surfaceModel =
    shyconfig?.identity?.surface_model ?? shyconfig?.messaging?.surface_model;
  if (!["mail", "chat"].includes(surfaceModel)) {
    throw new Error(
      'shyconfig identity.surface_model must be "mail" or "chat" for shychat apps.'
    );
  }

  if (shyconfig?.app?.product_type !== "shychat") {
    throw new Error("shyconfig product_type must be shychat for shychat apps.");
  }

  if (!shyconfig?.domains?.private?.console) {
    throw new Error(
      "shyconfig must declare a private console domain for shychat apps."
    );
  }

  if (!shyconfig?.messaging) {
    throw new Error(
      "shyconfig must include a messaging block for contract_version=shychat-v1."
    );
  }
}

export function createChatClient({
  defaultBase = "/api",
  storageKey = "shyware_chat_api_base",
  fetchImpl = globalThis.fetch?.bind(globalThis),
  getAuthHeaders = null,
  manifest = null,
  deriveSealerKey = null // async () => provider-issued secret (string or ArrayBuffer)
} = {}) {
  if (!fetchImpl) {
    throw new Error("fetch is required by the shychat client.");
  }

  function getBase() {
    if (typeof localStorage === "undefined") return defaultBase;
    return localStorage.getItem(storageKey) || defaultBase;
  }

  function setBase(url) {
    if (typeof localStorage === "undefined") return;
    if (!url) {
      localStorage.removeItem(storageKey);
      return;
    }
    localStorage.setItem(storageKey, url);
  }

  async function resolveHeaders(extraHeaders = {}) {
    if (!getAuthHeaders) return extraHeaders;
    const authHeaders = await getAuthHeaders();
    return {
      ...authHeaders,
      ...extraHeaders
    };
  }

  async function get(path) {
    let res;
    try {
      res = await fetchImpl(joinBaseAndPath(getBase(), path), {
        headers: await resolveHeaders()
      });
    } catch {
      throw new Error(
        "API not reachable - check Settings or your network connection."
      );
    }
    const body = await parseJson(res);
    if (!res.ok) {
      throw new Error(body.error ?? `HTTP ${res.status}`);
    }
    return body;
  }

  async function post(path, body) {
    let res;
    try {
      res = await fetchImpl(joinBaseAndPath(getBase(), path), {
        method: "POST",
        headers: await resolveHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(body)
      });
    } catch {
      throw new Error(
        "API not reachable - check Settings or your network connection."
      );
    }
    const payload = await parseJson(res);
    if (!res.ok) {
      throw new Error(payload.error ?? `HTTP ${res.status}`);
    }
    return payload;
  }

  // Sealing helpers for PII/high-risk payloads (gated by manifest.sealer)
  async function sealChatPayload(payload) {
    if (manifest?.sealer?.enabled === true) {
      if (typeof deriveSealerKey !== "function") {
        throw new Error(
          "Production sealer requires async deriveSealerKey() for idempotent, ephemeral key derivation"
        );
      }
      return sealPayload(payload, deriveSealerKey);
    }
    // If not PII/high-risk, return plaintext (structural anonymity only)
    return payload;
  }

  async function openChatPayload(sealedPayload) {
    if (manifest?.sealer?.enabled === true) {
      if (typeof deriveSealerKey !== "function") {
        throw new Error(
          "Production sealer requires async deriveSealerKey() for idempotent, ephemeral key derivation"
        );
      }
      return openPayload(sealedPayload, deriveSealerKey);
    }
    // If not PII/high-risk, return as-is
    return sealedPayload;
  }

  return {
    initialize() {
      return {
        contractVersion: manifest?.contract_version ?? null,
        appId: manifest?.app?.id ?? null,
        appName: manifest?.app?.name ?? null,
        chainId: manifest?.app?.chain_id ?? null,
        apiBase: getBase(),
        domains: manifest?.domains ?? null,
        identity: manifest?.identity ?? null,
        deployment: manifest?.deployment ?? null,
        attestationMode:
          manifest?.deployment?.attestation?.mode ?? "period_close",
        surfaceModel: manifest?.identity?.surface_model ?? "chat",
        accountModel: manifest?.identity?.account_model ?? "single_account",
        participantBinding:
          manifest?.identity?.participant_binding ??
          "scoped_commitment_optional",
        payloadModel:
          manifest?.messaging?.payload_model ?? "sealed_private_content",
        auditModel:
          manifest?.messaging?.audit_model ?? "delivery_commitment_only",
        allowedPayloadFormats: manifest?.messaging?.allowed_payload_formats ?? [
          "mail_text"
        ],
        mailboxModel: manifest?.messaging?.mailbox_model ?? "single_mailbox",
        deliveryModel: manifest?.messaging?.delivery_model ?? "dispatch_queue",
        retentionPolicy: manifest?.messaging?.retention_policy ?? "no_retention"
      };
    },
    getBase,
    setBase,
    getManifest: () => manifest,

    // ...existing API methods...
    sealChatPayload,
    openChatPayload,
    // ...existing API methods...
    listMailboxes: async () => {
      const payload = await get("/messages/mailboxes");
      return payload.mailboxes ?? [];
    },
    getMailbox: async (mailboxId, { includeContent = true } = {}) => {
      const payload = await get(
        `/messages/mailboxes/${mailboxId}?include_content=${includeContent ? "true" : "false"}`
      );
      return payload.mailbox ?? null;
    },
    createMailbox: async ({
      label,
      address,
      routeHint,
      accountLabel,
      accountScope,
      auditPolicy
    }) => {
      const payload = await post("/messages/mailboxes", {
        label,
        address,
        route_hint: routeHint,
        account_label: accountLabel,
        account_scope: accountScope,
        audit_policy: auditPolicy
      });
      return payload.mailbox ?? null;
    },
    queueDispatch: async ({
      mailboxId,
      recipientAddress,
      subject,
      body,
      deliveryWindow,
      contentClass,
      payloadFormat,
      privateFields,
      auditMode,
      attachmentRefs
    }) => {
      // Example: seal the body if PII/high-risk
      const sealedBody = await sealChatPayload(body);
      return post("/messages/dispatches", {
        mailbox_id: mailboxId,
        recipient_address: recipientAddress,
        subject,
        body: sealedBody,
        delivery_window: deliveryWindow,
        content_class: contentClass,
        payload_format: payloadFormat,
        private_fields: privateFields,
        audit_mode: auditMode,
        attachment_refs: attachmentRefs
      });
    },
    attestClose: async (mailboxId) => {
      const payload = await post(`/messages/mailboxes/${mailboxId}/close`, {});
      return payload.mailbox ?? null;
    },
    writeRecoveryReceipt: async (mailboxId) => {
      const payload = await post(
        `/messages/mailboxes/${mailboxId}/receipt`,
        {}
      );
      return payload.receipt ?? null;
    },
    readRecoveryReceipt: async (mailboxId) => {
      const payload = await get(`/messages/mailboxes/${mailboxId}/receipt`);
      return payload.receipt ?? null;
    }
  };
}

export function initializeFromShyConfig(shyconfig, options = {}) {
  assertChatManifest(shyconfig);

  const requiresAuth =
    shyconfig.api?.requires_auth === true ||
    (shyconfig.api?.auth_scheme && shyconfig.api.auth_scheme !== "none");

  if (requiresAuth && typeof options.getAuthHeaders !== "function") {
    throw new Error(
      "shyconfig requires authenticated chat API access, but no auth header provider was supplied."
    );
  }

  return createChatClient({
    defaultBase: shyconfig.api?.base_url ?? "/api",
    storageKey:
      shyconfig.api?.storage_key ??
      options.storageKey ??
      "shyware_chat_api_base",
    fetchImpl: options.fetchImpl,
    getAuthHeaders: options.getAuthHeaders,
    manifest: shyconfig,
    deriveSealerKey: options.deriveSealerKey
  });
}

export function formatChatError(error) {
  return error?.message || "Messaging request failed.";
}
