const crypto = require("crypto");
const { Pool } = require("pg");
const {
  normalizeTenantId: normalizeMigrationTenantId,
  normalizeMailboxRecord,
  normalizeDispatchRecord,
  normalizeReceiptRecord,
  createCheckpointPayload,
  createSignedCheckpoint,
  createExportBundle,
  verifyExportBundle
} = require("./scytaleCheckpoint");

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS verification_sessions (
  session_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  session_url TEXT NOT NULL,
  provider TEXT NOT NULL,
  status TEXT NOT NULL,
  verification_type TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  decision JSONB NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS verification_sessions_user_id_idx
  ON verification_sessions (user_id);

CREATE TABLE IF NOT EXISTS processed_webhook_events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  journey_id TEXT NULL,
  reference_no TEXT NULL,
  processed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS verification_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT '',
  session_id TEXT NOT NULL DEFAULT '',
  journey_id TEXT NOT NULL DEFAULT '',
  event TEXT NOT NULL,
  status TEXT NOT NULL,
  system_decision TEXT NULL,
  manual_decision TEXT NULL,
  final_decision TEXT NULL,
  decision JSONB NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS verification_logs_user_id_idx
  ON verification_logs (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS security_logs (
  id BIGSERIAL PRIMARY KEY,
  type TEXT NOT NULL,
  user_id TEXT NOT NULL,
  session_id TEXT NOT NULL DEFAULT '',
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS security_logs_user_id_idx
  ON security_logs (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS vote_receipts (
  user_id TEXT NOT NULL,
  poll_id TEXT NOT NULL,
  choice TEXT NOT NULL,
  ballot_id TEXT NOT NULL,
  ballot_nonce TEXT NOT NULL,
  identity_hash TEXT NOT NULL,
  receipt_version TEXT NOT NULL DEFAULT 'shyware-v1',
  receipt_escrow TEXT NOT NULL DEFAULT 'cockroach',
  submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, poll_id)
);

CREATE INDEX IF NOT EXISTS vote_receipts_poll_id_idx
  ON vote_receipts (poll_id, submitted_at DESC);

CREATE TABLE IF NOT EXISTS vote_receipt_confirmations (
  user_id TEXT NOT NULL,
  poll_id TEXT NOT NULL,
  confirmed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, poll_id)
);

CREATE INDEX IF NOT EXISTS vote_receipt_confirmations_poll_id_idx
  ON vote_receipt_confirmations (poll_id, confirmed_at DESC);

CREATE TABLE IF NOT EXISTS wire_provider_intents (
  intent_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  provider TEXT NOT NULL,
  provider_mode TEXT NOT NULL,
  issuer_name TEXT NOT NULL,
  amount NUMERIC NOT NULL,
  backing_asset TEXT NOT NULL,
  settlement_asset TEXT NOT NULL,
  external_reference TEXT NOT NULL DEFAULT '',
  requires_operator_review BOOLEAN NOT NULL DEFAULT true,
  supported_rails JSONB NOT NULL DEFAULT '[]'::jsonb,
  status TEXT NOT NULL,
  provider_status TEXT NOT NULL,
  payload JSONB NOT NULL,
  destination_network TEXT NULL,
  destination_address TEXT NULL,
  account_commitment TEXT NULL,
  payout_rail TEXT NULL,
  payout_network TEXT NULL,
  payout_destination TEXT NULL,
  provider_response JSONB NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  dispatched_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS wire_provider_intents_status_idx
  ON wire_provider_intents (status, provider_status);

CREATE TABLE IF NOT EXISTS scytale_mailboxes (
  mailbox_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  label TEXT NOT NULL,
  address TEXT NOT NULL,
  owner_uid TEXT NULL,
  account_label TEXT NOT NULL,
  account_scope TEXT NOT NULL,
  route_hint TEXT NOT NULL,
  mailbox_scope TEXT NOT NULL DEFAULT 'confidential',
  audit_policy TEXT NOT NULL DEFAULT 'delivery_commitment_only',
  delivery_state TEXT NOT NULL DEFAULT 'pending',
  delivery_window TEXT NOT NULL DEFAULT 'Awaiting close',
  excerpt TEXT NOT NULL DEFAULT '',
  counterparty_route TEXT NOT NULL DEFAULT 'unrouted',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE scytale_mailboxes
  DROP CONSTRAINT IF EXISTS scytale_mailboxes_address_key;

CREATE UNIQUE INDEX IF NOT EXISTS scytale_mailboxes_tenant_address_uidx
  ON scytale_mailboxes (tenant_id, address);

CREATE INDEX IF NOT EXISTS scytale_mailboxes_address_idx
  ON scytale_mailboxes (tenant_id, address);

CREATE INDEX IF NOT EXISTS scytale_mailboxes_tenant_idx
  ON scytale_mailboxes (tenant_id, updated_at DESC, created_at DESC);

CREATE INDEX IF NOT EXISTS scytale_mailboxes_owner_uid_idx
  ON scytale_mailboxes (tenant_id, owner_uid, updated_at DESC, created_at DESC);

CREATE TABLE IF NOT EXISTS scytale_dispatches (
  message_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  dispatch_id TEXT NOT NULL,
  mailbox_id TEXT NOT NULL,
  peer_mailbox_id TEXT NULL,
  direction TEXT NOT NULL,
  status TEXT NOT NULL,
  recipient_address TEXT NOT NULL,
  sender_address TEXT NOT NULL,
  requested_delivery_window TEXT NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL,
  payload_commitment TEXT NOT NULL,
  audit_surface JSONB NOT NULL DEFAULT '{}'::jsonb,
  content_class TEXT NOT NULL,
  payload_format TEXT NOT NULL,
  audit_mode TEXT NOT NULL,
  sensitivity TEXT NOT NULL DEFAULT 'assumed_pii',
  recovery_mode TEXT NOT NULL DEFAULT 'server_assisted_mailbox_open',
  content_disposition TEXT NOT NULL DEFAULT 'sealed_off_canonical',
  attachment_count INT NOT NULL DEFAULT 0,
  private_field_count INT NOT NULL DEFAULT 0,
  sealed_payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scytale_dispatches_mailbox_idx
  ON scytale_dispatches (mailbox_id, timestamp ASC);

CREATE INDEX IF NOT EXISTS scytale_dispatches_dispatch_idx
  ON scytale_dispatches (dispatch_id);

CREATE INDEX IF NOT EXISTS scytale_dispatches_tenant_idx
  ON scytale_dispatches (tenant_id, mailbox_id, timestamp ASC);

CREATE TABLE IF NOT EXISTS scytale_receipts (
  mailbox_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  mailbox_address TEXT NOT NULL,
  mailbox_scope TEXT NOT NULL,
  last_dispatch_id TEXT NULL,
  last_payload_commitment TEXT NULL,
  recovery_ref TEXT NOT NULL,
  recovery_mode TEXT NOT NULL,
  sealed_content BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scytale_receipts_tenant_idx
  ON scytale_receipts (tenant_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS scytale_checkpoints (
  checkpoint_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  digest TEXT NOT NULL,
  previous_checkpoint_id TEXT NULL,
  signer_public_key_fingerprint TEXT NULL,
  document JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scytale_checkpoints_tenant_idx
  ON scytale_checkpoints (tenant_id, created_at DESC);

ALTER TABLE scytale_mailboxes
  ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';

ALTER TABLE scytale_mailboxes
  ADD COLUMN IF NOT EXISTS owner_uid TEXT NULL;

ALTER TABLE scytale_dispatches
  ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';

ALTER TABLE scytale_receipts
  ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
`;

function normalizeTimestamp(value) {
  if (!value) return null;
  return value instanceof Date ? value.toISOString() : value;
}

function trimString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function mapVerificationSessionRow(row) {
  if (!row) return null;
  return {
    sessionId: row.session_id,
    userId: row.user_id,
    sessionUrl: row.session_url,
    provider: row.provider,
    status: row.status,
    verificationType: row.verification_type,
    metadata: row.metadata || {},
    decision: row.decision || null,
    createdAt: normalizeTimestamp(row.created_at),
    updatedAt: normalizeTimestamp(row.updated_at)
  };
}

function mapWireIntentRow(row) {
  if (!row) return null;
  return {
    intentId: row.intent_id,
    kind: row.kind,
    provider: row.provider,
    providerMode: row.provider_mode,
    issuerName: row.issuer_name,
    amount: Number(row.amount),
    backingAsset: row.backing_asset,
    settlementAsset: row.settlement_asset,
    externalReference: row.external_reference,
    requiresOperatorReview: row.requires_operator_review,
    supportedRails: Array.isArray(row.supported_rails)
      ? row.supported_rails
      : [],
    status: row.status,
    providerStatus: row.provider_status,
    payload: row.payload,
    destinationNetwork: row.destination_network || "",
    destinationAddress: row.destination_address || "",
    accountCommitment: row.account_commitment || "",
    payoutRail: row.payout_rail || "",
    payoutNetwork: row.payout_network || "",
    payoutDestination: row.payout_destination || "",
    providerResponse: row.provider_response || null,
    createdAt: normalizeTimestamp(row.created_at),
    updatedAt: normalizeTimestamp(row.updated_at),
    dispatchedAt: normalizeTimestamp(row.dispatched_at)
  };
}

function mapVoteReceiptRow(row) {
  if (!row) return null;
  return {
    userId: row.user_id,
    pollId: row.poll_id,
    billId: row.poll_id,
    choice: row.choice,
    vote: row.choice,
    ballotId: row.ballot_id,
    ballotNonce: row.ballot_nonce,
    identityHash: row.identity_hash,
    receiptVersion: row.receipt_version,
    receiptEscrow: row.receipt_escrow,
    submittedAt: normalizeTimestamp(row.submitted_at),
    updatedAt: normalizeTimestamp(row.updated_at)
  };
}

function mapScytaleMailboxRow(row) {
  if (!row) return null;
  return {
    id: row.mailbox_id,
    tenantId: row.tenant_id || "default",
    ownerUid: row.owner_uid || null,
    label: row.label,
    address: row.address,
    accountLabel: row.account_label,
    accountScope: row.account_scope,
    routeHint: row.route_hint,
    mailboxScope: row.mailbox_scope,
    auditPolicy: row.audit_policy,
    deliveryState: row.delivery_state,
    deliveryWindow: row.delivery_window,
    excerpt: row.excerpt,
    counterpartyRoute: row.counterparty_route,
    messages: [],
    proof: null,
    createdAt: normalizeTimestamp(row.created_at),
    updatedAt: normalizeTimestamp(row.updated_at)
  };
}

function mapScytaleDispatchRow(row) {
  if (!row) return null;
  return {
    messageId: row.message_id,
    tenantId: row.tenant_id || "default",
    dispatchId: row.dispatch_id,
    mailboxId: row.mailbox_id,
    peerMailboxId: row.peer_mailbox_id || null,
    direction: row.direction,
    status: row.status,
    recipientAddress: row.recipient_address,
    senderAddress: row.sender_address,
    requestedDeliveryWindow: row.requested_delivery_window,
    timestamp: normalizeTimestamp(row.timestamp),
    payloadCommitment: row.payload_commitment,
    auditSurface: row.audit_surface || {},
    contentClass: row.content_class,
    payloadFormat: row.payload_format,
    auditMode: row.audit_mode,
    sensitivity: row.sensitivity,
    recoveryMode: row.recovery_mode,
    contentDisposition: row.content_disposition,
    attachmentCount: Number(row.attachment_count || 0),
    privateFieldCount: Number(row.private_field_count || 0),
    sealedPayload: row.sealed_payload
  };
}

function mapScytaleReceiptRow(row) {
  if (!row) return null;
  return {
    tenantId: row.tenant_id || "default",
    mailboxId: row.mailbox_id,
    mailboxAddress: row.mailbox_address,
    mailboxScope: row.mailbox_scope,
    lastDispatchId: row.last_dispatch_id,
    lastPayloadCommitment: row.last_payload_commitment,
    recoveryRef: row.recovery_ref,
    recoveryMode: row.recovery_mode,
    sealedContent: row.sealed_content,
    createdAt: normalizeTimestamp(row.created_at),
    updatedAt: normalizeTimestamp(row.updated_at)
  };
}

function refreshMailbox(mailbox) {
  mailbox.messageCount = mailbox.messages?.length ?? 0;
  const last = mailbox.messages?.at(-1);
  mailbox.excerpt = last?.subject ?? last?.body?.slice(0, 80) ?? "";
  mailbox.proof = mailbox.proof ?? {
    periodCloseRoot: null,
    mailboxCommitment: mailbox.id ?? null,
    attestationMode: "pending",
    canonicalPosture: "non-materialized sender/message join",
    payloadAuditModel: mailbox.auditPolicy ?? "delivery_commitment_only"
  };
  return mailbox;
}

function hydrateScytaleMailbox(row, messages = []) {
  const mailbox = {
    ...row,
    messages,
    proof: row.proof || null
  };
  return refreshMailbox(mailbox);
}

function materializeScytaleMailbox(mailbox, { unsealContent = true } = {}) {
  return {
    ...mailbox,
    proof: mailbox.proof,
    messages: mailbox.messages.map((message) =>
      materializeScytaleMessage(message, { unsealContent })
    )
  };
}

function normalizeScytaleMailboxAddress(value) {
  return typeof value === "string" ? value.trim().toLowerCase().replace(/\s+/g, "-") : "";
}

function normalizeScytaleAuditMode(value) {
  const valid = ["delivery_commitment_only", "delivery_metadata_commitment"];
  const v = typeof value === "string" ? value.trim() : "";
  return valid.includes(v) ? v : "delivery_commitment_only";
}

function normalizeScytalePayloadFormat(value) {
  return typeof value === "string" ? value.trim() || "mail_text" : "mail_text";
}

function normalizeScytalePrivateFields(value) {
  if (!value || typeof value !== "object") return {};
  return value;
}

function normalizeScytaleAttachmentRefs(value) {
  if (!Array.isArray(value)) return [];
  return value.map(v => String(v).trim()).filter(Boolean);
}

function shortHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex").slice(0, 16);
}

function makeScytaleMessage({
  mailboxId, subject, body, direction, status, recipientAddress, senderAddress,
  peerMailboxId = null, dispatchId = null, requestedDeliveryWindow = "next attested close",
  contentClass = "mail", payloadFormat = "mail_text", privateFields = {},
  auditMode = "delivery_commitment_only", attachmentRefs = [],
  recoveryMode = "server_assisted_mailbox_open", sealedPayload = null,
  sensitivity = "assumed_pii"
} = {}) {
  const msgDispatchId = dispatchId || crypto.randomUUID();
  const payloadCommitment = shortHash(
    JSON.stringify({ mailboxId, subject, body, privateFields, dispatchId: msgDispatchId })
  );
  const canonicalAuditFields = auditMode === "delivery_metadata_commitment"
    ? ["payload_commitment", "delivery_window", "content_class", "payload_format"]
    : ["payload_commitment", "delivery_window"];
  return {
    messageId: crypto.randomUUID(),
    dispatchId: msgDispatchId,
    mailboxId,
    direction,
    status,
    recipientAddress,
    senderAddress,
    peerMailboxId,
    requestedDeliveryWindow,
    contentClass,
    payloadFormat,
    auditMode,
    attachmentRefs,
    recoveryMode,
    sealedPayload: sealedPayload ?? { ciphertext: shortHash(JSON.stringify({ subject, body, privateFields })) },
    payloadCommitment,
    sensitivity,
    attachmentCount: attachmentRefs.length,
    privateFieldCount: Object.keys(privateFields).length,
    contentDisposition: "sealed_off_canonical",
    auditSurface: {
      canonicalAuditFields,
      ...(auditMode === "delivery_metadata_commitment" ? { contentClass, payloadFormat, privateFieldCount: Object.keys(privateFields).length } : {})
    },
    timestamp: new Date().toISOString(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
}

function summarizeScytaleMailbox(mailbox) {
  const last = mailbox.messages?.at(-1);
  return {
    id: mailbox.id,
    label: mailbox.label,
    address: mailbox.address,
    routeHint: mailbox.routeHint,
    deliveryState: mailbox.deliveryState ?? "pending",
    messageCount: mailbox.messages?.length ?? 0,
    excerpt: last?.subject ?? last?.body?.slice(0, 80) ?? "",
    counterpartyRoute: mailbox.counterpartyRoute ?? null,
    proof: mailbox.proof ?? null,
    updatedAt: mailbox.updatedAt,
    createdAt: mailbox.createdAt,
  };
}

function materializeScytaleMessage(message, { unsealContent = true } = {}) {
  if (!unsealContent) return { ...message, body: undefined, subject: undefined };
  return { ...message };
}

function createCockroachStore({
  connectionString = process.env.COCKROACH_URL ||
    process.env.DATABASE_URL ||
    "",
  ssl = process.env.COCKROACH_SSL_MODE === "disable"
    ? false
    : {
        rejectUnauthorized:
          process.env.COCKROACH_SSL_REJECT_UNAUTHORIZED === "true"
      },
  defaultTenantId = process.env.SHYWARE_TENANT_ID ||
    process.env.SCYTALE_TENANT_ID ||
    "default"
} = {}) {
  let pool = null;
  let initPromise = null;

  function resolveTenantId(value) {
    return normalizeMigrationTenantId(value, defaultTenantId);
  }

  function isConfigured() {
    return Boolean(connectionString);
  }

  function requireConfigured() {
    if (!isConfigured()) {
      throw new Error("CockroachDB is not configured. Set COCKROACH_URL.");
    }
  }

  async function init() {
    requireConfigured();
    if (initPromise) return initPromise;
    pool = new Pool({
      connectionString,
      ssl,
      max: Number(process.env.COCKROACH_POOL_MAX || 10)
    });
    initPromise = pool.query(SCHEMA_SQL);
    await initPromise;
  }

  async function query(text, params = []) {
    await init();
    return pool.query(text, params);
  }

  async function transaction(callback) {
    await init();
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await callback(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async function fetchScytaleMessagesByMailboxIds(
    executor,
    mailboxIds,
    tenantId
  ) {
    const ids = mailboxIds.filter(Boolean);
    const grouped = new Map(ids.map((mailboxId) => [mailboxId, []]));
    if (ids.length === 0) return grouped;

    const result = await executor.query(
      `SELECT * FROM scytale_dispatches
       WHERE mailbox_id = ANY($1::text[]) AND tenant_id = $2
       ORDER BY timestamp ASC, created_at ASC`,
      [ids, resolveTenantId(tenantId)]
    );

    for (const row of result.rows) {
      const message = mapScytaleDispatchRow(row);
      if (!grouped.has(message.mailboxId)) {
        grouped.set(message.mailboxId, []);
      }
      grouped.get(message.mailboxId).push(message);
    }

    return grouped;
  }

  async function loadScytaleMailboxById(
    executor,
    mailboxId,
    tenantId,
    ownerUid = null
  ) {
    const result = await executor.query(
      `SELECT * FROM scytale_mailboxes
       WHERE mailbox_id = $1 AND tenant_id = $2
         AND ($3::text IS NULL OR owner_uid = $3)`,
      [mailboxId, resolveTenantId(tenantId), trimString(ownerUid) || null]
    );
    const row = mapScytaleMailboxRow(result.rows[0] || null);
    if (!row) return null;
    const grouped = await fetchScytaleMessagesByMailboxIds(
      executor,
      [row.id],
      row.tenantId
    );
    return hydrateScytaleMailbox(row, grouped.get(row.id) || []);
  }

  async function loadScytaleMailboxByAddress(
    executor,
    address,
    tenantId,
    ownerUid = null
  ) {
    const normalizedAddress = normalizeScytaleMailboxAddress(address);
    const result = await executor.query(
      `SELECT * FROM scytale_mailboxes
       WHERE address = $1 AND tenant_id = $2
         AND ($3::text IS NULL OR owner_uid = $3)`,
      [
        normalizedAddress,
        resolveTenantId(tenantId),
        trimString(ownerUid) || null
      ]
    );
    const row = mapScytaleMailboxRow(result.rows[0] || null);
    if (!row) return null;
    const grouped = await fetchScytaleMessagesByMailboxIds(
      executor,
      [row.id],
      row.tenantId
    );
    return hydrateScytaleMailbox(row, grouped.get(row.id) || []);
  }

  async function loadAllScytaleMailboxes(executor, tenantId, ownerUid = null) {
    const result = await executor.query(
      `SELECT * FROM scytale_mailboxes
       WHERE tenant_id = $1
         AND ($2::text IS NULL OR owner_uid = $2)
       ORDER BY updated_at DESC, created_at DESC`,
      [resolveTenantId(tenantId), trimString(ownerUid) || null]
    );
    const rows = result.rows.map(mapScytaleMailboxRow);
    const grouped = await fetchScytaleMessagesByMailboxIds(
      executor,
      rows.map((row) => row.id),
      resolveTenantId(tenantId)
    );
    return rows.map((row) =>
      hydrateScytaleMailbox(row, grouped.get(row.id) || [])
    );
  }

  async function persistScytaleMailbox(executor, mailbox) {
    await executor.query(
      `UPDATE scytale_mailboxes
       SET
         label = $2,
         address = $3,
         account_label = $4,
         account_scope = $5,
         route_hint = $6,
         mailbox_scope = $7,
         audit_policy = $8,
         delivery_state = $9,
         delivery_window = $10,
         excerpt = $11,
         counterparty_route = $12,
         owner_uid = $13,
         updated_at = now()
       WHERE mailbox_id = $1 AND tenant_id = $14`,
      [
        mailbox.id,
        mailbox.label,
        mailbox.address,
        mailbox.accountLabel,
        mailbox.accountScope,
        mailbox.routeHint,
        mailbox.mailboxScope,
        mailbox.auditPolicy,
        mailbox.deliveryState,
        mailbox.deliveryWindow,
        mailbox.excerpt,
        mailbox.counterpartyRoute,
        mailbox.ownerUid,
        mailbox.tenantId || resolveTenantId()
      ]
    );
  }

  async function insertScytaleDispatch(executor, message) {
    await executor.query(
      `INSERT INTO scytale_dispatches (
        message_id, tenant_id, dispatch_id, mailbox_id, peer_mailbox_id, direction, status,
        recipient_address, sender_address, requested_delivery_window, timestamp,
        payload_commitment, audit_surface, content_class, payload_format, audit_mode,
        sensitivity, recovery_mode, content_disposition, attachment_count,
        private_field_count, sealed_payload
      ) VALUES (
        $1,$2,$3,$4,$5,$6,$7,
        $8,$9,$10,$11::timestamptz,
        $12,$13::jsonb,$14,$15,$16,
        $17,$18,$19,$20,
        $21,$22::jsonb
      )`,
      [
        message.messageId,
        message.tenantId || resolveTenantId(),
        message.dispatchId,
        message.mailboxId,
        message.peerMailboxId,
        message.direction,
        message.status,
        message.recipientAddress,
        message.senderAddress,
        message.requestedDeliveryWindow,
        message.timestamp,
        message.payloadCommitment,
        JSON.stringify(message.auditSurface || {}),
        message.contentClass,
        message.payloadFormat,
        message.auditMode,
        message.sensitivity,
        message.recoveryMode,
        message.contentDisposition,
        message.attachmentCount,
        message.privateFieldCount,
        JSON.stringify(message.sealedPayload || {})
      ]
    );
  }

  async function updateScytaleDispatchStatus(
    executor,
    messageId,
    status,
    tenantId
  ) {
    await executor.query(
      `UPDATE scytale_dispatches SET status = $2 WHERE message_id = $1 AND tenant_id = $3`,
      [messageId, status, resolveTenantId(tenantId)]
    );
  }

  async function loadScytaleTenantRows(executor, tenantId) {
    const resolvedTenantId = resolveTenantId(tenantId);
    const [mailboxResult, dispatchResult, receiptResult] = await Promise.all([
      executor.query(
        `SELECT * FROM scytale_mailboxes
         WHERE tenant_id = $1
         ORDER BY created_at ASC, mailbox_id ASC`,
        [resolvedTenantId]
      ),
      executor.query(
        `SELECT * FROM scytale_dispatches
         WHERE tenant_id = $1
         ORDER BY created_at ASC, message_id ASC`,
        [resolvedTenantId]
      ),
      executor.query(
        `SELECT * FROM scytale_receipts
         WHERE tenant_id = $1
         ORDER BY created_at ASC, mailbox_id ASC`,
        [resolvedTenantId]
      )
    ]);

    return {
      tenantId: resolvedTenantId,
      mailboxes: mailboxResult.rows.map(normalizeMailboxRecord),
      dispatches: dispatchResult.rows.map(normalizeDispatchRecord),
      receipts: receiptResult.rows.map(normalizeReceiptRecord)
    };
  }

  async function saveScytaleCheckpoint(executor, checkpoint) {
    await executor.query(
      `INSERT INTO scytale_checkpoints (
        checkpoint_id, tenant_id, digest, previous_checkpoint_id,
        signer_public_key_fingerprint, document
      ) VALUES ($1,$2,$3,$4,$5,$6::jsonb)
      ON CONFLICT (checkpoint_id) DO UPDATE SET
        tenant_id = EXCLUDED.tenant_id,
        digest = EXCLUDED.digest,
        previous_checkpoint_id = EXCLUDED.previous_checkpoint_id,
        signer_public_key_fingerprint = EXCLUDED.signer_public_key_fingerprint,
        document = EXCLUDED.document`,
      [
        checkpoint.checkpointId,
        resolveTenantId(checkpoint.tenantId),
        checkpoint.digest,
        checkpoint.lineage?.previousCheckpointId || null,
        checkpoint.signer?.publicKeyFingerprint || null,
        JSON.stringify(checkpoint)
      ]
    );
  }

  return {
    isConfigured,
    init,
    query,
    async saveVerificationSession(session) {
      const result = await query(
        `INSERT INTO verification_sessions (
          session_id, user_id, session_url, provider, status, verification_type, metadata, decision
        ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb)
        ON CONFLICT (session_id) DO UPDATE SET
          user_id = EXCLUDED.user_id,
          session_url = EXCLUDED.session_url,
          provider = EXCLUDED.provider,
          status = EXCLUDED.status,
          verification_type = EXCLUDED.verification_type,
          metadata = EXCLUDED.metadata,
          decision = EXCLUDED.decision,
          updated_at = now()
        RETURNING *`,
        [
          session.sessionId,
          session.userId,
          session.sessionUrl,
          session.provider,
          session.status,
          session.verificationType,
          JSON.stringify(session.metadata || {}),
          JSON.stringify(session.decision ?? null)
        ]
      );
      return mapVerificationSessionRow(result.rows[0]);
    },
    async getVerificationSession(sessionId) {
      const result = await query(
        `SELECT * FROM verification_sessions WHERE session_id = $1`,
        [sessionId]
      );
      return mapVerificationSessionRow(result.rows[0] || null);
    },
    async updateVerificationSession(sessionId, updates) {
      const result = await query(
        `UPDATE verification_sessions
         SET
           status = COALESCE($2, status),
           decision = COALESCE($3::jsonb, decision),
           updated_at = now()
         WHERE session_id = $1
         RETURNING *`,
        [
          sessionId,
          updates.status ?? null,
          updates.decision === undefined
            ? null
            : JSON.stringify(updates.decision)
        ]
      );
      return mapVerificationSessionRow(result.rows[0] || null);
    },
    async isWebhookEventProcessed(eventId) {
      const result = await query(
        `SELECT 1 FROM processed_webhook_events WHERE event_id = $1`,
        [eventId]
      );
      return result.rowCount > 0;
    },
    async markWebhookEventProcessed(eventId, eventData = {}) {
      await query(
        `INSERT INTO processed_webhook_events (
          event_id, event_type, journey_id, reference_no
        ) VALUES ($1, $2, $3, $4)
        ON CONFLICT (event_id) DO NOTHING`,
        [
          eventId,
          eventData.event || "",
          eventData.body?.journeyId || null,
          eventData.body?.referenceNo || null
        ]
      );
    },
    async appendVerificationLog(entry) {
      await query(
        `INSERT INTO verification_logs (
          user_id, provider, session_id, journey_id, event, status,
          system_decision, manual_decision, final_decision, decision
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`,
        [
          entry.userId,
          entry.provider || "",
          entry.sessionId || "",
          entry.journeyId || "",
          entry.event,
          entry.status,
          entry.systemDecision || null,
          entry.manualDecision || null,
          entry.finalDecision || null,
          JSON.stringify(entry.decision ?? null)
        ]
      );
    },
    async appendSecurityLog(entry) {
      await query(
        `INSERT INTO security_logs (
          type, user_id, session_id, details
        ) VALUES ($1,$2,$3,$4::jsonb)`,
        [
          entry.type,
          entry.userId,
          entry.sessionId || "",
          JSON.stringify(entry.details || {})
        ]
      );
    },
    async listReconcileAuditLogs(filters = {}) {
      const limit = Math.max(1, Math.min(Number(filters.limit) || 200, 1000));

      const verificationClauses = [`event LIKE 'reconcile.provider.%'`];
      const verificationParams = [];

      if (filters.provider) {
        verificationParams.push(filters.provider);
        verificationClauses.push(`provider = $${verificationParams.length}`);
      }
      if (filters.userId) {
        verificationParams.push(filters.userId);
        verificationClauses.push(`user_id = $${verificationParams.length}`);
      }
      if (filters.sessionId) {
        verificationParams.push(filters.sessionId);
        verificationClauses.push(`session_id = $${verificationParams.length}`);
      }
      if (filters.pollId) {
        verificationParams.push(filters.pollId);
        verificationClauses.push(
          `decision ->> 'pollId' = $${verificationParams.length}`
        );
      }
      if (filters.identityHash) {
        verificationParams.push(filters.identityHash);
        verificationClauses.push(
          `decision ->> 'identityHash' = $${verificationParams.length}`
        );
      }
      if (filters.outcome) {
        verificationParams.push(filters.outcome);
        verificationClauses.push(`status = $${verificationParams.length}`);
      }

      verificationParams.push(limit);
      const verificationLimitParam = verificationParams.length;

      const verificationSql = `
        SELECT
          id, user_id, provider, session_id, event, status,
          system_decision, manual_decision, final_decision,
          decision, created_at
        FROM verification_logs
        WHERE ${verificationClauses.join(" AND ")}
        ORDER BY created_at DESC
        LIMIT $${verificationLimitParam}`;

      const securityClauses = [`type = 'reconcile_provider_nonapproved'`];
      const securityParams = [];

      if (filters.userId) {
        securityParams.push(filters.userId);
        securityClauses.push(`user_id = $${securityParams.length}`);
      }
      if (filters.sessionId) {
        securityParams.push(filters.sessionId);
        securityClauses.push(`session_id = $${securityParams.length}`);
      }
      if (filters.pollId) {
        securityParams.push(filters.pollId);
        securityClauses.push(
          `details ->> 'pollId' = $${securityParams.length}`
        );
      }
      if (filters.identityHash) {
        securityParams.push(filters.identityHash);
        securityClauses.push(
          `details ->> 'identityHash' = $${securityParams.length}`
        );
      }
      if (filters.provider) {
        securityParams.push(filters.provider);
        securityClauses.push(
          `details -> 'providerAuth' ->> 'provider' = $${securityParams.length}`
        );
      }

      securityParams.push(limit);
      const securityLimitParam = securityParams.length;

      const securitySql = `
        SELECT id, type, user_id, session_id, details, created_at
        FROM security_logs
        WHERE ${securityClauses.join(" AND ")}
        ORDER BY created_at DESC
        LIMIT $${securityLimitParam}`;

      const [verificationResult, securityResult] = await Promise.all([
        query(verificationSql, verificationParams),
        query(securitySql, securityParams)
      ]);

      return {
        verificationLogs: verificationResult.rows.map((row) => ({
          id: Number(row.id),
          userId: row.user_id,
          provider: row.provider,
          sessionId: row.session_id,
          event: row.event,
          status: row.status,
          systemDecision: row.system_decision,
          manualDecision: row.manual_decision,
          finalDecision: row.final_decision,
          decision: row.decision || null,
          createdAt: normalizeTimestamp(row.created_at)
        })),
        securityLogs: securityResult.rows.map((row) => ({
          id: Number(row.id),
          type: row.type,
          userId: row.user_id,
          sessionId: row.session_id,
          details: row.details || {},
          createdAt: normalizeTimestamp(row.created_at)
        }))
      };
    },
    async saveVoteReceipt(receipt) {
      const result = await query(
        `INSERT INTO vote_receipts (
          user_id, poll_id, choice, ballot_id, ballot_nonce, identity_hash,
          receipt_version, receipt_escrow, submitted_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9::timestamptz, now()))
        ON CONFLICT (user_id, poll_id) DO UPDATE SET
          choice = EXCLUDED.choice,
          ballot_id = EXCLUDED.ballot_id,
          ballot_nonce = EXCLUDED.ballot_nonce,
          identity_hash = EXCLUDED.identity_hash,
          receipt_version = EXCLUDED.receipt_version,
          receipt_escrow = EXCLUDED.receipt_escrow,
          submitted_at = EXCLUDED.submitted_at,
          updated_at = now()
        RETURNING *`,
        [
          receipt.userId,
          receipt.pollId,
          receipt.choice,
          receipt.ballotId,
          receipt.ballotNonce,
          receipt.identityHash,
          receipt.receiptVersion || "shyware-v1",
          receipt.receiptEscrow || "cockroach",
          receipt.submittedAt || null
        ]
      );
      return mapVoteReceiptRow(result.rows[0] || null);
    },
    async getVoteReceipt(userId, pollId) {
      const result = await query(
        `SELECT * FROM vote_receipts WHERE user_id = $1 AND poll_id = $2`,
        [userId, pollId]
      );
      return mapVoteReceiptRow(result.rows[0] || null);
    },
    async confirmVoteReceipt(userId, pollId) {
      return transaction(async (client) => {
        const receiptResult = await client.query(
          `SELECT 1 FROM vote_receipts WHERE user_id = $1 AND poll_id = $2`,
          [userId, pollId]
        );
        if (receiptResult.rowCount === 0) {
          return { status: "missing_receipt", confirmedCount: null };
        }

        const insertResult = await client.query(
          `INSERT INTO vote_receipt_confirmations (user_id, poll_id)
           VALUES ($1, $2)
           ON CONFLICT (user_id, poll_id) DO NOTHING
           RETURNING user_id`,
          [userId, pollId]
        );

        if (insertResult.rowCount === 0) {
          const existingCount = await client.query(
            `SELECT COUNT(*)::int AS count FROM vote_receipt_confirmations WHERE poll_id = $1`,
            [pollId]
          );
          return {
            status: "already_confirmed",
            confirmedCount: Number(existingCount.rows[0]?.count ?? 0)
          };
        }

        const countResult = await client.query(
          `SELECT COUNT(*)::int AS count FROM vote_receipt_confirmations WHERE poll_id = $1`,
          [pollId]
        );
        return {
          status: "confirmed",
          confirmedCount: Number(countResult.rows[0]?.count ?? 0)
        };
      });
    },
    async saveWireIntent(intent) {
      const providerStatus =
        intent.providerStatus ||
        (intent.requiresOperatorReview
          ? "pending_operator_review"
          : "pending_provider_dispatch");
      const result = await query(
        `INSERT INTO wire_provider_intents (
          intent_id, kind, provider, provider_mode, issuer_name, amount,
          backing_asset, settlement_asset, external_reference,
          requires_operator_review, supported_rails, status, provider_status,
          payload, destination_network, destination_address,
          account_commitment, payout_rail, payout_network, payout_destination,
          provider_response
        ) VALUES (
          $1,$2,$3,$4,$5,$6,
          $7,$8,$9,
          $10,$11::jsonb,$12,$13,
          $14::jsonb,$15,$16,
          $17,$18,$19,$20,
          $21::jsonb
        )
        ON CONFLICT (intent_id) DO UPDATE SET
          kind = EXCLUDED.kind,
          provider = EXCLUDED.provider,
          provider_mode = EXCLUDED.provider_mode,
          issuer_name = EXCLUDED.issuer_name,
          amount = EXCLUDED.amount,
          backing_asset = EXCLUDED.backing_asset,
          settlement_asset = EXCLUDED.settlement_asset,
          external_reference = EXCLUDED.external_reference,
          requires_operator_review = EXCLUDED.requires_operator_review,
          supported_rails = EXCLUDED.supported_rails,
          status = EXCLUDED.status,
          provider_status = EXCLUDED.provider_status,
          payload = EXCLUDED.payload,
          destination_network = EXCLUDED.destination_network,
          destination_address = EXCLUDED.destination_address,
          account_commitment = EXCLUDED.account_commitment,
          payout_rail = EXCLUDED.payout_rail,
          payout_network = EXCLUDED.payout_network,
          payout_destination = EXCLUDED.payout_destination,
          provider_response = EXCLUDED.provider_response,
          updated_at = now()
        RETURNING *`,
        [
          intent.intentId,
          intent.kind,
          intent.provider,
          intent.providerMode,
          intent.issuerName,
          intent.amount,
          intent.backingAsset,
          intent.settlementAsset,
          intent.externalReference || "",
          intent.requiresOperatorReview,
          JSON.stringify(intent.supportedRails || []),
          intent.status,
          providerStatus,
          JSON.stringify(intent.payload || {}),
          intent.destinationNetwork || null,
          intent.destinationAddress || null,
          intent.accountCommitment || null,
          intent.payoutRail || null,
          intent.payoutNetwork || null,
          intent.payoutDestination || null,
          JSON.stringify(intent.providerResponse ?? null)
        ]
      );
      return mapWireIntentRow(result.rows[0]);
    },
    async getWireIntent(intentId) {
      const result = await query(
        `SELECT * FROM wire_provider_intents WHERE intent_id = $1`,
        [intentId]
      );
      return mapWireIntentRow(result.rows[0] || null);
    },
    async updateWireIntentDispatch(intentId, updates) {
      const result = await query(
        `UPDATE wire_provider_intents
         SET
           status = COALESCE($2, status),
           provider_status = COALESCE($3, provider_status),
           provider_response = COALESCE($4::jsonb, provider_response),
           dispatched_at = CASE WHEN $5 THEN now() ELSE dispatched_at END,
           updated_at = now()
         WHERE intent_id = $1
         RETURNING *`,
        [
          intentId,
          updates.status ?? null,
          updates.providerStatus ?? null,
          updates.providerResponse === undefined
            ? null
            : JSON.stringify(updates.providerResponse),
          updates.markDispatched === true
        ]
      );
      return mapWireIntentRow(result.rows[0] || null);
    },
    async listScytaleMailboxes({ tenantId, ownerUid } = {}) {
      const mailboxes = await loadAllScytaleMailboxes(
        { query },
        tenantId,
        ownerUid
      );
      return mailboxes.map((mailbox) => summarizeScytaleMailbox(mailbox));
    },
    async getScytaleMailbox(
      mailboxId,
      { unsealContent = true, tenantId, ownerUid } = {}
    ) {
      const mailbox = await loadScytaleMailboxById(
        { query },
        mailboxId,
        tenantId,
        ownerUid
      );
      if (!mailbox) return null;
      return materializeScytaleMailbox(mailbox, { unsealContent });
    },
    async getScytaleMailboxByAddress(
      address,
      { unsealContent = true, tenantId, ownerUid } = {}
    ) {
      const mailbox = await loadScytaleMailboxByAddress(
        { query },
        address,
        tenantId,
        ownerUid
      );
      if (!mailbox) return null;
      return materializeScytaleMailbox(mailbox, { unsealContent });
    },
    async createScytaleMailbox({
      label,
      address,
      routeHint,
      accountLabel,
      accountScope,
      auditPolicy,
      tenantId,
      ownerUid
    }) {
      const trimmedLabel = trimString(label);
      const normalizedAddress = normalizeScytaleMailboxAddress(
        address || label
      );
      const resolvedTenantId = resolveTenantId(tenantId);
      if (!trimmedLabel) throw new Error("Mailbox label is required");
      if (!normalizedAddress) throw new Error("Mailbox address is required");

      return transaction(async (client) => {
        const existing = await client.query(
          `SELECT 1 FROM scytale_mailboxes WHERE address = $1 AND tenant_id = $2`,
          [normalizedAddress, resolvedTenantId]
        );
        if (existing.rowCount > 0) {
          throw new Error("Mailbox address already exists");
        }

        const mailboxId = `mbx-${crypto.randomUUID()}`;
        await client.query(
          `INSERT INTO scytale_mailboxes (
            mailbox_id, tenant_id, label, address, owner_uid, account_label, account_scope, route_hint,
            mailbox_scope, audit_policy, delivery_state, delivery_window, excerpt, counterparty_route
          ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,
            $9,$10,$11,$12,$13,$14
          )`,
          [
            mailboxId,
            resolvedTenantId,
            trimmedLabel,
            normalizedAddress,
            trimString(ownerUid) || null,
            trimString(accountLabel) || "Primary account",
            trimString(accountScope) || "multi_account",
            trimString(routeHint) || "private-delivery",
            "confidential",
            normalizeScytaleAuditMode(auditPolicy),
            "pending",
            "Awaiting close",
            "Sealed mail package created. No dispatches accepted into canonical close yet.",
            "unrouted"
          ]
        );

        return loadScytaleMailboxById(
          client,
          mailboxId,
          resolvedTenantId,
          trimString(ownerUid) || null
        );
      });
    },
    async queueScytaleDispatch({
      mailboxId,
      recipientAddress,
      subject,
      body,
      deliveryWindow,
      contentClass = "mail",
      payloadFormat = "mail_text",
      privateFields = {},
      auditMode = null,
      attachmentRefs = [],
      tenantId,
      ownerUid
    }) {
      const resolvedTenantId = resolveTenantId(tenantId);
      return transaction(async (client) => {
        const senderMailbox = await loadScytaleMailboxById(
          client,
          mailboxId,
          resolvedTenantId,
          ownerUid
        );
        if (!senderMailbox) throw new Error("Sender mailbox not found");

        const normalizedRecipient =
          normalizeScytaleMailboxAddress(recipientAddress);
        if (!normalizedRecipient)
          throw new Error("Recipient address is required");

        const recipientMailbox = await loadScytaleMailboxByAddress(
          client,
          normalizedRecipient,
          resolvedTenantId
        );
        const resolvedAuditMode = normalizeScytaleAuditMode(
          auditMode || senderMailbox.auditPolicy
        );
        const normalizedPayloadFormat =
          normalizeScytalePayloadFormat(payloadFormat);
        const normalizedPrivateFields =
          normalizeScytalePrivateFields(privateFields);
        const normalizedAttachmentRefs =
          normalizeScytaleAttachmentRefs(attachmentRefs);

        const outbound = makeScytaleMessage({
          mailboxId: senderMailbox.id,
          subject,
          body,
          direction: "outbound",
          status: recipientMailbox ? "delivered" : "queued",
          recipientAddress: normalizedRecipient,
          senderAddress: senderMailbox.address,
          peerMailboxId: recipientMailbox ? recipientMailbox.id : null,
          requestedDeliveryWindow:
            trimString(deliveryWindow) || "next attested close",
          contentClass,
          payloadFormat: normalizedPayloadFormat,
          privateFields: normalizedPrivateFields,
          auditMode: resolvedAuditMode,
          attachmentRefs: normalizedAttachmentRefs,
          recoveryMode: "server_assisted_mailbox_open"
        });
        outbound.tenantId = resolvedTenantId;

        senderMailbox.messages.push(outbound);
        senderMailbox.deliveryState = recipientMailbox ? "delivered" : "queued";
        senderMailbox.counterpartyRoute = normalizedRecipient;
        refreshMailbox(senderMailbox);
        await insertScytaleDispatch(client, outbound);
        await persistScytaleMailbox(client, senderMailbox);


        let hydratedRecipient = null;
        if (recipientMailbox) {
          const inbound = makeScytaleMessage({
            mailboxId: recipientMailbox.id,
            subject,
            body,
            direction: "inbound",
            status: "delivered",
            recipientAddress: recipientMailbox.address,
            senderAddress: senderMailbox.address,
            peerMailboxId: senderMailbox.id,
            dispatchId: outbound.dispatchId,
            requestedDeliveryWindow: outbound.requestedDeliveryWindow,
            contentClass,
            payloadFormat: normalizedPayloadFormat,
            privateFields: normalizedPrivateFields,
            auditMode: resolvedAuditMode,
            attachmentRefs: normalizedAttachmentRefs,
            recoveryMode: "server_assisted_mailbox_open",
            sealedPayload: outbound.sealedPayload
          });
          inbound.tenantId = resolvedTenantId;

          recipientMailbox.messages.push(inbound);
          recipientMailbox.deliveryState = "delivered";
          recipientMailbox.counterpartyRoute = senderMailbox.address;
          refreshMailbox(recipientMailbox);
          await insertScytaleDispatch(client, inbound);
          await persistScytaleMailbox(client, recipientMailbox);
          hydratedRecipient = recipientMailbox;
        }

        return {
          dispatchId: outbound.dispatchId,
          mailbox: senderMailbox,
          recipientMailbox: hydratedRecipient,
          routeStatus: recipientMailbox
            ? "local_mailbox_resolved"
            : "external_route_stubbed"
        };
      });
    },
    async attestScytaleMailboxClose(mailboxId, options = {}) {
      return this.attestScytaleMailboxCloseForTenant(mailboxId, options);
    },
    async attestScytaleMailboxCloseForTenant(
      mailboxId,
      { tenantId, ownerUid } = {}
    ) {
      const resolvedTenantId = resolveTenantId(tenantId);
      return transaction(async (client) => {
        const mailbox = await loadScytaleMailboxById(
          client,
          mailboxId,
          resolvedTenantId,
          ownerUid
        );
        if (!mailbox) throw new Error("Mailbox not found");

        mailbox.messages = mailbox.messages.map((message) => {
          let nextStatus = message.status;
          if (message.direction === "outbound" && message.status === "queued") {
            nextStatus = "attested";
          } else if (message.status === "delivered") {
            nextStatus = "attested";
          }

          if (nextStatus !== message.status) {
            return { ...message, status: nextStatus };
          }
          return message;
        });

        for (const message of mailbox.messages) {
          await updateScytaleDispatchStatus(
            client,
            message.messageId,
            message.status,
            resolvedTenantId
          );
        }

        mailbox.deliveryState = "attested";
        refreshMailbox(mailbox);
        await persistScytaleMailbox(client, mailbox);
        return mailbox;
      });
    },
    async writeScytaleRecoveryReceipt(mailboxId, { tenantId, ownerUid } = {}) {
      const resolvedTenantId = resolveTenantId(tenantId);
      return transaction(async (client) => {
        const mailbox = await loadScytaleMailboxById(
          client,
          mailboxId,
          resolvedTenantId,
          ownerUid
        );
        if (!mailbox) throw new Error("Mailbox not found");

        const lastMessage =
          mailbox.messages[mailbox.messages.length - 1] || null;
        const receipt = {
          mailboxId: mailbox.id,
          mailboxAddress: mailbox.address,
          mailboxScope: mailbox.mailboxScope,
          lastDispatchId: lastMessage?.dispatchId || null,
          lastPayloadCommitment: lastMessage?.payloadCommitment || null,
          recoveryRef: shortHash(
            `${mailbox.id}:${mailbox.messages.length}:receipt`
          ),
          recoveryMode:
            lastMessage?.recoveryMode || "server_assisted_mailbox_open",
          sealedContent: true
        };

        const result = await client.query(
          `INSERT INTO scytale_receipts (
            mailbox_id, tenant_id, mailbox_address, mailbox_scope, last_dispatch_id,
            last_payload_commitment, recovery_ref, recovery_mode, sealed_content
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
          ON CONFLICT (mailbox_id) DO UPDATE SET
            tenant_id = EXCLUDED.tenant_id,
            mailbox_address = EXCLUDED.mailbox_address,
            mailbox_scope = EXCLUDED.mailbox_scope,
            last_dispatch_id = EXCLUDED.last_dispatch_id,
            last_payload_commitment = EXCLUDED.last_payload_commitment,
            recovery_ref = EXCLUDED.recovery_ref,
            recovery_mode = EXCLUDED.recovery_mode,
            sealed_content = EXCLUDED.sealed_content,
            updated_at = now()
          RETURNING *`,
          [
            receipt.mailboxId,
            resolvedTenantId,
            receipt.mailboxAddress,
            receipt.mailboxScope,
            receipt.lastDispatchId,
            receipt.lastPayloadCommitment,
            receipt.recoveryRef,
            receipt.recoveryMode,
            receipt.sealedContent
          ]
        );
        return mapScytaleReceiptRow(result.rows[0] || null);
      });
    },
    async getScytaleRecoveryReceipt(mailboxId, { tenantId, ownerUid } = {}) {
      const mailbox = await loadScytaleMailboxById(
        { query },
        mailboxId,
        tenantId,
        ownerUid
      );
      if (!mailbox) return null;
      const result = await query(
        `SELECT * FROM scytale_receipts WHERE mailbox_id = $1 AND tenant_id = $2`,
        [mailboxId, resolveTenantId(tenantId)]
      );
      return mapScytaleReceiptRow(result.rows[0] || null);
    },
    async getScytaleCheckpoint(checkpointId, { tenantId } = {}) {
      const result = await query(
        `SELECT document FROM scytale_checkpoints
         WHERE checkpoint_id = $1 AND tenant_id = $2`,
        [checkpointId, resolveTenantId(tenantId)]
      );
      return result.rows[0]?.document || null;
    },
    async createScytaleCheckpoint({
      tenantId,
      previousCheckpointId = null,
      sourceDeployment = {},
      sourceCheckpoint = null,
      createdAt = new Date().toISOString(),
      privateKeyPem = process.env.SHYWARE_MIGRATION_PRIVATE_KEY_PEM ||
        process.env.SCYTALE_MIGRATION_PRIVATE_KEY_PEM ||
        "",
      requireSignature = false
    } = {}) {
      const tenantRows = await loadScytaleTenantRows({ query }, tenantId);
      const unsignedCheckpoint = createCheckpointPayload({
        tenantId: tenantRows.tenantId,
        mailboxes: tenantRows.mailboxes,
        dispatches: tenantRows.dispatches,
        receipts: tenantRows.receipts,
        previousCheckpointId,
        sourceDeployment,
        sourceCheckpoint,
        createdAt
      });
      const checkpoint = createSignedCheckpoint(
        unsignedCheckpoint,
        privateKeyPem
      );
      if (requireSignature && !checkpoint.signature) {
        throw new Error(
          "Migration signing key is required for a formal checkpoint"
        );
      }
      await saveScytaleCheckpoint({ query }, checkpoint);
      return checkpoint;
    },
    async exportScytaleTenantBundle({
      tenantId,
      checkpointId = null,
      previousCheckpointId = null,
      sourceDeployment = {},
      sourceCheckpoint = null,
      exportedAt = new Date().toISOString(),
      privateKeyPem = process.env.SHYWARE_MIGRATION_PRIVATE_KEY_PEM ||
        process.env.SCYTALE_MIGRATION_PRIVATE_KEY_PEM ||
        "",
      requireSignature = false
    } = {}) {
      const tenantRows = await loadScytaleTenantRows({ query }, tenantId);
      let checkpoint = null;
      if (checkpointId) {
        checkpoint = await this.getScytaleCheckpoint(checkpointId, {
          tenantId: tenantRows.tenantId
        });
        if (!checkpoint) {
          throw new Error(`Checkpoint not found: ${checkpointId}`);
        }
      } else {
        checkpoint = await this.createScytaleCheckpoint({
          tenantId: tenantRows.tenantId,
          previousCheckpointId,
          sourceDeployment,
          sourceCheckpoint,
          createdAt: exportedAt,
          privateKeyPem,
          requireSignature
        });
      }

      return createExportBundle({
        tenantId: tenantRows.tenantId,
        checkpoint,
        mailboxes: tenantRows.mailboxes,
        dispatches: tenantRows.dispatches,
        receipts: tenantRows.receipts,
        sourceDeployment,
        exportedAt
      });
    },
    async importScytaleTenantBundle(
      bundle,
      { tenantId, mode = "restore", verifySignature = true } = {}
    ) {
      const verification = verifyExportBundle(bundle);
      if (!verification.digestMatches) {
        throw new Error("Export bundle digest does not match checkpoint");
      }
      if (
        verifySignature &&
        bundle.checkpoint?.signature &&
        verification.signatureValid !== true
      ) {
        throw new Error("Export bundle signature verification failed");
      }

      const targetTenantId = resolveTenantId(tenantId || bundle.tenantId);
      if (targetTenantId !== resolveTenantId(bundle.tenantId)) {
        throw new Error(
          "Tenant override must match the bundle tenant for formal import; namespace renames require a separate bootstrap cutover"
        );
      }
      return transaction(async (client) => {
        const existing = await client.query(
          `SELECT
             (SELECT COUNT(*)::int FROM scytale_mailboxes WHERE tenant_id = $1) AS mailbox_count,
             (SELECT COUNT(*)::int FROM scytale_dispatches WHERE tenant_id = $1) AS dispatch_count,
             (SELECT COUNT(*)::int FROM scytale_receipts WHERE tenant_id = $1) AS receipt_count`,
          [targetTenantId]
        );
        const counts = existing.rows[0] || {};
        const existingRows =
          Number(counts.mailbox_count || 0) +
          Number(counts.dispatch_count || 0) +
          Number(counts.receipt_count || 0);
        if (mode !== "replace" && existingRows > 0) {
          throw new Error(
            `Tenant ${targetTenantId} already has persisted state; import requires an empty tenant or mode=replace`
          );
        }
        if (mode === "replace" && existingRows > 0) {
          await client.query(
            `DELETE FROM scytale_receipts WHERE tenant_id = $1`,
            [targetTenantId]
          );
          await client.query(
            `DELETE FROM scytale_dispatches WHERE tenant_id = $1`,
            [targetTenantId]
          );
          await client.query(
            `DELETE FROM scytale_mailboxes WHERE tenant_id = $1`,
            [targetTenantId]
          );
        }

        for (const mailbox of bundle.mailboxes || []) {
          const row = normalizeMailboxRecord({
            ...mailbox,
            tenantId: targetTenantId
          });
          await client.query(
            `INSERT INTO scytale_mailboxes (
              mailbox_id, tenant_id, label, address, owner_uid, account_label, account_scope, route_hint,
              mailbox_scope, audit_policy, delivery_state, delivery_window, excerpt, counterparty_route,
              created_at, updated_at
            ) VALUES (
              $1,$2,$3,$4,$5,$6,$7,$8,
              $9,$10,$11,$12,$13,$14,
              COALESCE($15::timestamptz, now()), COALESCE($16::timestamptz, now())
            )`,
            [
              row.mailboxId,
              row.tenantId,
              row.label || "",
              row.address,
              row.ownerUid || null,
              row.accountLabel || "",
              row.accountScope || "",
              row.routeHint || "",
              row.mailboxScope || "confidential",
              row.auditPolicy || "delivery_commitment_only",
              row.deliveryState || "pending",
              row.deliveryWindow || "Awaiting close",
              row.excerpt || "",
              row.counterpartyRoute || "unrouted",
              row.createdAt,
              row.updatedAt
            ]
          );
        }

        for (const dispatch of bundle.dispatches || []) {
          const row = normalizeDispatchRecord({
            ...dispatch,
            tenantId: targetTenantId
          });
          await client.query(
            `INSERT INTO scytale_dispatches (
              message_id, tenant_id, dispatch_id, mailbox_id, peer_mailbox_id, direction, status,
              recipient_address, sender_address, requested_delivery_window, timestamp,
              payload_commitment, audit_surface, content_class, payload_format, audit_mode,
              sensitivity, recovery_mode, content_disposition, attachment_count,
              private_field_count, sealed_payload, created_at
            ) VALUES (
              $1,$2,$3,$4,$5,$6,$7,
              $8,$9,$10,$11::timestamptz,
              $12,$13::jsonb,$14,$15,$16,
              $17,$18,$19,$20,
              $21,$22::jsonb,COALESCE($23::timestamptz, now())
            )`,
            [
              row.messageId,
              row.tenantId,
              row.dispatchId,
              row.mailboxId,
              row.peerMailboxId,
              row.direction,
              row.status,
              row.recipientAddress,
              row.senderAddress,
              row.requestedDeliveryWindow,
              row.timestamp,
              row.payloadCommitment,
              JSON.stringify(row.auditSurface || {}),
              row.contentClass || "mail",
              row.payloadFormat || "mail_text",
              row.auditMode || "delivery_commitment_only",
              row.sensitivity || "assumed_pii",
              row.recoveryMode || "server_assisted_mailbox_open",
              row.contentDisposition || "sealed_off_canonical",
              row.attachmentCount || 0,
              row.privateFieldCount || 0,
              JSON.stringify(row.sealedPayload || {}),
              row.createdAt
            ]
          );
        }

        for (const receipt of bundle.receipts || []) {
          const row = normalizeReceiptRecord({
            ...receipt,
            tenantId: targetTenantId
          });
          await client.query(
            `INSERT INTO scytale_receipts (
              mailbox_id, tenant_id, mailbox_address, mailbox_scope, last_dispatch_id,
              last_payload_commitment, recovery_ref, recovery_mode, sealed_content,
              created_at, updated_at
            ) VALUES (
              $1,$2,$3,$4,$5,
              $6,$7,$8,$9,
              COALESCE($10::timestamptz, now()), COALESCE($11::timestamptz, now())
            )`,
            [
              row.mailboxId,
              row.tenantId,
              row.mailboxAddress,
              row.mailboxScope || "confidential",
              row.lastDispatchId,
              row.lastPayloadCommitment,
              row.recoveryRef,
              row.recoveryMode || "server_assisted_mailbox_open",
              row.sealedContent !== false,
              row.createdAt,
              row.updatedAt
            ]
          );
        }

        await saveScytaleCheckpoint(client, bundle.checkpoint);

        return {
          tenantId: targetTenantId,
          imported: {
            mailboxes: (bundle.mailboxes || []).length,
            dispatches: (bundle.dispatches || []).length,
            receipts: (bundle.receipts || []).length
          },
          checkpointId: bundle.checkpoint?.checkpointId || null,
          digest: bundle.checkpoint?.digest || null
        };
      });
    },
    // Claim 56: ownerUid is required — the activity feed is scoped to the
    // caller's own dispatches. No cross-participant enumeration is possible
    // from the query layer regardless of routing.
    async recentScytaleActivity({ tenantId, ownerUid, limit = 20 } = {}) {
      const uid = trimString(ownerUid) || null;
      const result = await query(
        `SELECT d.dispatch_id, d.payload_commitment, d.status, d.direction,
                d.content_class, d.timestamp, d.created_at
         FROM scytale_dispatches d
         JOIN scytale_mailboxes m ON d.mailbox_id = m.mailbox_id
         WHERE d.tenant_id = $1
           AND m.tenant_id = $1
           AND ($2::text IS NULL OR m.owner_uid = $2)
         ORDER BY d.created_at DESC
         LIMIT $3`,
        [resolveTenantId(tenantId), uid, limit]
      );
      return result.rows.map((row) => ({
        dispatchId: row.dispatch_id,
        payloadCommitment: row.payload_commitment,
        status: row.status,
        direction: row.direction,
        contentClass: row.content_class,
        timestamp: row.timestamp,
      }));
    }
  };
}

module.exports = { createCockroachStore };
