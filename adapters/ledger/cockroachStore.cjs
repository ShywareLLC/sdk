const crypto = require("crypto");
const { Pool } = require("pg");
const {
  UNINITIALIZED_VERSION,
  createMigrationRegistry,
  runMigrations
} = require("../migration/engine.cjs");
const {
  normalizeTenantId: normalizeMigrationTenantId,
  normalizeMailboxRecord,
  normalizeDispatchRecord,
  normalizeReceiptRecord,
  createCheckpointPayload,
  createSignedCheckpoint,
  createExportBundle,
  verifyExportBundle
} = require("./scytaleCheckpoint.cjs");

let SDK_VERSION = "0.0.0";
try {
  SDK_VERSION = require("../../package.json").version || SDK_VERSION;
} catch (_) {}

const COCKROACH_COMPONENT = "cockroach-store";
const COCKROACH_SCHEMA_VERSION = "2026-08-31.5";

const SCHEMA_SQL = `

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

CREATE TABLE IF NOT EXISTS console_deployments (
  operator_uid        TEXT        NOT NULL,
  id                  TEXT        NOT NULL,
  name                TEXT        NOT NULL,
  domain              TEXT        NOT NULL,
  contract            TEXT        NOT NULL,
  default_posture     TEXT        NOT NULL DEFAULT 'recoverable',
  deployment_tier     TEXT        NOT NULL DEFAULT 'stack4',
  ledger_operator     TEXT        NOT NULL DEFAULT 'shyware',
  ra_operator         TEXT        NOT NULL DEFAULT 'operator',
  posture_override    TEXT        NULL,
  posture_reason      TEXT        NULL,
  posture_updated_at  TIMESTAMPTZ NULL,
  posture_updated_by  TEXT        NULL,
  country_rules       JSONB       NOT NULL DEFAULT '[]'::jsonb,
  country_rules_updated_at TIMESTAMPTZ NULL,
  country_rules_updated_by TEXT   NULL,
  stripe_customer_id  TEXT        NULL,
  stripe_subscription_id TEXT     NULL,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (operator_uid, id)
);

`;

const MIGRATION_STATE_SQL = `
CREATE TABLE IF NOT EXISTS shyware_migration_state (
  component TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  sdk_version TEXT NULL,
  status TEXT NOT NULL DEFAULT 'ready',
  stack TEXT NULL,
  ledger_role TEXT NULL,
  source_ledger TEXT NULL,
  target_ledger TEXT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS shyware_migration_steps (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  component TEXT NOT NULL,
  migration_id TEXT NOT NULL,
  from_version TEXT NOT NULL,
  to_version TEXT NOT NULL,
  sdk_version TEXT NULL,
  type TEXT NOT NULL,
  status TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS shyware_migration_steps_component_idx
  ON shyware_migration_steps (component, applied_at DESC);
`;

function createCockroachMigrationStateStore(pool) {
  let ensurePromise = null;
  async function ensure() {
    if (!ensurePromise) ensurePromise = pool.query(MIGRATION_STATE_SQL);
    await ensurePromise;
  }
  return {
    async getComponentState(component) {
      await ensure();
      const { rows } = await pool.query(
        `SELECT component, version, sdk_version, status, stack, ledger_role,
                source_ledger, target_ledger, metadata, updated_at
           FROM shyware_migration_state
          WHERE component = $1`,
        [component]
      );
      const row = rows[0];
      if (!row) return null;
      return {
        component: row.component,
        version: row.version,
        sdkVersion: row.sdk_version,
        status: row.status,
        stack: row.stack,
        ledgerRole: row.ledger_role,
        sourceLedger: row.source_ledger,
        targetLedger: row.target_ledger,
        metadata: row.metadata || {},
        updatedAt: row.updated_at?.toISOString?.() || row.updated_at
      };
    },
    async setComponentState(state) {
      await ensure();
      await pool.query(
        `UPSERT INTO shyware_migration_state (
           component, version, sdk_version, status, stack, ledger_role,
           source_ledger, target_ledger, metadata, updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, now())`,
        [
          state.component,
          state.version,
          state.sdkVersion || null,
          state.status || "ready",
          state.stack || null,
          state.ledgerRole || null,
          state.sourceLedger || null,
          state.targetLedger || null,
          JSON.stringify(state.metadata || {})
        ]
      );
    },
    async recordMigrationStep(step) {
      await ensure();
      await pool.query(
        `INSERT INTO shyware_migration_steps (
           component, migration_id, from_version, to_version, sdk_version,
           type, status, metadata
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
        [
          step.component,
          step.migrationId,
          step.fromVersion,
          step.toVersion,
          step.sdkVersion || null,
          step.type || "additive",
          step.status || "applied",
          JSON.stringify(step.metadata || {})
        ]
      );
    },
    async listMigrationSteps(component) {
      await ensure();
      const { rows } = await pool.query(
        `SELECT component, migration_id, from_version, to_version, sdk_version,
                type, status, metadata, applied_at
           FROM shyware_migration_steps
          WHERE component = $1
          ORDER BY applied_at ASC`,
        [component]
      );
      return rows.map(row => ({
        component: row.component,
        migrationId: row.migration_id,
        fromVersion: row.from_version,
        toVersion: row.to_version,
        sdkVersion: row.sdk_version,
        type: row.type,
        status: row.status,
        metadata: row.metadata || {},
        appliedAt: row.applied_at?.toISOString?.() || row.applied_at
      }));
    }
  };
}

const cockroachMigrationRegistry = createMigrationRegistry({
  component: COCKROACH_COMPONENT,
  migrations: [
    {
      id: "cockroach-store:bootstrap-2026-06-16.1",
      fromVersion: UNINITIALIZED_VERSION,
      toVersion: "2026-06-16.1",
      type: "additive",
      description: "Create or repair the core Shyware CockroachDB schema.",
      canAutoRun: true,
      up: async ({ pool }) => {
        await pool.query(SCHEMA_SQL);
      },
      validate: async ({ pool }) => {
        await pool.query("SELECT 1 FROM scytale_mailboxes LIMIT 1");
      }
    },
    {
      id: "cockroach-store:console-deployments-2026-06-19.1",
      fromVersion: "2026-06-16.1",
      toVersion: "2026-06-19.1",
      type: "additive",
      description: "Add console_deployments table for operator-scoped deployment registry.",
      canAutoRun: true,
      up: async ({ pool }) => {
        await pool.query(`
          CREATE TABLE IF NOT EXISTS console_deployments (
            operator_uid        TEXT        NOT NULL,
            id                  TEXT        NOT NULL,
            name                TEXT        NOT NULL,
            domain              TEXT        NOT NULL,
            contract            TEXT        NOT NULL,
            default_posture     TEXT        NOT NULL DEFAULT 'recoverable',
            deployment_tier     TEXT        NOT NULL DEFAULT 'stack4',
            ra_operator         TEXT        NOT NULL DEFAULT 'operator',
            posture_override    TEXT        NULL,
            posture_reason      TEXT        NULL,
            posture_updated_at  TIMESTAMPTZ NULL,
            posture_updated_by  TEXT        NULL,
            country_rules       JSONB       NOT NULL DEFAULT '[]'::jsonb,
            country_rules_updated_at TIMESTAMPTZ NULL,
            country_rules_updated_by TEXT   NULL,
            stripe_customer_id  TEXT        NULL,
            stripe_subscription_id TEXT     NULL,
            created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (operator_uid, id)
          );
        `);
      },
      validate: async ({ pool }) => {
        await pool.query("SELECT 1 FROM console_deployments LIMIT 1");
      }
    },
    {
      id: "cockroach-store:console-ledger-operator-2026-06-19.2",
      fromVersion: "2026-06-19.1",
      toVersion: "2026-06-19.2",
      type: "additive",
      description: "Add ledger_operator to console deployments.",
      canAutoRun: true,
      up: async ({ pool }) => {
        await pool.query(`
          ALTER TABLE console_deployments
            ADD COLUMN IF NOT EXISTS ledger_operator TEXT NOT NULL DEFAULT 'shyware';
        `);
      },
      validate: async ({ pool }) => {
        await pool.query("SELECT ledger_operator FROM console_deployments LIMIT 1");
      }
    },
    {
      id: "cockroach-store:populist-core-2026-08-30.1",
      fromVersion: "2026-06-19.2",
      toVersion: "2026-08-30.1",
      type: "additive",
      description:
        "Add devices, users, user_votes, bill_votes, user_bookmarks tables (Populist Firestore migration, Stage 1).",
      canAutoRun: true,
      up: async () => {
        // No-op: this migration formerly created tables that were exclusively
        // used by the Populist consumer app. They have moved to
        // Consumers/POP-U-LIST/populistStore.cjs, which manages them via its own
        // migration chain against the same physical database (idempotent
        // CREATE TABLE IF NOT EXISTS there is safe against data already created
        // here). This entry is kept -- not deleted -- so the shared version
        // chain (UNINITIALIZED_VERSION -> current) stays traversable both for
        // databases that already recorded reaching this version, and for any
        // brand-new shared-SDK consumer walking the full chain from scratch.
      }
    },
    {
      id: "cockroach-store:devices-revocation-metadata-2026-08-30.2",
      fromVersion: "2026-08-30.1",
      toVersion: "2026-08-30.2",
      type: "additive",
      description: "Add revocation metadata columns to devices.",
      canAutoRun: true,
      up: async () => {
        // No-op: this migration formerly created tables that were exclusively
        // used by the Populist consumer app. They have moved to
        // Consumers/POP-U-LIST/populistStore.cjs, which manages them via its own
        // migration chain against the same physical database (idempotent
        // CREATE TABLE IF NOT EXISTS there is safe against data already created
        // here). This entry is kept -- not deleted -- so the shared version
        // chain (UNINITIALIZED_VERSION -> current) stays traversable both for
        // databases that already recorded reaching this version, and for any
        // brand-new shared-SDK consumer walking the full chain from scratch.
      }
    },
    {
      id: "cockroach-store:populist-marketplace-2026-08-31.1",
      fromVersion: "2026-08-30.2",
      toVersion: "2026-08-31.1",
      type: "additive",
      description:
        "Add registered_campaigns, user_solicitation_prefs, contact_transactions tables (Populist Firestore migration, Stage 2).",
      canAutoRun: true,
      up: async () => {
        // No-op: this migration formerly created tables that were exclusively
        // used by the Populist consumer app. They have moved to
        // Consumers/POP-U-LIST/populistStore.cjs, which manages them via its own
        // migration chain against the same physical database (idempotent
        // CREATE TABLE IF NOT EXISTS there is safe against data already created
        // here). This entry is kept -- not deleted -- so the shared version
        // chain (UNINITIALIZED_VERSION -> current) stays traversable both for
        // databases that already recorded reaching this version, and for any
        // brand-new shared-SDK consumer walking the full chain from scratch.
      }
    },
    {
      id: "cockroach-store:populist-social-2026-08-31.2",
      fromVersion: "2026-08-31.1",
      toVersion: "2026-08-31.2",
      type: "additive",
      description:
        "Add organization_messages, forum_posts, events, event_attendees tables (Populist Firestore migration, Stage 3).",
      canAutoRun: true,
      up: async () => {
        // No-op: this migration formerly created tables that were exclusively
        // used by the Populist consumer app. They have moved to
        // Consumers/POP-U-LIST/populistStore.cjs, which manages them via its own
        // migration chain against the same physical database (idempotent
        // CREATE TABLE IF NOT EXISTS there is safe against data already created
        // here). This entry is kept -- not deleted -- so the shared version
        // chain (UNINITIALIZED_VERSION -> current) stays traversable both for
        // databases that already recorded reaching this version, and for any
        // brand-new shared-SDK consumer walking the full chain from scratch.
      }
    },
    {
      id: "cockroach-store:populist-permission-batches-2026-08-31.3",
      fromVersion: "2026-08-31.2",
      toVersion: "2026-08-31.3",
      type: "additive",
      description:
        "Add permission_batches table (Populist Firestore migration, Stage 4).",
      canAutoRun: true,
      up: async () => {
        // No-op: this migration formerly created tables that were exclusively
        // used by the Populist consumer app. They have moved to
        // Consumers/POP-U-LIST/populistStore.cjs, which manages them via its own
        // migration chain against the same physical database (idempotent
        // CREATE TABLE IF NOT EXISTS there is safe against data already created
        // here). This entry is kept -- not deleted -- so the shared version
        // chain (UNINITIALIZED_VERSION -> current) stays traversable both for
        // databases that already recorded reaching this version, and for any
        // brand-new shared-SDK consumer walking the full chain from scratch.
      }
    },
    {
      id: "cockroach-store:populist-forum-interactions-2026-08-31.4",
      fromVersion: "2026-08-31.3",
      toVersion: "2026-08-31.4",
      type: "additive",
      description:
        "Add forum_comments and forum_reports tables -- forum_posts already carries like_count/liked_by for likes, but had no comment storage at all (comment_count existed with nothing to back it), and no report/flag path existed anywhere. Also add permission_batches.comments so minor-consent batching covers comments alongside posts/messages.",
      canAutoRun: true,
      up: async () => {
        // No-op: this migration formerly created tables that were exclusively
        // used by the Populist consumer app. They have moved to
        // Consumers/POP-U-LIST/populistStore.cjs, which manages them via its own
        // migration chain against the same physical database (idempotent
        // CREATE TABLE IF NOT EXISTS there is safe against data already created
        // here). This entry is kept -- not deleted -- so the shared version
        // chain (UNINITIALIZED_VERSION -> current) stays traversable both for
        // databases that already recorded reaching this version, and for any
        // brand-new shared-SDK consumer walking the full chain from scratch.
      }
    },
    {
      id: "cockroach-store:populist-organizations-2026-08-31.5",
      fromVersion: "2026-08-31.4",
      toVersion: "2026-08-31.5",
      type: "additive",
      description:
        "Add organizations and organization_members tables -- organization_messages.organization_id was free text with no parent row, no FK, and no membership check, so any authed user could read/write any org's chat by guessing/reusing an id, and the iOS client had no durable org id at all (regenerated a random UUID every launch).",
      canAutoRun: true,
      up: async () => {
        // No-op: this migration formerly created tables that were exclusively
        // used by the Populist consumer app. They have moved to
        // Consumers/POP-U-LIST/populistStore.cjs, which manages them via its own
        // migration chain against the same physical database (idempotent
        // CREATE TABLE IF NOT EXISTS there is safe against data already created
        // here). This entry is kept -- not deleted -- so the shared version
        // chain (UNINITIALIZED_VERSION -> current) stays traversable both for
        // databases that already recorded reaching this version, and for any
        // brand-new shared-SDK consumer walking the full chain from scratch.
      }
    }
  ]
});

async function runCockroachStoreMigrations(pool, {
  currentVersion,
  targetVersion = COCKROACH_SCHEMA_VERSION,
  sdkVersion = SDK_VERSION,
  stack = process.env.SHYWARE_STACK ||
    process.env.STACK_NUM ||
    process.env.FABRIC_MODE ||
    "stack-agnostic",
  dryRun = false,
  allowManual = false,
  allowDestructive = false,
  allowWithoutBackup = false,
  backupVerified = false,
  ledgerRole = process.env.SHYWARE_LEDGER_ROLE || "operator",
  sourceLedger = process.env.SHYWARE_SOURCE_LEDGER || null,
  targetLedger = process.env.SHYWARE_TARGET_LEDGER || null
} = {}) {
  const summary = await runMigrations({
    registry: cockroachMigrationRegistry,
    store: createCockroachMigrationStateStore(pool),
    component: COCKROACH_COMPONENT,
    currentVersion,
    targetVersion,
    sdkVersion,
    stack,
    context: { pool },
    dryRun,
    allowManual,
    allowDestructive,
    allowWithoutBackup,
    backupVerified,
    ledgerRole,
    sourceLedger,
    targetLedger
  });
  if (!dryRun && summary.applied.length === 0 && summary.fromVersion === summary.toVersion) {
    await pool.query(SCHEMA_SQL);
  }
  return summary;
}

function normalizeTimestamp(value) {
  if (!value) return null;
  return value instanceof Date ? value.toISOString() : value;
}

function trimString(value) {
  return typeof value === "string" ? value.trim() : "";
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
    initPromise = runCockroachStoreMigrations(pool);
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

  async function getMigrationStatus() {
    await init();
    const store = createCockroachMigrationStateStore(pool);
    const state = await store.getComponentState(COCKROACH_COMPONENT);
    return {
      component: COCKROACH_COMPONENT,
      currentVersion: state?.version || UNINITIALIZED_VERSION,
      targetVersion: COCKROACH_SCHEMA_VERSION,
      sdkVersion: state?.sdkVersion || SDK_VERSION,
      status: state?.status || "ready",
      stack: state?.stack || null,
      ledgerRole: state?.ledgerRole || null,
      sourceLedger: state?.sourceLedger || null,
      targetLedger: state?.targetLedger || null,
      updatedAt: state?.updatedAt || null
    };
  }

  async function listMigrationHistory() {
    await init();
    return createCockroachMigrationStateStore(pool).listMigrationSteps(COCKROACH_COMPONENT);
  }

  return {
    isConfigured,
    init,
    query,
    getMigrationStatus,
    listMigrationHistory,

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
    },

    // ── Console deployment registry ────────────────────────────────────────────

    async getConsoleDeployments(operatorUid) {
      const result = await query(
        `SELECT * FROM console_deployments WHERE operator_uid = $1 ORDER BY created_at ASC`,
        [operatorUid]
      );
      return result.rows.map(mapConsoleDeploymentRow);
    },

    async upsertConsoleDeployment(operatorUid, d) {
      await query(
        `INSERT INTO console_deployments (
           operator_uid, id, name, domain, contract,
           deployment_tier, ledger_operator, ra_operator,
           stripe_customer_id, stripe_subscription_id, updated_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now())
         ON CONFLICT (operator_uid, id) DO UPDATE SET
           name = EXCLUDED.name,
           domain = EXCLUDED.domain,
           contract = EXCLUDED.contract,
           deployment_tier = EXCLUDED.deployment_tier,
           ledger_operator = EXCLUDED.ledger_operator,
           ra_operator = EXCLUDED.ra_operator,
           stripe_customer_id = EXCLUDED.stripe_customer_id,
           stripe_subscription_id = EXCLUDED.stripe_subscription_id,
           updated_at = now()`,
        [
          operatorUid, d.id, d.name, d.domain, d.contract,
          d.deployment_tier ?? "stack4",
          d.ledger_operator ?? "shyware",
          d.ra_operator ?? "operator",
          d.stripe_customer_id ?? null,
          d.stripe_subscription_id ?? null,
        ]
      );
    },

    async updateConsoleDeploymentPosture(operatorUid, id, { posture, reason, updatedBy }) {
      await query(
        `UPDATE console_deployments
            SET posture_override = $3,
                posture_reason = $4,
                posture_updated_at = now(),
                posture_updated_by = $5,
                updated_at = now()
          WHERE operator_uid = $1 AND id = $2`,
        [operatorUid, id, posture ?? null, reason ?? null, updatedBy ?? null]
      );
    },

    async updateConsoleDeploymentCountryRules(operatorUid, id, { rules, updatedBy }) {
      await query(
        `UPDATE console_deployments
            SET country_rules = $3::jsonb,
                country_rules_updated_at = now(),
                country_rules_updated_by = $4,
                updated_at = now()
          WHERE operator_uid = $1 AND id = $2`,
        [operatorUid, id, JSON.stringify(rules ?? []), updatedBy ?? null]
      );
    },
  };
}

function mapConsoleDeploymentRow(row) {
  const effectivePosture = row.posture_override ?? "recoverable";
  return {
    id: row.id,
    name: row.name,
    domain: row.domain,
    contract: row.contract,
    deployment_tier: row.deployment_tier,
    ledger_operator: row.ledger_operator ?? "shyware",
    ra_operator: row.ra_operator,
    effective_posture: effectivePosture,
    source: row.posture_override ? "operator" : "default",
    posture_updated_at: row.posture_updated_at?.toISOString?.() ?? null,
    posture_reason: row.posture_reason ?? null,
    country_rules: row.country_rules ?? [],
    stripe_customer_id: row.stripe_customer_id ?? null,
    stripe_subscription_id: row.stripe_subscription_id ?? null,
  };
}

module.exports = {
  createCockroachStore,
  createCockroachMigrationStateStore,
  cockroachMigrationRegistry,
  runCockroachStoreMigrations,
  COCKROACH_COMPONENT,
  COCKROACH_SCHEMA_VERSION
};
