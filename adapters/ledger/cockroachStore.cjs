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
const COCKROACH_SCHEMA_VERSION = "2026-08-31.3";

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

CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY,
  public_key TEXT NULL,
  counter INT NOT NULL DEFAULT 0,
  bundle_id TEXT NULL,
  service TEXT NULL,
  platform TEXT NULL,
  encrypted_key TEXT NULL,
  iv TEXT NULL,
  auth_tag TEXT NULL,
  key_version TEXT NULL,
  revoked BOOLEAN NOT NULL DEFAULT false,
  request_count INT NOT NULL DEFAULT 0,
  ip_address TEXT NULL,
  registered_at TIMESTAMPTZ NULL,
  issued_at TIMESTAMPTZ NULL,
  last_seen TIMESTAMPTZ NULL,
  last_used TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  email TEXT NULL,
  digit_verification_status TEXT NULL,
  age_range TEXT NULL,
  political_party TEXT NULL,
  state TEXT NULL,
  employment_expertise TEXT NULL,
  education_expertise TEXT NULL,
  hobby_expertise TEXT NULL,
  parent_phone TEXT NULL,
  profile JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  verified_at TIMESTAMPTZ NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_votes (
  user_id TEXT NOT NULL,
  bill_id TEXT NOT NULL,
  vote TEXT NOT NULL,
  bill_committees JSONB NOT NULL DEFAULT '[]'::jsonb,
  state TEXT NULL,
  age_range TEXT NULL,
  employment_expertise TEXT NULL,
  education_expertise TEXT NULL,
  hobby_expertise TEXT NULL,
  political_party TEXT NULL,
  verified BOOLEAN NOT NULL DEFAULT false,
  verified_age INT NULL,
  counted_in_results BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, bill_id)
);

CREATE INDEX IF NOT EXISTS user_votes_bill_id_idx ON user_votes (bill_id);

CREATE TABLE IF NOT EXISTS bill_votes (
  bill_id TEXT PRIMARY KEY,
  support_count INT NOT NULL DEFAULT 0,
  oppose_count INT NOT NULL DEFAULT 0,
  total_votes INT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_bookmarks (
  user_id TEXT NOT NULL,
  bill_id TEXT NOT NULL,
  bill_number TEXT NULL,
  title TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, bill_id)
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
        await pool.query("SELECT 1 FROM vote_receipts LIMIT 1");
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
      up: async ({ pool }) => {
        await pool.query(`
          CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            public_key TEXT NULL,
            counter INT NOT NULL DEFAULT 0,
            bundle_id TEXT NULL,
            service TEXT NULL,
            platform TEXT NULL,
            encrypted_key TEXT NULL,
            iv TEXT NULL,
            auth_tag TEXT NULL,
            key_version TEXT NULL,
            revoked BOOLEAN NOT NULL DEFAULT false,
            request_count INT NOT NULL DEFAULT 0,
            ip_address TEXT NULL,
            registered_at TIMESTAMPTZ NULL,
            issued_at TIMESTAMPTZ NULL,
            last_seen TIMESTAMPTZ NULL,
            last_used TIMESTAMPTZ NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
          );

          CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            email TEXT NULL,
            digit_verification_status TEXT NULL,
            age_range TEXT NULL,
            political_party TEXT NULL,
            state TEXT NULL,
            employment_expertise TEXT NULL,
            education_expertise TEXT NULL,
            hobby_expertise TEXT NULL,
            parent_phone TEXT NULL,
            profile JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            verified_at TIMESTAMPTZ NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
          );

          CREATE TABLE IF NOT EXISTS user_votes (
            user_id TEXT NOT NULL,
            bill_id TEXT NOT NULL,
            vote TEXT NOT NULL,
            bill_committees JSONB NOT NULL DEFAULT '[]'::jsonb,
            state TEXT NULL,
            age_range TEXT NULL,
            employment_expertise TEXT NULL,
            education_expertise TEXT NULL,
            hobby_expertise TEXT NULL,
            political_party TEXT NULL,
            verified BOOLEAN NOT NULL DEFAULT false,
            verified_age INT NULL,
            counted_in_results BOOLEAN NOT NULL DEFAULT false,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (user_id, bill_id)
          );

          CREATE INDEX IF NOT EXISTS user_votes_bill_id_idx ON user_votes (bill_id);

          CREATE TABLE IF NOT EXISTS bill_votes (
            bill_id TEXT PRIMARY KEY,
            support_count INT NOT NULL DEFAULT 0,
            oppose_count INT NOT NULL DEFAULT 0,
            total_votes INT NOT NULL DEFAULT 0,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
          );

          CREATE TABLE IF NOT EXISTS user_bookmarks (
            user_id TEXT NOT NULL,
            bill_id TEXT NOT NULL,
            bill_number TEXT NULL,
            title TEXT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (user_id, bill_id)
          );
        `);
      },
      validate: async ({ pool }) => {
        await pool.query("SELECT 1 FROM devices LIMIT 1");
        await pool.query("SELECT 1 FROM users LIMIT 1");
        await pool.query("SELECT 1 FROM user_votes LIMIT 1");
        await pool.query("SELECT 1 FROM bill_votes LIMIT 1");
        await pool.query("SELECT 1 FROM user_bookmarks LIMIT 1");
      }
    },
    {
      id: "cockroach-store:devices-revocation-metadata-2026-08-30.2",
      fromVersion: "2026-08-30.1",
      toVersion: "2026-08-30.2",
      type: "additive",
      description: "Add revocation metadata columns to devices.",
      canAutoRun: true,
      up: async ({ pool }) => {
        await pool.query(`
          ALTER TABLE devices ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ NULL;
          ALTER TABLE devices ADD COLUMN IF NOT EXISTS revoked_reason TEXT NULL;
          ALTER TABLE devices ADD COLUMN IF NOT EXISTS revoked_by TEXT NULL;
        `);
      },
      validate: async ({ pool }) => {
        await pool.query("SELECT revoked_at, revoked_reason, revoked_by FROM devices LIMIT 1");
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
      up: async ({ pool }) => {
        await pool.query(`
          CREATE TABLE IF NOT EXISTS registered_campaigns (
            campaign_id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            created_by TEXT NOT NULL,
            name TEXT NOT NULL,
            org_name TEXT NOT NULL,
            agreed_to_tos_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            tos_version TEXT NOT NULL DEFAULT '1.0',
            stripe_customer_id TEXT NULL,
            active BOOLEAN NOT NULL DEFAULT true,
            contacts_used_this_month INT NOT NULL DEFAULT 0,
            monthly_contact_limit INT NOT NULL DEFAULT 1000,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
          );

          CREATE INDEX IF NOT EXISTS registered_campaigns_created_by_idx
            ON registered_campaigns (created_by);

          CREATE TABLE IF NOT EXISTS user_solicitation_prefs (
            user_id TEXT PRIMARY KEY,
            opted_in BOOLEAN NOT NULL DEFAULT false,
            share_email BOOLEAN NOT NULL DEFAULT false,
            share_phone BOOLEAN NOT NULL DEFAULT false,
            share_address BOOLEAN NOT NULL DEFAULT false,
            price_per_contact_cents INT NOT NULL DEFAULT 50,
            consent_version TEXT NULL,
            total_earnings_cents INT NOT NULL DEFAULT 0,
            stripe_connect_account_id TEXT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
          );

          CREATE INDEX IF NOT EXISTS user_solicitation_prefs_opted_in_idx
            ON user_solicitation_prefs (opted_in);

          CREATE TABLE IF NOT EXISTS contact_transactions (
            transaction_id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            campaign_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            contacted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            fields_shared JSONB NOT NULL DEFAULT '[]'::jsonb,
            gross_cents INT NOT NULL DEFAULT 0,
            platform_fee_cents INT NOT NULL DEFAULT 0,
            user_earnings_cents INT NOT NULL DEFAULT 0,
            stripe_payment_intent_id TEXT NULL,
            stripe_transfer_id TEXT NULL
          );

          CREATE INDEX IF NOT EXISTS contact_transactions_pi_idx
            ON contact_transactions (stripe_payment_intent_id);

          CREATE INDEX IF NOT EXISTS contact_transactions_campaign_idx
            ON contact_transactions (campaign_id);
        `);
      },
      validate: async ({ pool }) => {
        await pool.query("SELECT 1 FROM registered_campaigns LIMIT 1");
        await pool.query("SELECT 1 FROM user_solicitation_prefs LIMIT 1");
        await pool.query("SELECT 1 FROM contact_transactions LIMIT 1");
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
      up: async ({ pool }) => {
        await pool.query(`
          CREATE TABLE IF NOT EXISTS organization_messages (
            message_id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            organization_id TEXT NOT NULL,
            author_id TEXT NOT NULL,
            author_name TEXT NOT NULL,
            content TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'text',
            reactions JSONB NOT NULL DEFAULT '{}'::jsonb,
            permission_kit_message_id TEXT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
          );

          CREATE INDEX IF NOT EXISTS organization_messages_org_idx
            ON organization_messages (organization_id, created_at DESC);

          CREATE TABLE IF NOT EXISTS forum_posts (
            post_id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            author_id TEXT NOT NULL,
            author_name TEXT NOT NULL,
            content TEXT NOT NULL,
            bill_id TEXT NULL,
            organization_id TEXT NULL,
            like_count INT NOT NULL DEFAULT 0,
            comment_count INT NOT NULL DEFAULT 0,
            liked_by JSONB NOT NULL DEFAULT '[]'::jsonb,
            permission_kit_post_id TEXT NULL,
            is_sample BOOLEAN NOT NULL DEFAULT false,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
          );

          CREATE INDEX IF NOT EXISTS forum_posts_created_idx
            ON forum_posts (created_at DESC);
          CREATE INDEX IF NOT EXISTS forum_posts_bill_idx
            ON forum_posts (bill_id);
          CREATE INDEX IF NOT EXISTS forum_posts_org_idx
            ON forum_posts (organization_id);

          CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            title TEXT NOT NULL,
            latitude DOUBLE PRECISION NOT NULL,
            longitude DOUBLE PRECISION NOT NULL,
            address TEXT NOT NULL,
            start_date TIMESTAMPTZ NOT NULL,
            end_date TIMESTAMPTZ NOT NULL,
            description TEXT NULL,
            created_by TEXT NOT NULL,
            organization_id TEXT NULL,
            attendee_count INT NOT NULL DEFAULT 0,
            is_sample BOOLEAN NOT NULL DEFAULT false,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
          );

          CREATE INDEX IF NOT EXISTS events_start_date_idx
            ON events (start_date ASC);
          CREATE INDEX IF NOT EXISTS events_org_idx
            ON events (organization_id);

          CREATE TABLE IF NOT EXISTS event_attendees (
            event_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (event_id, user_id)
          );
        `);
      },
      validate: async ({ pool }) => {
        await pool.query("SELECT 1 FROM organization_messages LIMIT 1");
        await pool.query("SELECT 1 FROM forum_posts LIMIT 1");
        await pool.query("SELECT 1 FROM events LIMIT 1");
        await pool.query("SELECT 1 FROM event_attendees LIMIT 1");
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
      up: async ({ pool }) => {
        await pool.query(`
          CREATE TABLE IF NOT EXISTS permission_batches (
            batch_id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            user_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            posts JSONB NOT NULL DEFAULT '[]'::jsonb,
            messages JSONB NOT NULL DEFAULT '[]'::jsonb,
            processed_at TIMESTAMPTZ NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
          );

          CREATE INDEX IF NOT EXISTS permission_batches_user_idx
            ON permission_batches (user_id, created_at DESC);
        `);
      },
      validate: async ({ pool }) => {
        await pool.query("SELECT 1 FROM permission_batches LIMIT 1");
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

function toInt(value, fallback = 0) {
  if (value === null || value === undefined) return fallback;
  const n = typeof value === "number" ? value : parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
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

function mapDeviceRow(row) {
  if (!row) return null;
  return {
    deviceId: row.device_id,
    publicKey: row.public_key,
    counter: toInt(row.counter),
    bundleId: row.bundle_id,
    service: row.service,
    platform: row.platform,
    encryptedKey: row.encrypted_key,
    iv: row.iv,
    authTag: row.auth_tag,
    keyVersion: row.key_version,
    revoked: row.revoked,
    revokedAt: normalizeTimestamp(row.revoked_at),
    revokedReason: row.revoked_reason,
    revokedBy: row.revoked_by,
    requestCount: toInt(row.request_count),
    ipAddress: row.ip_address,
    registeredAt: normalizeTimestamp(row.registered_at),
    issuedAt: normalizeTimestamp(row.issued_at),
    lastSeen: normalizeTimestamp(row.last_seen),
    lastUsed: normalizeTimestamp(row.last_used),
    createdAt: normalizeTimestamp(row.created_at),
    updatedAt: normalizeTimestamp(row.updated_at)
  };
}

function mapUserRow(row) {
  if (!row) return null;
  return {
    ...(row.profile || {}),
    userId: row.user_id,
    email: row.email,
    digitVerificationStatus: row.digit_verification_status,
    ageRange: row.age_range,
    politicalParty: row.political_party,
    state: row.state,
    employmentExpertise: row.employment_expertise,
    educationExpertise: row.education_expertise,
    hobbyExpertise: row.hobby_expertise,
    parentPhone: row.parent_phone,
    createdAt: normalizeTimestamp(row.created_at),
    verifiedAt: normalizeTimestamp(row.verified_at),
    updatedAt: normalizeTimestamp(row.updated_at)
  };
}

function mapUserVoteRow(row) {
  if (!row) return null;
  return {
    userId: row.user_id,
    billId: row.bill_id,
    vote: row.vote,
    billCommittees: row.bill_committees || [],
    state: row.state,
    ageRange: row.age_range,
    employmentExpertise: row.employment_expertise,
    educationExpertise: row.education_expertise,
    hobbyExpertise: row.hobby_expertise,
    politicalParty: row.political_party,
    verified: row.verified,
    verifiedAge: row.verified_age === null ? null : toInt(row.verified_age),
    countedInResults: row.counted_in_results,
    createdAt: normalizeTimestamp(row.created_at),
    updatedAt: normalizeTimestamp(row.updated_at)
  };
}

function mapBillVotesRow(row) {
  if (!row) {
    return { billId: null, supportCount: 0, opposeCount: 0, totalVotes: 0, updatedAt: null };
  }
  return {
    billId: row.bill_id,
    supportCount: toInt(row.support_count),
    opposeCount: toInt(row.oppose_count),
    totalVotes: toInt(row.total_votes),
    updatedAt: normalizeTimestamp(row.updated_at)
  };
}

function mapUserBookmarkRow(row) {
  if (!row) return null;
  return {
    userId: row.user_id,
    billId: row.bill_id,
    billNumber: row.bill_number,
    title: row.title,
    createdAt: normalizeTimestamp(row.created_at)
  };
}

function mapCampaignRow(row) {
  if (!row) return null;
  return {
    campaignId: row.campaign_id,
    createdBy: row.created_by,
    name: row.name,
    orgName: row.org_name,
    agreedToToSAt: normalizeTimestamp(row.agreed_to_tos_at),
    tosVersion: row.tos_version,
    stripeCustomerId: row.stripe_customer_id,
    active: row.active,
    contactsUsedThisMonth: toInt(row.contacts_used_this_month),
    monthlyContactLimit: toInt(row.monthly_contact_limit),
    createdAt: normalizeTimestamp(row.created_at),
    updatedAt: normalizeTimestamp(row.updated_at)
  };
}

function mapSolicitationPrefsRow(row) {
  if (!row) return null;
  return {
    userId: row.user_id,
    optedIn: row.opted_in,
    shareEmail: row.share_email,
    sharePhone: row.share_phone,
    shareAddress: row.share_address,
    pricePerContactCents: toInt(row.price_per_contact_cents),
    consentVersion: row.consent_version,
    totalEarningsCents: toInt(row.total_earnings_cents),
    stripeConnectAccountId: row.stripe_connect_account_id,
    createdAt: normalizeTimestamp(row.created_at),
    updatedAt: normalizeTimestamp(row.updated_at)
  };
}

function mapContactTransactionRow(row) {
  if (!row) return null;
  return {
    transactionId: row.transaction_id,
    campaignId: row.campaign_id,
    userId: row.user_id,
    contactedAt: normalizeTimestamp(row.contacted_at),
    fieldsShared: row.fields_shared || [],
    grossCents: toInt(row.gross_cents),
    platformFeeCents: toInt(row.platform_fee_cents),
    userEarningsCents: toInt(row.user_earnings_cents),
    stripePaymentIntentId: row.stripe_payment_intent_id,
    stripeTransferId: row.stripe_transfer_id
  };
}

function mapOrganizationMessageRow(row) {
  if (!row) return null;
  return {
    messageId: row.message_id,
    organizationId: row.organization_id,
    authorId: row.author_id,
    authorName: row.author_name,
    content: row.content,
    type: row.type,
    reactions: row.reactions || {},
    permissionKitMessageId: row.permission_kit_message_id,
    createdAt: normalizeTimestamp(row.created_at)
  };
}

function mapForumPostRow(row) {
  if (!row) return null;
  return {
    postId: row.post_id,
    authorId: row.author_id,
    authorName: row.author_name,
    content: row.content,
    billId: row.bill_id,
    organizationId: row.organization_id,
    likeCount: toInt(row.like_count),
    commentCount: toInt(row.comment_count),
    likedBy: row.liked_by || [],
    permissionKitPostId: row.permission_kit_post_id,
    isSample: row.is_sample,
    createdAt: normalizeTimestamp(row.created_at)
  };
}

function mapEventRow(row) {
  if (!row) return null;
  return {
    eventId: row.event_id,
    title: row.title,
    latitude: row.latitude,
    longitude: row.longitude,
    address: row.address,
    startDate: normalizeTimestamp(row.start_date),
    endDate: normalizeTimestamp(row.end_date),
    description: row.description,
    createdBy: row.created_by,
    organizationId: row.organization_id,
    attendeeCount: toInt(row.attendee_count),
    isSample: row.is_sample,
    createdAt: normalizeTimestamp(row.created_at),
    updatedAt: normalizeTimestamp(row.updated_at)
  };
}

function mapPermissionBatchRow(row) {
  if (!row) return null;
  return {
    batchId: row.batch_id,
    userId: row.user_id,
    status: row.status,
    posts: row.posts || [],
    messages: row.messages || [],
    processedAt: normalizeTimestamp(row.processed_at),
    createdAt: normalizeTimestamp(row.created_at)
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

    // -- devices (App Attest registry + perpetual API key cache) --------
    async getDevice(deviceId) {
      const result = await query(`SELECT * FROM devices WHERE device_id = $1`, [
        deviceId
      ]);
      return mapDeviceRow(result.rows[0] || null);
    },
    async upsertDeviceRegistration({ deviceId, publicKey, counter = 0, bundleId }) {
      const result = await query(
        `INSERT INTO devices (device_id, public_key, counter, bundle_id, registered_at, updated_at)
         VALUES ($1,$2,$3,$4, now(), now())
         ON CONFLICT (device_id) DO UPDATE SET
           public_key = EXCLUDED.public_key,
           counter = EXCLUDED.counter,
           bundle_id = EXCLUDED.bundle_id,
           registered_at = EXCLUDED.registered_at,
           updated_at = now()
         RETURNING *`,
        [deviceId, publicKey, counter, bundleId || null]
      );
      return mapDeviceRow(result.rows[0]);
    },
    async deleteDevice(deviceId) {
      await query(`DELETE FROM devices WHERE device_id = $1`, [deviceId]);
    },
    async updateDeviceCounter(deviceId, counter) {
      await query(
        `UPDATE devices SET counter = $2, last_used = now(), updated_at = now()
         WHERE device_id = $1`,
        [deviceId, counter]
      );
    },
    async upsertDeviceKeyIssuance({
      deviceId,
      service,
      platform,
      encryptedKey,
      iv,
      authTag,
      keyVersion,
      ipAddress
    }) {
      const result = await query(
        `INSERT INTO devices (
           device_id, service, platform, encrypted_key, iv, auth_tag, key_version,
           issued_at, last_seen, revoked, request_count, ip_address, updated_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7, now(), now(), false, 1, $8, now())
         ON CONFLICT (device_id) DO UPDATE SET
           service = EXCLUDED.service,
           platform = EXCLUDED.platform,
           encrypted_key = EXCLUDED.encrypted_key,
           iv = EXCLUDED.iv,
           auth_tag = EXCLUDED.auth_tag,
           key_version = EXCLUDED.key_version,
           issued_at = now(),
           last_seen = now(),
           revoked = false,
           request_count = 1,
           ip_address = EXCLUDED.ip_address,
           updated_at = now()
         RETURNING *`,
        [
          deviceId,
          service || null,
          platform || null,
          encryptedKey,
          iv,
          authTag,
          keyVersion || null,
          ipAddress || null
        ]
      );
      return mapDeviceRow(result.rows[0]);
    },
    async touchDeviceLastSeen(deviceId) {
      const result = await query(
        `UPDATE devices SET last_seen = now(), request_count = request_count + 1, updated_at = now()
         WHERE device_id = $1
         RETURNING *`,
        [deviceId]
      );
      return mapDeviceRow(result.rows[0] || null);
    },
    async setDeviceRevoked(deviceId, revoked, { reason = null, by = null } = {}) {
      const result = await query(
        `UPDATE devices SET
           revoked = $2,
           revoked_at = CASE WHEN $2 THEN now() ELSE NULL END,
           revoked_reason = CASE WHEN $2 THEN $3 ELSE NULL END,
           revoked_by = CASE WHEN $2 THEN $4 ELSE NULL END,
           updated_at = now()
         WHERE device_id = $1
         RETURNING *`,
        [deviceId, Boolean(revoked), reason, by]
      );
      return mapDeviceRow(result.rows[0] || null);
    },
    async listDevices({ limit = 50, platform = null, revoked = null } = {}) {
      const result = await query(
        `SELECT * FROM devices
         WHERE ($2::text IS NULL OR platform = $2)
           AND ($3::boolean IS NULL OR revoked = $3)
         ORDER BY issued_at DESC NULLS LAST, updated_at DESC
         LIMIT $1`,
        [limit, platform, revoked]
      );
      return result.rows.map(mapDeviceRow);
    },

    // -- users ------------------------------------------------------------
    async getUser(userId) {
      const result = await query(`SELECT * FROM users WHERE user_id = $1`, [
        userId
      ]);
      return mapUserRow(result.rows[0] || null);
    },
    async upsertUser(userId, data = {}) {
      const {
        email = null,
        digitVerificationStatus = null,
        ageRange = null,
        politicalParty = null,
        state = null,
        employmentExpertise = null,
        educationExpertise = null,
        hobbyExpertise = null,
        parentPhone = null,
        verifiedAt = null,
        ...rest
      } = data;
      const result = await query(
        `INSERT INTO users (
           user_id, email, digit_verification_status, age_range, political_party, state,
           employment_expertise, education_expertise, hobby_expertise, parent_phone,
           profile, verified_at, updated_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,now())
         ON CONFLICT (user_id) DO UPDATE SET
           email = COALESCE($2, users.email),
           digit_verification_status = COALESCE($3, users.digit_verification_status),
           age_range = COALESCE($4, users.age_range),
           political_party = COALESCE($5, users.political_party),
           state = COALESCE($6, users.state),
           employment_expertise = COALESCE($7, users.employment_expertise),
           education_expertise = COALESCE($8, users.education_expertise),
           hobby_expertise = COALESCE($9, users.hobby_expertise),
           parent_phone = COALESCE($10, users.parent_phone),
           profile = users.profile || $11::jsonb,
           verified_at = COALESCE($12, users.verified_at),
           updated_at = now()
         RETURNING *`,
        [
          userId,
          email,
          digitVerificationStatus,
          ageRange,
          politicalParty,
          state,
          employmentExpertise,
          educationExpertise,
          hobbyExpertise,
          parentPhone,
          JSON.stringify(rest || {}),
          verifiedAt
        ]
      );
      return mapUserRow(result.rows[0]);
    },
    async deleteUser(userId) {
      await query(`DELETE FROM users WHERE user_id = $1`, [userId]);
    },

    // -- votes / bookmarks --------------------------------------------
    async getUserVote(userId, billId) {
      const result = await query(
        `SELECT * FROM user_votes WHERE user_id = $1 AND bill_id = $2`,
        [userId, billId]
      );
      return mapUserVoteRow(result.rows[0] || null);
    },
    async setUserVote(userId, billId, data = {}) {
      const result = await query(
        `INSERT INTO user_votes (
           user_id, bill_id, vote, bill_committees, state, age_range,
           employment_expertise, education_expertise, hobby_expertise, political_party,
           verified, verified_age, counted_in_results, updated_at
         ) VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11,$12,$13, now())
         ON CONFLICT (user_id, bill_id) DO UPDATE SET
           vote = EXCLUDED.vote,
           bill_committees = EXCLUDED.bill_committees,
           state = EXCLUDED.state,
           age_range = EXCLUDED.age_range,
           employment_expertise = EXCLUDED.employment_expertise,
           education_expertise = EXCLUDED.education_expertise,
           hobby_expertise = EXCLUDED.hobby_expertise,
           political_party = EXCLUDED.political_party,
           verified = EXCLUDED.verified,
           verified_age = EXCLUDED.verified_age,
           counted_in_results = EXCLUDED.counted_in_results,
           updated_at = now()
         RETURNING *`,
        [
          userId,
          billId,
          data.vote,
          JSON.stringify(data.billCommittees || []),
          data.state || null,
          data.ageRange || null,
          data.employmentExpertise || null,
          data.educationExpertise || null,
          data.hobbyExpertise || null,
          data.politicalParty || null,
          Boolean(data.verified),
          data.verifiedAge ?? null,
          Boolean(data.countedInResults)
        ]
      );
      return mapUserVoteRow(result.rows[0]);
    },
    async listUserVotes(userId) {
      const result = await query(
        `SELECT * FROM user_votes WHERE user_id = $1 ORDER BY updated_at DESC`,
        [userId]
      );
      return result.rows.map(mapUserVoteRow);
    },
    async adjustBillVoteCounts(billId, { supportDelta = 0, opposeDelta = 0, totalDelta = 0 }) {
      const result = await query(
        `INSERT INTO bill_votes (bill_id, support_count, oppose_count, total_votes, updated_at)
         VALUES ($1, GREATEST($2,0), GREATEST($3,0), GREATEST($4,0), now())
         ON CONFLICT (bill_id) DO UPDATE SET
           support_count = GREATEST(bill_votes.support_count + $2, 0),
           oppose_count = GREATEST(bill_votes.oppose_count + $3, 0),
           total_votes = GREATEST(bill_votes.total_votes + $4, 0),
           updated_at = now()
         RETURNING *`,
        [billId, supportDelta, opposeDelta, totalDelta]
      );
      return mapBillVotesRow(result.rows[0]);
    },
    async getBillVotes(billId) {
      const result = await query(`SELECT * FROM bill_votes WHERE bill_id = $1`, [
        billId
      ]);
      return mapBillVotesRow(result.rows[0] || null);
    },
    async setUserBookmark(userId, billId, { billNumber = null, title = null } = {}) {
      const result = await query(
        `INSERT INTO user_bookmarks (user_id, bill_id, bill_number, title, created_at)
         VALUES ($1,$2,$3,$4, now())
         ON CONFLICT (user_id, bill_id) DO UPDATE SET
           bill_number = EXCLUDED.bill_number,
           title = EXCLUDED.title
         RETURNING *`,
        [userId, billId, billNumber, title]
      );
      return mapUserBookmarkRow(result.rows[0]);
    },
    async deleteUserBookmark(userId, billId) {
      await query(
        `DELETE FROM user_bookmarks WHERE user_id = $1 AND bill_id = $2`,
        [userId, billId]
      );
    },
    async listUserBookmarks(userId) {
      const result = await query(
        `SELECT * FROM user_bookmarks WHERE user_id = $1 ORDER BY created_at DESC`,
        [userId]
      );
      return result.rows.map(mapUserBookmarkRow);
    },
    async deleteAllUserVotes(userId) {
      await query(`DELETE FROM user_votes WHERE user_id = $1`, [userId]);
    },
    async deleteAllUserBookmarks(userId) {
      await query(`DELETE FROM user_bookmarks WHERE user_id = $1`, [userId]);
    },

    // -- marketplace: campaigns / solicitation prefs / contact transactions --
    async createCampaign({
      createdBy,
      name,
      orgName,
      stripeCustomerId = null,
      tosVersion = "1.0",
      monthlyContactLimit = 1000
    }) {
      const result = await query(
        `INSERT INTO registered_campaigns (
           campaign_id, created_by, name, org_name, agreed_to_tos_at, tos_version,
           stripe_customer_id, active, contacts_used_this_month, monthly_contact_limit
         ) VALUES (gen_random_uuid()::text, $1,$2,$3, now(), $4, $5, true, 0, $6)
         RETURNING *`,
        [createdBy, name, orgName, tosVersion, stripeCustomerId, monthlyContactLimit]
      );
      return mapCampaignRow(result.rows[0]);
    },
    async getCampaign(campaignId) {
      const result = await query(
        `SELECT * FROM registered_campaigns WHERE campaign_id = $1`,
        [campaignId]
      );
      return mapCampaignRow(result.rows[0] || null);
    },

    async getSolicitationPrefs(userId) {
      const result = await query(
        `SELECT * FROM user_solicitation_prefs WHERE user_id = $1`,
        [userId]
      );
      return mapSolicitationPrefsRow(result.rows[0] || null);
    },
    async upsertSolicitationPrefs(userId, data = {}) {
      const result = await query(
        `INSERT INTO user_solicitation_prefs (
           user_id, opted_in, share_email, share_phone, share_address,
           price_per_contact_cents, consent_version, stripe_connect_account_id, updated_at
         ) VALUES (
           $1,
           COALESCE($2, false), COALESCE($3, false), COALESCE($4, false), COALESCE($5, false),
           COALESCE($6, 50), $7, $8, now()
         )
         ON CONFLICT (user_id) DO UPDATE SET
           opted_in = COALESCE($2, user_solicitation_prefs.opted_in),
           share_email = COALESCE($3, user_solicitation_prefs.share_email),
           share_phone = COALESCE($4, user_solicitation_prefs.share_phone),
           share_address = COALESCE($5, user_solicitation_prefs.share_address),
           price_per_contact_cents = COALESCE($6, user_solicitation_prefs.price_per_contact_cents),
           consent_version = COALESCE($7, user_solicitation_prefs.consent_version),
           stripe_connect_account_id = COALESCE($8, user_solicitation_prefs.stripe_connect_account_id),
           updated_at = now()
         RETURNING *`,
        [
          userId,
          data.optedIn ?? null,
          data.shareEmail ?? null,
          data.sharePhone ?? null,
          data.shareAddress ?? null,
          data.pricePerContactCents ?? null,
          data.consentVersion ?? null,
          data.stripeConnectAccountId ?? null
        ]
      );
      return mapSolicitationPrefsRow(result.rows[0]);
    },
    async incrementSolicitationEarnings(userId, deltaCents) {
      const result = await query(
        `INSERT INTO user_solicitation_prefs (user_id, total_earnings_cents, updated_at)
         VALUES ($1, GREATEST($2,0), now())
         ON CONFLICT (user_id) DO UPDATE SET
           total_earnings_cents = user_solicitation_prefs.total_earnings_cents + $2,
           updated_at = now()
         RETURNING *`,
        [userId, deltaCents]
      );
      return mapSolicitationPrefsRow(result.rows[0]);
    },
    async listOptedInSolicitationPrefs() {
      const result = await query(
        `SELECT * FROM user_solicitation_prefs WHERE opted_in = true`
      );
      return result.rows.map(mapSolicitationPrefsRow);
    },
    async deleteSolicitationPrefs(userId) {
      await query(`DELETE FROM user_solicitation_prefs WHERE user_id = $1`, [
        userId
      ]);
    },

    async createContactTransaction({
      campaignId,
      userId,
      fieldsShared,
      grossCents,
      platformFeeCents,
      userEarningsCents,
      stripePaymentIntentId
    }) {
      const result = await query(
        `INSERT INTO contact_transactions (
           transaction_id, campaign_id, user_id, contacted_at, fields_shared,
           gross_cents, platform_fee_cents, user_earnings_cents, stripe_payment_intent_id
         ) VALUES (gen_random_uuid()::text, $1,$2, now(), $3::jsonb, $4,$5,$6,$7)
         RETURNING *`,
        [
          campaignId,
          userId,
          JSON.stringify(fieldsShared || []),
          grossCents,
          platformFeeCents,
          userEarningsCents,
          stripePaymentIntentId || null
        ]
      );
      return mapContactTransactionRow(result.rows[0]);
    },
    async listContactTransactionsByPaymentIntent(paymentIntentId) {
      const result = await query(
        `SELECT * FROM contact_transactions WHERE stripe_payment_intent_id = $1`,
        [paymentIntentId]
      );
      return result.rows.map(mapContactTransactionRow);
    },
    async setContactTransactionTransfer(transactionId, transferId) {
      await query(
        `UPDATE contact_transactions SET stripe_transfer_id = $2 WHERE transaction_id = $1`,
        [transactionId, transferId]
      );
    },

    // -- organization messages / forum posts / events --------------------
    async createOrganizationMessage({
      organizationId,
      authorId,
      authorName,
      content,
      type = "text",
      permissionKitMessageId = null
    }) {
      const result = await query(
        `INSERT INTO organization_messages (
           message_id, organization_id, author_id, author_name, content, type, permission_kit_message_id
         ) VALUES (gen_random_uuid()::text, $1,$2,$3,$4,$5,$6)
         RETURNING *`,
        [organizationId, authorId, authorName, content, type, permissionKitMessageId]
      );
      return mapOrganizationMessageRow(result.rows[0]);
    },
    async listOrganizationMessages(organizationId, limit = 50) {
      const result = await query(
        `SELECT * FROM organization_messages WHERE organization_id = $1
         ORDER BY created_at DESC LIMIT $2`,
        [organizationId, limit]
      );
      return result.rows.map(mapOrganizationMessageRow);
    },

    async createForumPost({
      authorId,
      authorName,
      content,
      billId = null,
      organizationId = null,
      permissionKitPostId = null
    }) {
      const result = await query(
        `INSERT INTO forum_posts (
           post_id, author_id, author_name, content, bill_id, organization_id, permission_kit_post_id
         ) VALUES (gen_random_uuid()::text, $1,$2,$3,$4,$5,$6)
         RETURNING *`,
        [authorId, authorName, content, billId, organizationId, permissionKitPostId]
      );
      return mapForumPostRow(result.rows[0]);
    },
    async listForumPosts({ limit = 50, billId = null, organizationId = null } = {}) {
      const result = await query(
        `SELECT * FROM forum_posts
         WHERE ($2::text IS NULL OR bill_id = $2)
           AND ($3::text IS NULL OR organization_id = $3)
         ORDER BY created_at DESC LIMIT $1`,
        [limit, billId, organizationId]
      );
      return result.rows.map(mapForumPostRow);
    },

    async createEvent({
      title,
      latitude,
      longitude,
      address,
      startDate,
      endDate,
      description = null,
      createdBy,
      organizationId = null
    }) {
      const result = await query(
        `INSERT INTO events (
           event_id, title, latitude, longitude, address, start_date, end_date,
           description, created_by, organization_id
         ) VALUES (gen_random_uuid()::text, $1,$2,$3,$4,$5::timestamptz,$6::timestamptz,$7,$8,$9)
         RETURNING *`,
        [title, latitude, longitude, address, startDate, endDate, description, createdBy, organizationId]
      );
      return mapEventRow(result.rows[0]);
    },
    async getEvent(eventId) {
      const result = await query(`SELECT * FROM events WHERE event_id = $1`, [
        eventId
      ]);
      return mapEventRow(result.rows[0] || null);
    },
    async listUpcomingEvents(limit = 50) {
      const result = await query(
        `SELECT * FROM events WHERE start_date > now() ORDER BY start_date ASC LIMIT $1`,
        [limit]
      );
      return result.rows.map(mapEventRow);
    },
    async addEventAttendee(eventId, userId) {
      const result = await query(
        `WITH ins AS (
           INSERT INTO event_attendees (event_id, user_id)
           VALUES ($1, $2)
           ON CONFLICT (event_id, user_id) DO NOTHING
           RETURNING event_id
         )
         UPDATE events SET
           attendee_count = attendee_count + (SELECT count(*) FROM ins),
           updated_at = now()
         WHERE event_id = $1
         RETURNING *`,
        [eventId, userId]
      );
      return mapEventRow(result.rows[0] || null);
    },
    async removeEventAttendee(eventId, userId) {
      const result = await query(
        `WITH del AS (
           DELETE FROM event_attendees WHERE event_id = $1 AND user_id = $2
           RETURNING event_id
         )
         UPDATE events SET
           attendee_count = GREATEST(attendee_count - (SELECT count(*) FROM del), 0),
           updated_at = now()
         WHERE event_id = $1
         RETURNING *`,
        [eventId, userId]
      );
      return mapEventRow(result.rows[0] || null);
    },

    // -- permission batches (PermissionKit minor-consent queueing) -------
    async createPermissionBatch({ userId, posts = [], messages = [] }) {
      const result = await query(
        `INSERT INTO permission_batches (batch_id, user_id, status, posts, messages)
         VALUES (gen_random_uuid()::text, $1, 'pending', $2::jsonb, $3::jsonb)
         RETURNING *`,
        [userId, JSON.stringify(posts), JSON.stringify(messages)]
      );
      return mapPermissionBatchRow(result.rows[0]);
    },
    async getPermissionBatch(batchId) {
      const result = await query(
        `SELECT * FROM permission_batches WHERE batch_id = $1`,
        [batchId]
      );
      return mapPermissionBatchRow(result.rows[0] || null);
    },
    async setPermissionBatchStatus(batchId, status) {
      const result = await query(
        `UPDATE permission_batches SET status = $2, processed_at = now()
         WHERE batch_id = $1
         RETURNING *`,
        [batchId, status]
      );
      return mapPermissionBatchRow(result.rows[0] || null);
    },

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
