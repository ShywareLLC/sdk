const crypto = require("crypto");

function trimString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function sortValue(value) {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value && typeof value === "object") {
    return Object.keys(value)
      .sort()
      .reduce((accumulator, key) => {
        accumulator[key] = sortValue(value[key]);
        return accumulator;
      }, {});
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(sortValue(value));
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function normalizeTenantId(value, fallback = "default") {
  return trimString(value) || fallback;
}

function toIso(value) {
  if (!value) return null;
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function normalizeMailboxRecord(row = {}) {
  return {
    tenantId: normalizeTenantId(row.tenantId ?? row.tenant_id),
    mailboxId: row.mailboxId ?? row.mailbox_id,
    ownerUid: row.ownerUid ?? row.owner_uid ?? null,
    label: row.label,
    address: row.address,
    accountLabel: row.accountLabel ?? row.account_label,
    accountScope: row.accountScope ?? row.account_scope,
    routeHint: row.routeHint ?? row.route_hint,
    mailboxScope: row.mailboxScope ?? row.mailbox_scope,
    auditPolicy: row.auditPolicy ?? row.audit_policy,
    deliveryState: row.deliveryState ?? row.delivery_state,
    deliveryWindow: row.deliveryWindow ?? row.delivery_window,
    excerpt: row.excerpt,
    counterpartyRoute: row.counterpartyRoute ?? row.counterparty_route,
    createdAt: toIso(row.createdAt ?? row.created_at),
    updatedAt: toIso(row.updatedAt ?? row.updated_at),
  };
}

function normalizeDispatchRecord(row = {}) {
  return {
    tenantId: normalizeTenantId(row.tenantId ?? row.tenant_id),
    messageId: row.messageId ?? row.message_id,
    dispatchId: row.dispatchId ?? row.dispatch_id,
    mailboxId: row.mailboxId ?? row.mailbox_id,
    peerMailboxId: row.peerMailboxId ?? row.peer_mailbox_id ?? null,
    direction: row.direction,
    status: row.status,
    recipientAddress: row.recipientAddress ?? row.recipient_address,
    senderAddress: row.senderAddress ?? row.sender_address,
    requestedDeliveryWindow:
      row.requestedDeliveryWindow ?? row.requested_delivery_window,
    timestamp: toIso(row.timestamp),
    payloadCommitment: row.payloadCommitment ?? row.payload_commitment,
    auditSurface: sortValue(row.auditSurface ?? row.audit_surface ?? {}),
    contentClass: row.contentClass ?? row.content_class,
    payloadFormat: row.payloadFormat ?? row.payload_format,
    auditMode: row.auditMode ?? row.audit_mode,
    sensitivity: row.sensitivity,
    recoveryMode: row.recoveryMode ?? row.recovery_mode,
    contentDisposition: row.contentDisposition ?? row.content_disposition,
    attachmentCount: Number(row.attachmentCount ?? row.attachment_count ?? 0),
    privateFieldCount: Number(row.privateFieldCount ?? row.private_field_count ?? 0),
    sealedPayload: sortValue(row.sealedPayload ?? row.sealed_payload ?? {}),
    createdAt: toIso(row.createdAt ?? row.created_at),
  };
}

function normalizeReceiptRecord(row = {}) {
  return {
    tenantId: normalizeTenantId(row.tenantId ?? row.tenant_id),
    mailboxId: row.mailboxId ?? row.mailbox_id,
    mailboxAddress: row.mailboxAddress ?? row.mailbox_address,
    mailboxScope: row.mailboxScope ?? row.mailbox_scope,
    lastDispatchId: row.lastDispatchId ?? row.last_dispatch_id ?? null,
    lastPayloadCommitment:
      row.lastPayloadCommitment ?? row.last_payload_commitment ?? null,
    recoveryRef: row.recoveryRef ?? row.recovery_ref,
    recoveryMode: row.recoveryMode ?? row.recovery_mode,
    sealedContent:
      row.sealedContent === undefined ? row.sealed_content : row.sealedContent,
    createdAt: toIso(row.createdAt ?? row.created_at),
    updatedAt: toIso(row.updatedAt ?? row.updated_at),
  };
}

function collectionRoot(rows) {
  const digests = rows
    .map((row) => sha256Hex(canonicalJson(row)))
    .sort();
  return sha256Hex(JSON.stringify(digests));
}

function createCheckpointPayload({
  tenantId,
  mailboxes = [],
  dispatches = [],
  receipts = [],
  previousCheckpointId = null,
  sourceDeployment = {},
  sourceCheckpoint = null,
  createdAt = new Date().toISOString(),
} = {}) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const normalizedMailboxes = mailboxes.map(normalizeMailboxRecord);
  const normalizedDispatches = dispatches.map(normalizeDispatchRecord);
  const normalizedReceipts = receipts.map(normalizeReceiptRecord);

  const roots = {
    mailboxes: collectionRoot(normalizedMailboxes),
    dispatches: collectionRoot(normalizedDispatches),
    receipts: collectionRoot(normalizedReceipts),
  };

  const counts = {
    mailboxes: normalizedMailboxes.length,
    dispatches: normalizedDispatches.length,
    receipts: normalizedReceipts.length,
  };

  const lineage = {
    previousCheckpointId: trimString(previousCheckpointId) || null,
    sourceCheckpointId: trimString(sourceCheckpoint?.checkpointId) || null,
    sourceCheckpointDigest: trimString(sourceCheckpoint?.digest) || null,
  };

  const body = {
    schemaVersion: "scytale-cutover-v1",
    tenantId: normalizedTenantId,
    createdAt: toIso(createdAt),
    counts,
    roots,
    lineage,
    sourceDeployment: sortValue(sourceDeployment || {}),
  };

  const digest = sha256Hex(canonicalJson(body));
  return {
    checkpointId: `chk-${digest.slice(0, 16)}`,
    digest,
    ...body,
  };
}

function createSignedCheckpoint(checkpoint, privateKeyPem) {
  const privateKey = trimString(privateKeyPem);
  if (!privateKey) {
    return {
      ...checkpoint,
      signature: null,
      signer: null,
    };
  }

  const keyObject = crypto.createPrivateKey(privateKey);
  const publicKeyObject = crypto.createPublicKey(keyObject);
  const signature = crypto.sign(
    null,
    Buffer.from(checkpoint.digest, "utf8"),
    keyObject,
  );
  const publicKeyPem = publicKeyObject.export({ type: "spki", format: "pem" });
  const signerFingerprint = sha256Hex(String(publicKeyPem)).slice(0, 32);

  return {
    ...checkpoint,
    signature: signature.toString("base64"),
    signer: {
      algorithm: "ed25519",
      publicKeyPem: String(publicKeyPem),
      publicKeyFingerprint: signerFingerprint,
    },
  };
}

function verifySignedCheckpoint(checkpoint) {
  if (!checkpoint?.signature || !checkpoint?.signer?.publicKeyPem) {
    return false;
  }
  return crypto.verify(
    null,
    Buffer.from(checkpoint.digest, "utf8"),
    checkpoint.signer.publicKeyPem,
    Buffer.from(checkpoint.signature, "base64"),
  );
}

function createBootstrapStatement({
  bundle,
  destinationDeployment = {},
  destinationGenesisRef = null,
  destinationCheckpointRef = null,
  createdAt = new Date().toISOString(),
} = {}) {
  if (!bundle?.checkpoint?.digest) {
    throw new Error("A verified export bundle with a checkpoint is required to create a bootstrap statement");
  }

  const normalizedBundle = createExportBundle(bundle);
  const body = {
    schemaVersion: "scytale-bootstrap-v1",
    tenantId: normalizeTenantId(normalizedBundle.tenantId),
    createdAt: toIso(createdAt),
    sourceBundleSchema: normalizedBundle.schemaVersion,
    sourceCheckpointId: trimString(normalizedBundle.checkpoint.checkpointId) || null,
    sourceCheckpointDigest: trimString(normalizedBundle.checkpoint.digest) || null,
    sourceRoots: {
      mailboxes: normalizedBundle.checkpoint.roots?.mailboxes || null,
      dispatches: normalizedBundle.checkpoint.roots?.dispatches || null,
      receipts: normalizedBundle.checkpoint.roots?.receipts || null,
    },
    sourceCounts: {
      mailboxes: Number(normalizedBundle.checkpoint.counts?.mailboxes ?? 0),
      dispatches: Number(normalizedBundle.checkpoint.counts?.dispatches ?? 0),
      receipts: Number(normalizedBundle.checkpoint.counts?.receipts ?? 0),
    },
    destinationDeployment: sortValue(destinationDeployment || {}),
    destinationGenesisRef: trimString(destinationGenesisRef) || null,
    destinationCheckpointRef: trimString(destinationCheckpointRef) || null,
  };

  const digest = sha256Hex(canonicalJson(body));
  return {
    bootstrapId: `boot-${digest.slice(0, 16)}`,
    digest,
    ...body,
  };
}

function createSignedBootstrapStatement(statement, privateKeyPem) {
  return createSignedCheckpoint(statement, privateKeyPem);
}

function verifySignedBootstrapStatement(statement) {
  return verifySignedCheckpoint(statement);
}

function createExportBundle({
  tenantId,
  checkpoint,
  mailboxes = [],
  dispatches = [],
  receipts = [],
  sourceDeployment = {},
  exportedAt = new Date().toISOString(),
} = {}) {
  return {
    schemaVersion: "scytale-export-v1",
    tenantId: normalizeTenantId(tenantId),
    exportedAt: toIso(exportedAt),
    sourceDeployment: sortValue(sourceDeployment || {}),
    checkpoint,
    mailboxes: mailboxes.map(normalizeMailboxRecord),
    dispatches: dispatches.map(normalizeDispatchRecord),
    receipts: receipts.map(normalizeReceiptRecord),
  };
}

function verifyExportBundle(bundle = {}) {
  if (bundle.schemaVersion !== "scytale-export-v1") {
    return { ok: false, reason: "unsupported_bundle_schema" };
  }
  if (!bundle.checkpoint) {
    return { ok: false, reason: "missing_checkpoint" };
  }

  const recomputed = createCheckpointPayload({
    tenantId: bundle.tenantId,
    mailboxes: bundle.mailboxes || [],
    dispatches: bundle.dispatches || [],
    receipts: bundle.receipts || [],
    previousCheckpointId: bundle.checkpoint.lineage?.previousCheckpointId || null,
    sourceDeployment: bundle.checkpoint.sourceDeployment || bundle.sourceDeployment || {},
    sourceCheckpoint: {
      checkpointId: bundle.checkpoint.lineage?.sourceCheckpointId || null,
      digest: bundle.checkpoint.lineage?.sourceCheckpointDigest || null,
    },
    createdAt: bundle.checkpoint.createdAt,
  });

  const signatureValid =
    bundle.checkpoint.signature && bundle.checkpoint.signer
      ? verifySignedCheckpoint(bundle.checkpoint)
      : null;

  const digestMatches = recomputed.digest === bundle.checkpoint.digest;
  return {
    ok: digestMatches && signatureValid !== false,
    digestMatches,
    signatureValid,
    recomputedDigest: recomputed.digest,
    checkpointDigest: bundle.checkpoint.digest,
  };
}

function verifyCutoverContinuity({ bundle, bootstrapStatement } = {}) {
  if (!bundle || !bootstrapStatement) {
    return { ok: false, reason: "bundle_and_bootstrap_required" };
  }

  const bundleVerification = verifyExportBundle(bundle);
  if (!bundleVerification.ok) {
    return { ok: false, reason: "invalid_bundle", bundleVerification };
  }

  if (bootstrapStatement.schemaVersion !== "scytale-bootstrap-v1") {
    return { ok: false, reason: "unsupported_bootstrap_schema", bundleVerification };
  }

  const recomputed = createBootstrapStatement({
    bundle,
    destinationDeployment: bootstrapStatement.destinationDeployment || {},
    destinationGenesisRef: bootstrapStatement.destinationGenesisRef || null,
    destinationCheckpointRef: bootstrapStatement.destinationCheckpointRef || null,
    createdAt: bootstrapStatement.createdAt,
  });

  const digestMatches = recomputed.digest === bootstrapStatement.digest;
  const signatureValid =
    bootstrapStatement.signature && bootstrapStatement.signer
      ? verifySignedBootstrapStatement(bootstrapStatement)
      : null;
  const tenantMatches =
    normalizeTenantId(bundle.tenantId) === normalizeTenantId(bootstrapStatement.tenantId);
  const checkpointMatches =
    trimString(bundle.checkpoint?.checkpointId) === trimString(bootstrapStatement.sourceCheckpointId) &&
    trimString(bundle.checkpoint?.digest) === trimString(bootstrapStatement.sourceCheckpointDigest);

  return {
    ok: bundleVerification.ok && digestMatches && tenantMatches && checkpointMatches && signatureValid !== false,
    bundleVerification,
    digestMatches,
    signatureValid,
    tenantMatches,
    checkpointMatches,
    recomputedDigest: recomputed.digest,
    bootstrapDigest: bootstrapStatement.digest,
  };
}

module.exports = {
  canonicalJson,
  sha256Hex,
  normalizeTenantId,
  normalizeMailboxRecord,
  normalizeDispatchRecord,
  normalizeReceiptRecord,
  createCheckpointPayload,
  createSignedCheckpoint,
  verifySignedCheckpoint,
  createExportBundle,
  verifyExportBundle,
  createBootstrapStatement,
  createSignedBootstrapStatement,
  verifySignedBootstrapStatement,
  verifyCutoverContinuity,
};
