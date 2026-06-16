const UNINITIALIZED_VERSION = "uninitialized";

class MigrationPlanError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "MigrationPlanError";
    this.code = details.code || "MIGRATION_PLAN_ERROR";
    this.details = details;
  }
}

class MigrationGuardrailError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "MigrationGuardrailError";
    this.code = details.code || "MIGRATION_GUARDRAIL";
    this.details = details;
  }
}

function normalizeVersion(version) {
  if (version === null || version === undefined || version === "") {
    return UNINITIALIZED_VERSION;
  }
  return String(version);
}

function normalizeStacks(stacks) {
  if (!stacks) return null;
  const list = Array.isArray(stacks) ? stacks : [stacks];
  return new Set(list.map(String));
}

function supportsStack(migration, stack) {
  if (!stack || !migration.stacks) return true;
  return migration.stacks.has(String(stack));
}

function clonePublicMigration(migration) {
  return {
    id: migration.id,
    component: migration.component,
    fromVersion: migration.fromVersion,
    toVersion: migration.toVersion,
    type: migration.type,
    description: migration.description,
    canAutoRun: migration.canAutoRun,
    requiresBackup: migration.requiresBackup,
    destructive: migration.destructive,
    stacks: migration.stacks ? Array.from(migration.stacks) : null,
    metadata: migration.metadata || {}
  };
}

function normalizeMigration(input, component) {
  if (!input || typeof input !== "object") {
    throw new MigrationPlanError("Migration must be an object", {
      code: "MIGRATION_INVALID"
    });
  }
  const migration = {
    id: input.id,
    component: input.component || component,
    fromVersion: normalizeVersion(input.fromVersion),
    toVersion: normalizeVersion(input.toVersion),
    type: input.type || "additive",
    description: input.description || "",
    canAutoRun: input.canAutoRun !== false,
    requiresBackup: input.requiresBackup === true,
    destructive: input.destructive === true,
    stacks: normalizeStacks(input.stacks),
    metadata: input.metadata || {},
    up: input.up,
    validate: input.validate,
    rollback: input.rollback
  };
  if (!migration.id) {
    throw new MigrationPlanError("Migration id is required", {
      code: "MIGRATION_ID_REQUIRED"
    });
  }
  if (!migration.component) {
    throw new MigrationPlanError(`Migration ${migration.id} missing component`, {
      code: "MIGRATION_COMPONENT_REQUIRED",
      migrationId: migration.id
    });
  }
  if (migration.fromVersion === migration.toVersion) {
    throw new MigrationPlanError(`Migration ${migration.id} has identical from/to versions`, {
      code: "MIGRATION_NOOP_EDGE",
      migrationId: migration.id
    });
  }
  return migration;
}

function createMigrationRegistry({ component, migrations = [] } = {}) {
  const records = [];
  const byId = new Map();

  function register(input) {
    const migration = normalizeMigration(input, component);
    if (byId.has(migration.id)) {
      throw new MigrationPlanError(`Duplicate migration id: ${migration.id}`, {
        code: "MIGRATION_DUPLICATE_ID",
        migrationId: migration.id
      });
    }
    byId.set(migration.id, migration);
    records.push(migration);
    return migration;
  }

  function list({ component: scopedComponent = component, stack } = {}) {
    return records
      .filter(m => !scopedComponent || m.component === scopedComponent)
      .filter(m => supportsStack(m, stack))
      .map(clonePublicMigration);
  }

  function plan({
    fromVersion,
    toVersion,
    component: scopedComponent = component,
    stack
  } = {}) {
    const from = normalizeVersion(fromVersion);
    const target = normalizeVersion(toVersion);
    if (!target || target === UNINITIALIZED_VERSION) {
      throw new MigrationPlanError("Target version is required", {
        code: "MIGRATION_TARGET_REQUIRED",
        fromVersion: from
      });
    }
    if (from === target) {
      return {
        component: scopedComponent,
        fromVersion: from,
        toVersion: target,
        steps: []
      };
    }

    const candidates = records
      .filter(m => !scopedComponent || m.component === scopedComponent)
      .filter(m => supportsStack(m, stack));
    const queue = [{ version: from, path: [] }];
    const visited = new Set([from]);

    while (queue.length) {
      const current = queue.shift();
      for (const migration of candidates) {
        if (migration.fromVersion !== current.version) continue;
        if (visited.has(migration.toVersion)) continue;
        const nextPath = current.path.concat(migration);
        if (migration.toVersion === target) {
          return {
            component: scopedComponent,
            fromVersion: from,
            toVersion: target,
            steps: nextPath.map(clonePublicMigration),
            _steps: nextPath
          };
        }
        visited.add(migration.toVersion);
        queue.push({ version: migration.toVersion, path: nextPath });
      }
    }

    throw new MigrationPlanError(
      `No migration path for ${scopedComponent || "component"} ${from} -> ${target}`,
      {
        code: "MIGRATION_PATH_MISSING",
        component: scopedComponent,
        fromVersion: from,
        toVersion: target,
        available: candidates.map(clonePublicMigration)
      }
    );
  }

  for (const migration of migrations) register(migration);

  return {
    component,
    register,
    list,
    plan,
    get(id) {
      return byId.get(id) || null;
    }
  };
}

function assertStepAllowed(step, options) {
  if (step.destructive && !options.allowDestructive) {
    throw new MigrationGuardrailError(`Migration ${step.id} is destructive`, {
      code: "MIGRATION_DESTRUCTIVE_BLOCKED",
      migrationId: step.id
    });
  }
  if (step.requiresBackup && !options.backupVerified && !options.allowWithoutBackup) {
    throw new MigrationGuardrailError(`Migration ${step.id} requires a verified backup/checkpoint`, {
      code: "MIGRATION_BACKUP_REQUIRED",
      migrationId: step.id
    });
  }
  if (step.canAutoRun === false && !options.allowManual) {
    throw new MigrationGuardrailError(`Migration ${step.id} requires explicit operator approval`, {
      code: "MIGRATION_MANUAL_APPROVAL_REQUIRED",
      migrationId: step.id
    });
  }
}

async function runMigrations({
  registry,
  store,
  component,
  targetVersion,
  currentVersion,
  sdkVersion,
  stack,
  context = {},
  dryRun = false,
  allowManual = false,
  allowDestructive = false,
  allowWithoutBackup = false,
  backupVerified = false,
  ledgerRole = "unspecified",
  sourceLedger = null,
  targetLedger = null
} = {}) {
  if (!registry) {
    throw new MigrationPlanError("Migration registry is required", {
      code: "MIGRATION_REGISTRY_REQUIRED"
    });
  }
  const resolvedComponent = component || registry.component;
  const state = currentVersion === undefined && store?.getComponentState
    ? await store.getComponentState(resolvedComponent)
    : null;
  const fromVersion = normalizeVersion(currentVersion ?? state?.version);
  const planned = registry.plan({
    component: resolvedComponent,
    fromVersion,
    toVersion: targetVersion,
    stack
  });
  const internalSteps = planned._steps || planned.steps.map(step => registry.get(step.id));
  for (const step of internalSteps) {
    assertStepAllowed(step, { allowManual, allowDestructive, allowWithoutBackup, backupVerified });
  }

  const summary = {
    component: resolvedComponent,
    fromVersion,
    toVersion: normalizeVersion(targetVersion),
    sdkVersion: sdkVersion || null,
    stack: stack || null,
    ledgerRole,
    sourceLedger,
    targetLedger,
    dryRun,
    steps: internalSteps.map(clonePublicMigration),
    applied: []
  };
  if (dryRun || internalSteps.length === 0) return summary;

  let version = fromVersion;
  for (const step of internalSteps) {
    if (typeof step.up !== "function") {
      throw new MigrationGuardrailError(`Migration ${step.id} has no executable up() function`, {
        code: "MIGRATION_UP_MISSING",
        migrationId: step.id
      });
    }
    await step.up({
      ...context,
      component: resolvedComponent,
      migration: clonePublicMigration(step),
      fromVersion: version,
      toVersion: step.toVersion,
      store
    });
    if (typeof step.validate === "function") {
      await step.validate({
        ...context,
        component: resolvedComponent,
        migration: clonePublicMigration(step),
        fromVersion: version,
        toVersion: step.toVersion,
        store
      });
    }
    if (store?.recordMigrationStep) {
      await store.recordMigrationStep({
        component: resolvedComponent,
        migrationId: step.id,
        fromVersion: version,
        toVersion: step.toVersion,
        sdkVersion: sdkVersion || null,
        type: step.type,
        status: "applied",
        metadata: step.metadata || {}
      });
    }
    version = step.toVersion;
    if (store?.setComponentState) {
      await store.setComponentState({
        component: resolvedComponent,
        version,
        sdkVersion: sdkVersion || null,
        status: "ready",
        stack: stack || null,
        ledgerRole,
        sourceLedger,
        targetLedger,
        metadata: {}
      });
    }
    summary.applied.push(clonePublicMigration(step));
  }
  return summary;
}

function createMemoryMigrationStateStore(initial = {}) {
  const states = new Map();
  const steps = [];
  for (const [component, state] of Object.entries(initial)) {
    states.set(component, { component, ...state });
  }
  return {
    async getComponentState(component) {
      return states.get(component) || null;
    },
    async setComponentState(state) {
      states.set(state.component, { ...state, updatedAt: new Date().toISOString() });
    },
    async recordMigrationStep(step) {
      steps.push({ ...step, appliedAt: new Date().toISOString() });
    },
    async listMigrationSteps(component) {
      return steps.filter(step => step.component === component);
    },
    _debug() {
      return { states, steps };
    }
  };
}

function buildMigrationStatus({
  component,
  state = null,
  plan = null,
  blockers = [],
  ledgers = []
} = {}) {
  return {
    component,
    currentVersion: normalizeVersion(state?.version),
    targetVersion: plan?.toVersion || null,
    status: blockers.length ? "blocked" : (plan?.steps?.length ? "pending" : "ready"),
    blockers,
    ledgers,
    pendingSteps: plan?.steps || [],
    updatedAt: state?.updatedAt || null
  };
}

module.exports = {
  UNINITIALIZED_VERSION,
  MigrationPlanError,
  MigrationGuardrailError,
  normalizeVersion,
  createMigrationRegistry,
  runMigrations,
  createMemoryMigrationStateStore,
  buildMigrationStatus
};
