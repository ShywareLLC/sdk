import test from "node:test";
import assert from "node:assert/strict";
import {
  MigrationGuardrailError,
  UNINITIALIZED_VERSION,
  createMemoryMigrationStateStore,
  createMigrationRegistry,
  runMigrations
} from "../adapters/migration/index.js";
import { DualLedgerInterface } from "../adapters/ledger/dual.js";

test("plans skipped-version migrations stepwise", () => {
  const registry = createMigrationRegistry({
    component: "ledger",
    migrations: [
      { id: "init", fromVersion: UNINITIALIZED_VERSION, toVersion: "v1", up: async () => {} },
      { id: "v1-v2", fromVersion: "v1", toVersion: "v2", up: async () => {} },
      { id: "v2-v3", fromVersion: "v2", toVersion: "v3", up: async () => {} },
      { id: "v3-v4", fromVersion: "v3", toVersion: "v4", up: async () => {} }
    ]
  });

  const plan = registry.plan({ fromVersion: "v1", toVersion: "v4" });
  assert.deepEqual(plan.steps.map(step => step.id), ["v1-v2", "v2-v3", "v3-v4"]);
});

test("records migration state while applying intermediate steps", async () => {
  const applied = [];
  const registry = createMigrationRegistry({
    component: "cockroach-store",
    migrations: [
      { id: "v1-v2", fromVersion: "v1", toVersion: "v2", up: async () => applied.push("v1-v2") },
      { id: "v2-v4", fromVersion: "v2", toVersion: "v4", up: async () => applied.push("v2-v4") }
    ]
  });
  const store = createMemoryMigrationStateStore({
    "cockroach-store": { version: "v1", status: "ready" }
  });

  const summary = await runMigrations({
    registry,
    store,
    targetVersion: "v4",
    sdkVersion: "0.6.0",
    stack: "native-fabric"
  });

  assert.deepEqual(applied, ["v1-v2", "v2-v4"]);
  assert.deepEqual(summary.applied.map(step => step.id), ["v1-v2", "v2-v4"]);
  const state = await store.getComponentState("cockroach-store");
  assert.equal(state.version, "v4");
  const history = await store.listMigrationSteps("cockroach-store");
  assert.equal(history.length, 2);
});

test("blocks manual migrations unless explicitly approved", async () => {
  const registry = createMigrationRegistry({
    component: "fabric-ledger",
    migrations: [
      {
        id: "ledger-cutover",
        fromVersion: "community",
        toVersion: "operator",
        type: "dual-ledger",
        canAutoRun: false,
        up: async () => {}
      }
    ]
  });

  await assert.rejects(
    () => runMigrations({
      registry,
      currentVersion: "community",
      targetVersion: "operator"
    }),
    err => err instanceof MigrationGuardrailError &&
      err.code === "MIGRATION_MANUAL_APPROVAL_REQUIRED"
  );
});

function makeLedger(name, count = { l1Count: 1, l2Count: 1, countMatch: true }) {
  const calls = [];
  return {
    name,
    calls,
    async submitTwoListWrite(...args) {
      calls.push(["submitTwoListWrite", ...args]);
      return { txId: `${name}-tx`, l1Count: 1, l2Count: 1, countMatch: true };
    },
    async getCount(...args) {
      calls.push(["getCount", ...args]);
      return count;
    },
    async rescindTwoListWrite(...args) {
      calls.push(["rescindTwoListWrite", ...args]);
      return { countMatch: true, rescinded: true };
    },
    async replaceTwoListWrite(...args) {
      calls.push(["replaceTwoListWrite", ...args]);
      return { countMatch: true, replaced: true, newSubmissionId: args[2]?.submissionId };
    },
    async commitPeriodClose(...args) {
      calls.push(["commitPeriodClose", ...args]);
      return { txId: `${name}-close`, timestamp: "2026-06-16T00:00:00.000Z" };
    },
    async disconnect() {}
  };
}

test("dual ledger adapter mirrors writes and can compare reads", async () => {
  const comparisons = [];
  const source = makeLedger("community");
  const target = makeLedger("operator");
  const ledger = new DualLedgerInterface({
    source,
    target,
    readPreference: "source",
    compareReads: true,
    onCompare: entry => comparisons.push(entry)
  });

  const result = await ledger.submitTwoListWrite("scope", { submissionId: "s1" }, { identityHash: "h1" });
  assert.equal(result.txId, "community-tx");
  assert.equal(source.calls.filter(call => call[0] === "submitTwoListWrite").length, 1);
  assert.equal(target.calls.filter(call => call[0] === "submitTwoListWrite").length, 1);

  await ledger.getCount("scope");
  assert.equal(comparisons.length, 1);
  assert.equal(comparisons[0].match, true);
});
