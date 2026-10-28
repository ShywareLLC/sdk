import test from "node:test";
import assert from "node:assert/strict";
import { createVoterRevealAuthority, validateVoterRevealPolicy } from "../protocol/voterReveal.js";
import { sealPayload, openPayload } from "../protocol/sealer.js";

function fixture() {
  const polls = new Map(), entries = new Map();
  const store = {
    async configurePoll(id, policy) {
      if (polls.has(id) && JSON.stringify(polls.get(id).policy) !== JSON.stringify(policy)) throw Error("immutable");
      if (!polls.has(id)) polls.set(id, { policy, revealed: false });
    },
    async getPoll(id) { return polls.get(id); },
    async putIdentity(id, token, owner, sealed) {
      const key = `${id}:${token}`;
      if (entries.has(key) && entries.get(key).owner !== owner) throw Error("owner mismatch");
      entries.set(key, { id, owner, sealed });
    },
    async listIdentities(id) { return [...entries.values()].filter(row => row.id === id).map(row => row.sealed); },
    async markRevealed(id) { polls.get(id).revealed = true; },
    async deleteOwner(owner) { for (const [key, row] of entries) if (row.owner === owner) entries.delete(key); }
  };
  const active = new Set();
  const options = { store, deriveSealerKey: async () => new Uint8Array(32).fill(7),
    getParticipationSnapshot: async (_, ids) => ({ count: active.size, active: ids.map(id => active.has(id)) }) };
  const authority = createVoterRevealAuthority(options);
  const alice = "a".repeat(64), bob = "b".repeat(64);
  return { authority, options, store, polls, entries, active, alice, bob };
}

test("reuses shystore AES-GCM envelopes for identity attributes", async () => {
  const key = async () => new Uint8Array(32).fill(4);
  const sealed = await sealPayload({ publicIdentity: "Alice" }, key);
  assert.deepEqual(await openPayload(sealed, key), { publicIdentity: "Alice" });
  await assert.rejects(openPayload({ ...sealed, alg: "other" }, key));
  await assert.rejects(openPayload(sealed, async () => new Uint8Array(32).fill(5)));
});

test("off by default; validates explicit configurable thresholds", async () => {
  assert.deepEqual(validateVoterRevealPolicy(null), { enabled: false });
  for (const threshold of [0, -1, 1.5, "100", Infinity]) assert.throws(() => validateVoterRevealPolicy({ enabled: true, threshold }));
  assert.equal(validateVoterRevealPolicy({ enabled: true, threshold: 1 }).threshold, 1);
  const f = fixture();
  assert.deepEqual(await f.authority.inspect("poll"), { enabled: false, identities: [] });
  await assert.rejects(f.authority.register({ pollId: "poll" }));
});

test("seals names until canonical active count crosses threshold; no ballot or choice returned", async () => {
  const f = fixture();
  await f.authority.configure("poll", { enabled: true, threshold: 2 });
  f.active.add(f.alice);
  await f.authority.register({ pollId: "poll", participantId: f.alice, ownerId: "account-a", publicIdentity: "Alice" });
  assert.equal(JSON.stringify([...f.entries.values()]).includes("Alice"), false);
  assert.equal(JSON.stringify([...f.entries.values()]).includes(f.alice), false);
  assert.deepEqual((await f.authority.inspect("poll")).identities, []);
  f.active.add(f.bob);
  await f.authority.register({ pollId: "poll", participantId: f.bob, ownerId: "account-b", publicIdentity: "Bob" });
  const revealed = await f.authority.inspect("poll");
  assert.deepEqual(revealed.identities, ["Alice", "Bob"]);
  assert.equal(revealed.participantCount, 2);
  assert.equal(revealed.ledgerProofVerified, false);
  assert.equal(JSON.stringify(revealed).includes(f.alice), false);
  assert.equal(JSON.stringify(revealed).includes("ballot"), false);
});

test("replacements do not inflate participation; release survives restart and withdrawal", async () => {
  const f = fixture();
  await f.authority.configure("poll", { enabled: true, threshold: 2 });
  f.active.add(f.alice);
  const input = { pollId: "poll", participantId: f.alice, ownerId: "account-a", publicIdentity: "Alice" };
  await f.authority.register(input); await f.authority.register(input);
  assert.equal(f.entries.size, 1);
  assert.equal((await f.authority.inspect("poll")).revealed, false);
  f.active.add(f.bob);
  await f.authority.inspect("poll");
  f.active.delete(f.bob);
  const restarted = createVoterRevealAuthority(f.options);
  assert.equal((await restarted.inspect("poll")).revealed, true);
  f.active.delete(f.alice);
  assert.deepEqual((await restarted.inspect("poll")).identities, []);
});

test("rejects fabricated participation, owner substitution, policy changes and cross-poll envelope copying", async () => {
  const f = fixture();
  await f.authority.configure("one", { enabled: true, threshold: 2 });
  await f.authority.configure("two", { enabled: true, threshold: 2 });
  const input = { pollId: "one", participantId: f.alice, ownerId: "account-a", publicIdentity: "Alice" };
  await assert.rejects(f.authority.register(input));
  f.active.add(f.alice); await f.authority.register(input);
  await assert.rejects(f.authority.register({ ...input, ownerId: "attacker" }));
  await assert.rejects(f.authority.configure("one", { enabled: true, threshold: 3 }));
  f.entries.set("copy", { ...[...f.entries.values()][0], id: "two" });
  await assert.rejects(f.authority.inspect("two"));
});

test("deletion removes account-linked sealed identities and invalid snapshot fails closed", async () => {
  const f = fixture();
  await f.authority.configure("poll", { enabled: true, threshold: 2 });
  f.active.add(f.alice);
  await f.authority.register({ pollId: "poll", participantId: f.alice, ownerId: "account-a", publicIdentity: "Alice" });
  await f.authority.deleteOwner("account-a");
  assert.equal(f.entries.size, 0);
  const broken = createVoterRevealAuthority({ ...f.options, getParticipationSnapshot: async () => ({ count: 100, active: [true] }) });
  await assert.rejects(broken.inspect("poll"));
  assert.equal(f.polls.get("poll").revealed, false);
});
