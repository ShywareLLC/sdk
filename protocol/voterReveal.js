import { sealPayload, openPayload } from "./sealer.js";

export function validateVoterRevealPolicy(policy) {
  if (policy == null || policy.enabled === false) return { enabled: false };
  if (policy.enabled !== true || !Number.isSafeInteger(policy.threshold) || policy.threshold < 1) {
    throw new Error("Voter reveal requires an enabled policy with a positive integer threshold");
  }
  return { enabled: true, threshold: policy.threshold };
}

// Authority-side utility: neither keys nor the registry belong in the consumer app.
// The snapshot callback must check current canonical membership, not receipt mirrors.
export function createVoterRevealAuthority({ store, deriveSealerKey, getParticipationSnapshot }) {
  if (!store || typeof deriveSealerKey !== "function" || typeof getParticipationSnapshot !== "function") {
    throw new Error("Voter reveal requires a persistent store, authority key and canonical snapshot reader");
  }
  function scope(pollId) {
    if (typeof pollId !== "string" || !pollId || pollId.length > 256) throw new Error("Invalid poll ID");
    return pollId;
  }
  async function token(domain, value) {
    const key = await globalThis.crypto.subtle.importKey("raw", await deriveSealerKey(),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const digest = await globalThis.crypto.subtle.sign("HMAC", key,
      new TextEncoder().encode(JSON.stringify([domain, ...value])));
    return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
  }
  async function pollKey(pollId) {
    // A domain-separated key prevents copying an envelope into a different poll.
    const material = await token("shyvoting-voter-reveal-key-v1", [pollId]);
    return new TextEncoder().encode(material);
  }
  async function load(pollId) {
    const state = await store.getPoll(scope(pollId));
    if (!state) return null;
    return { ...state, policy: validateVoterRevealPolicy(state.policy) };
  }
  async function snapshot(pollId, identities) {
    const result = await getParticipationSnapshot(pollId, identities);
    if (!Number.isSafeInteger(result?.count) || result.count < 0 ||
        !Array.isArray(result.active) || result.active.length !== identities.length ||
        !result.active.every(value => typeof value === "boolean") ||
        result.active.filter(Boolean).length > result.count) {
      throw new Error("Invalid canonical participation snapshot");
    }
    return result;
  }
  return {
    async configure(pollId, policy) {
      const validated = validateVoterRevealPolicy(policy);
      // The store must reject policy changes for an already configured poll.
      await store.configurePoll(scope(pollId), validated);
    },
    async register({ pollId, participantId, ownerId, publicIdentity }) {
      const state = await load(pollId);
      if (!state?.policy.enabled) throw new Error("Voter reveal is disabled for this poll");
      if (!/^[a-f0-9]{64}$/.test(participantId) || typeof ownerId !== "string" || !ownerId ||
          typeof publicIdentity !== "string" || !publicIdentity.trim() || publicIdentity.length > 200) {
        throw new Error("Invalid voter reveal registration");
      }
      // participantId and publicIdentity must come from an authenticated authority,
      // not unchecked caller fields. No ballot identifier or choice is accepted.
      const current = await snapshot(pollId, [participantId]);
      if (!current.active[0]) throw new Error("Participant has no active canonical vote");
      const sealed = await sealPayload({ version: 1, pollId, participantId,
        publicIdentity: publicIdentity.trim() }, () => pollKey(pollId));
      await store.putIdentity(pollId,
        await token("shyvoting-voter-reveal-participant-v1", [pollId, participantId]),
        await token("shyvoting-voter-reveal-owner-v1", [ownerId]), sealed);
    },
    async inspect(pollId) {
      const state = await load(pollId);
      if (!state?.policy.enabled) return { enabled: false, identities: [] };
      const envelopes = await store.listIdentities(pollId);
      const records = await Promise.all(envelopes.map(envelope => openPayload(envelope, () => pollKey(pollId))));
      if (records.some(record => record.version !== 1 || record.pollId !== pollId ||
          !/^[a-f0-9]{64}$/.test(record.participantId) || typeof record.publicIdentity !== "string")) {
        throw new Error("Invalid voter reveal record");
      }
      const current = await snapshot(pollId, records.map(record => record.participantId));
      let revealed = state.revealed === true;
      if (!revealed && current.count >= state.policy.threshold) {
        await store.markRevealed(pollId);
        revealed = true;
      }
      const identities = revealed ? records.filter((_, index) => current.active[index])
        .map(record => record.publicIdentity).sort() : [];
      return { enabled: true, threshold: state.policy.threshold, revealed,
        participantCount: current.count, publishedIdentityCount: identities.length,
        identities, source: "provider", ledgerProofVerified: false };
    },
    async deleteOwner(ownerId) {
      await store.deleteOwner(await token("shyvoting-voter-reveal-owner-v1", [ownerId]));
    }
  };
}
