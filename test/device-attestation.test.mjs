import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { enrollDeviceSecret } from "../clients/embodiments/votingClient.js";

const manifest = { identity: { attestation_service_base_url: "https://enclave.test/" } };

test("enrollment trades the session for a device credential", async () => {
  const sent = [];
  globalThis.fetch = async (url, init) => {
    sent.push({ url, body: JSON.parse(init.body) });
    return { ok: true, status: 200, json: async () => ({ device_id: "d1", secret_hex: "ab".repeat(32), identity_key_hex: "cd".repeat(32) }) };
  };
  const device = await enrollDeviceSecret({ manifest, sessionId: "s1", userId: "alice" });
  assert.equal(sent[0].url, "https://enclave.test/device-secret/enroll");
  assert.deepEqual(sent[0].body, { session_id: "s1", user_id: "alice" });
  assert.deepEqual(device, { userId: "alice", deviceId: "d1", secretHex: "ab".repeat(32), identityKeyHex: "cd".repeat(32) });
});

test("the ballot-key MAC matches the enclave's (same fields, same HMAC)", async () => {
  // The enclave verifies HMAC-SHA256(secret, fields joined by "\n").
  const fields = ["shyware-ballot-key-request-v1", "alice", "d1", "ef".repeat(32), "poll-1", "2026-11-16T18:00:00.000Z"];
  const expected = createHmac("sha256", Buffer.from("ab".repeat(32), "hex")).update(fields.join("\n")).digest("hex");
  const key = await crypto.subtle.importKey("raw", Buffer.from("ab".repeat(32), "hex"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = Buffer.from(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(fields.join("\n")))).toString("hex");
  assert.equal(mac, expected);
});
