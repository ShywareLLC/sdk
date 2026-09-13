// Test-only fake Algodv2. Docker is unavailable in the environment this
// adapter was built in, so a real Algorand LocalNet could not be started
// to run the adapter end-to-end against genuine consensus. This fake
// stands in for algod's REST surface at exactly the methods
// AlgorandLedgerInterface and algosdk's AtomicTransactionComposer call
// (getTransactionParams, sendRawTransaction, status,
// pendingTransactionInformation, getApplicationBoxByName), and re-derives
// the same box-storage state transitions the real shyware_two_list TEAL
// contract performs (box_create / box_replace / box_delete / box_get /
// box_put over the same "L1"/"L2"/"CN"/"PC" + sha256 key scheme) so the
// four checks (rejection predicate, sybil resistance, replay protection,
// count-match) are actually exercised end-to-end through real algosdk
// transaction building, ABI arg encoding, ABI return decoding, and error
// propagation -- not merely asserted by inspecting JS call arguments.
//
// This is NOT a substitute for running the real TEAL on a real node: it
// is a hand-written oracle of what the contract is *supposed* to do,
// used to verify the JS adapter's wiring against that oracle. See the
// report in the task response for exactly what this does and does not
// prove.

import { createHash } from 'crypto';

const RETURN_PREFIX = Buffer.from([0x15, 0x1f, 0x7c, 0x75]);

function boxName(prefix, ...parts) {
  const digest = createHash('sha256').update(parts.join('|'), 'utf8').digest();
  return Buffer.concat([Buffer.from(prefix, 'ascii'), digest]);
}

export class FakeAlgod {
  constructor({ algosdk, contract }) {
    this._algosdk = algosdk;
    this._contract = contract;
    this._boxes = new Map(); // hex(boxName) -> Buffer
    this._confirmed = new Map(); // txid -> pendingInfo
    this._round = 1n;
  }

  // --- helpers -------------------------------------------------------------

  _boxGet(name) { return this._boxes.get(Buffer.from(name).toString('hex')); }
  _boxSet(name, value) { this._boxes.set(Buffer.from(name).toString('hex'), Buffer.from(value)); }
  _boxDelete(name) {
    const key = Buffer.from(name).toString('hex');
    const existed = this._boxes.has(key);
    this._boxes.delete(key);
    return existed;
  }
  _boxCreate(name, size) {
    const key = Buffer.from(name).toString('hex');
    if (this._boxes.has(key)) return false;
    this._boxes.set(key, Buffer.alloc(size));
    return true;
  }

  _decodeMethodCall(stxnBytes) {
    const { txn } = this._algosdk.decodeSignedTransaction(stxnBytes);
    if (txn.type !== 'appl') return null;
    const appArgs = txn.applicationCall.appArgs || [];
    if (appArgs.length === 0) return null;
    const selector = Buffer.from(appArgs[0]);
    const method = this._contract.methods.find((m) => Buffer.from(m.getSelector()).equals(selector));
    if (!method) return null;
    const args = method.args.map((argSpec, i) => argSpec.type.decode(appArgs[i + 1]));
    return { txn, method, args };
  }

  /** Re-derive the contract's on-chain effect for one decoded method call. */
  _apply(method, args) {
    switch (method.name) {
      case 'submit_two_list_write': {
        const [scopingId, submissionId, payloadCommitment, identityHash] = args;
        if (!scopingId || !submissionId || !payloadCommitment || !identityHash) {
          throw new Error('logic eval error: assert failed (required field)');
        }
        const digestHex = createHash('sha256').update(submissionId, 'utf8').digest('hex');
        if (digestHex === identityHash) {
          throw new Error('logic eval error: assert failed (rejection predicate)');
        }
        const l1 = boxName('L1', scopingId, submissionId);
        const l2 = boxName('L2', scopingId, identityHash);
        const cn = boxName('CN', scopingId);
        if (!this._boxCreate(l2, 1)) throw new Error('logic eval error: assert failed (sybil resistance)');
        this._boxSet(l2, Buffer.from([0x01]));
        if (!this._boxCreate(l1, Buffer.byteLength(payloadCommitment))) {
          throw new Error('logic eval error: assert failed (replay protection)');
        }
        this._boxSet(l1, Buffer.from(payloadCommitment, 'utf8'));
        const prev = this._boxGet(cn);
        const count = (prev ? prev.readBigUInt64BE(0) : 0n) + 1n;
        const buf = Buffer.alloc(8); buf.writeBigUInt64BE(count); this._boxSet(cn, buf);
        return [count, count, true];
      }
      case 'get_count': {
        const [scopingId] = args;
        const cn = boxName('CN', scopingId);
        const prev = this._boxGet(cn);
        const count = prev ? prev.readBigUInt64BE(0) : 0n;
        return [count, count, true];
      }
      case 'rescind_two_list_write': {
        const [scopingId, submissionId, identityHash] = args;
        const l1 = boxName('L1', scopingId, submissionId);
        const l2 = boxName('L2', scopingId, identityHash);
        const cn = boxName('CN', scopingId);
        if (!this._boxDelete(l1)) throw new Error('logic eval error: assert failed (no such L1 box)');
        if (!this._boxDelete(l2)) throw new Error('logic eval error: assert failed (no such L2 box)');
        const prev = this._boxGet(cn);
        if (!prev) throw new Error('logic eval error: assert failed (no count box)');
        const count = prev.readBigUInt64BE(0) - 1n;
        const buf = Buffer.alloc(8); buf.writeBigUInt64BE(count); this._boxSet(cn, buf);
        return [true, true];
      }
      case 'replace_two_list_write': {
        const [scopingId, oldSubmissionId, newSubmissionId, newPayloadCommitment, identityHash] = args;
        const digestHex = createHash('sha256').update(newSubmissionId, 'utf8').digest('hex');
        if (digestHex === identityHash) throw new Error('logic eval error: assert failed (rejection predicate)');
        const l2 = boxName('L2', scopingId, identityHash);
        if (!this._boxGet(l2)) throw new Error('logic eval error: assert failed (not a registered participant)');
        const oldL1 = boxName('L1', scopingId, oldSubmissionId);
        const newL1 = boxName('L1', scopingId, newSubmissionId);
        if (!this._boxDelete(oldL1)) throw new Error('logic eval error: assert failed (no such old L1 box)');
        if (!this._boxCreate(newL1, Buffer.byteLength(newPayloadCommitment))) {
          throw new Error('logic eval error: assert failed (new submissionId already used)');
        }
        this._boxSet(newL1, Buffer.from(newPayloadCommitment, 'utf8'));
        return [true, true];
      }
      case 'commit_period_close': {
        const [scopingId, l1Root, l2Root, attestation] = args;
        const pc = boxName('PC', scopingId);
        const value = Buffer.concat([Buffer.from(l1Root, 'utf8'), Buffer.from(l2Root, 'utf8'), Buffer.from(attestation, 'utf8')]);
        if (!this._boxCreate(pc, value.length)) throw new Error('logic eval error: assert failed (already closed)');
        this._boxSet(pc, value);
        return [true, BigInt(Math.floor(Date.now() / 1000))];
      }
      default:
        throw new Error(`unknown method ${method.name}`);
    }
  }

  // --- algod REST surface ---------------------------------------------------

  getTransactionParams() {
    return { do: async () => ({
      fee: 1000n, minFee: 1000n, flatFee: true,
      firstValid: this._round, lastValid: this._round + 1000n,
      genesisID: 'fake-v1', genesisHash: new Uint8Array(32),
    }) };
  }

  sendRawTransaction(stxnsOrOne) {
    const stxns = Array.isArray(stxnsOrOne) ? stxnsOrOne : [stxnsOrOne];
    return { do: async () => {
      let appCall = null;
      for (const stxn of stxns) {
        const decoded = this._decodeMethodCall(stxn);
        if (decoded) appCall = decoded;
      }
      if (!appCall) throw new Error('fake algod: no method-call transaction found in group');

      const returnValues = this._apply(appCall.method, appCall.args); // throws on rejection, exactly as a real node rejects a failing app call at broadcast

      const returnBytes = appCall.method.returns.type.encode(returnValues);
      const log = Buffer.concat([RETURN_PREFIX, Buffer.from(returnBytes)]);
      const txid = appCall.txn.txID();
      this._round += 1n;
      this._confirmed.set(txid, { confirmedRound: this._round, logs: [log] });
      return { txId: txid };
    } };
  }

  status() {
    return { do: async () => ({ lastRound: this._round }) };
  }

  statusAfterBlock(_round) {
    return { do: async () => ({ lastRound: this._round }) };
  }

  pendingTransactionInformation(txid) {
    return { do: async () => {
      const info = this._confirmed.get(txid);
      if (!info) throw new Error('fake algod: transaction not found (404)');
      return info;
    } };
  }

  getApplicationBoxByName(_appId, name) {
    return { do: async () => {
      const value = this._boxGet(name);
      if (!value) { const err = new Error('box not found'); err.status = 404; throw err; }
      return { name, value: new Uint8Array(value) };
    } };
  }
}
