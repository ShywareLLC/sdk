import { LedgerInterface } from "./interface.js";

function ensureLedger(name, ledger) {
  if (!ledger) throw new Error(`DualLedgerInterface requires ${name}`);
  for (const method of [
    "submitTwoListWrite",
    "getCount",
    "rescindTwoListWrite",
    "replaceTwoListWrite",
    "commitPeriodClose"
  ]) {
    if (typeof ledger[method] !== "function") {
      throw new Error(`${name} ledger missing ${method}()`);
    }
  }
}

function sameResult(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

export class DualLedgerInterface extends LedgerInterface {
  constructor({
    source,
    target,
    mode = "dual-write",
    readPreference = "target",
    mirrorFailurePolicy = "throw",
    compareReads = false,
    onMirrorError = null,
    onCompare = null
  } = {}) {
    super();
    ensureLedger("source", source);
    ensureLedger("target", target);
    this.source = source;
    this.target = target;
    this.mode = mode;
    this.readPreference = readPreference;
    this.mirrorFailurePolicy = mirrorFailurePolicy;
    this.compareReads = compareReads;
    this.onMirrorError = onMirrorError;
    this.onCompare = onCompare;
  }

  get name() {
    return `dual:${this.source.name || "source"}->${this.target.name || "target"}:${this.mode}`;
  }

  _primary() {
    if (this.mode === "source-only") return this.source;
    if (this.mode === "target-only") return this.target;
    return this.readPreference === "source" ? this.source : this.target;
  }

  _secondary() {
    return this._primary() === this.source ? this.target : this.source;
  }

  async _write(method, args) {
    if (this.mode === "source-only") return this.source[method](...args);
    if (this.mode === "target-only") return this.target[method](...args);

    const primary = this.readPreference === "source" ? this.source : this.target;
    const secondary = primary === this.source ? this.target : this.source;
    const result = await primary[method](...args);
    try {
      await secondary[method](...args);
    } catch (err) {
      if (typeof this.onMirrorError === "function") {
        this.onMirrorError({ method, args, error: err, primary: primary.name, secondary: secondary.name });
      }
      if (this.mirrorFailurePolicy === "throw") throw err;
    }
    return result;
  }

  async _read(method, args) {
    const primary = this._primary();
    const secondary = this._secondary();
    try {
      const result = await primary[method](...args);
      if (this.compareReads && this.mode !== "source-only" && this.mode !== "target-only") {
        try {
          const comparison = await secondary[method](...args);
          const match = sameResult(result, comparison);
          if (typeof this.onCompare === "function") {
            this.onCompare({ method, args, match, primary: primary.name, secondary: secondary.name, result, comparison });
          }
        } catch (err) {
          if (typeof this.onCompare === "function") {
            this.onCompare({ method, args, match: false, primary: primary.name, secondary: secondary.name, error: err });
          }
          if (this.mode !== "read-through") throw err;
        }
      }
      return result;
    } catch (err) {
      if (this.mode === "read-through") {
        return secondary[method](...args);
      }
      throw err;
    }
  }

  async submitTwoListWrite(scopingId, list1, list2) {
    return this._write("submitTwoListWrite", [scopingId, list1, list2]);
  }

  async getCount(scopingId) {
    return this._read("getCount", [scopingId]);
  }

  async rescindTwoListWrite(scopingId, submissionId, identityHash) {
    return this._write("rescindTwoListWrite", [scopingId, submissionId, identityHash]);
  }

  async replaceTwoListWrite(scopingId, oldSubmissionId, newList1, identityHash) {
    return this._write("replaceTwoListWrite", [scopingId, oldSubmissionId, newList1, identityHash]);
  }

  async commitPeriodClose(scopingId, l1MerkleRoot, l2MerkleRoot, attestation) {
    return this._write("commitPeriodClose", [scopingId, l1MerkleRoot, l2MerkleRoot, attestation]);
  }

  async disconnect() {
    await Promise.all([
      this.source.disconnect?.(),
      this.target.disconnect?.()
    ]);
  }
}
