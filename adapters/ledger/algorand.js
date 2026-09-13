// AlgorandLedgerInterface — chain-enforced two-list-invariant adapter.
//
// This adapter is a thin client over a real Algorand smart contract
// (adapters/ledger/algorand/contracts/shyware_two_list.py, compiled to
// adapters/ledger/algorand/contracts/shyware_two_list_approval.teal). The
// four checks (rejection predicate, sybil resistance, replay protection,
// count-match) run inside the AVM on every validating node when the
// contract's box_create / Assert opcodes execute — not in this file. A
// bug or a malicious edit here can, at worst, submit a transaction the
// chain then rejects; it cannot forge a state the chain didn't validate.
// This is the same contract every other LedgerInterface adapter in this
// SDK (fabric.js, cockroach.js) is built to, so this file is a drop-in
// swap for any consumer already coded against LedgerInterface.
//
// Peer dependency (optional, loaded lazily so it need not be installed
// unless this adapter is actually used):
//   algosdk  — npm install algosdk
//
// Required env vars (or pass overrides directly to the constructor):
//   ALGORAND_NODE_URL          — algod REST endpoint (e.g. http://localhost:4001)
//   ALGORAND_NODE_TOKEN        — algod API token ('' for a token-less LocalNet)
//   ALGORAND_APP_ID            — deployed shyware_two_list application id
//   ALGORAND_ACCOUNT_MNEMONIC  — 25-word mnemonic for the submitting account
//
// Constructor overrides (bypass the env vars / mnemonic derivation entirely —
// useful for tests and for callers that already hold an algosdk.Algodv2 or a
// derived {addr, sk} account):
//   { algodClient, account, appId, boxFundingMicroAlgos, tracer }
//
// Box-key scheme (must match shyware_two_list.py's box_key() exactly):
//   L1  "L1" + sha256(scopingId + "|" + submissionId)  -> payloadCommitment
//   L2  "L2" + sha256(scopingId + "|" + identityHash)  -> 1-byte marker
//   CN  "CN" + sha256(scopingId)                        -> 8-byte uint64 count
//   PC  "PC" + sha256(scopingId)                         -> l1Root||l2Root||attestation

import { createHash } from 'crypto';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { LedgerInterface } from './interface.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ABI_SPEC_PATH = join(__dirname, 'algorand', 'contracts', 'shyware_two_list.arc4.json');

// Box MBR (minimum balance requirement) is 2_500 microAlgo per box plus
// 400 microAlgo per byte of (name + value). This is a generous flat
// funding amount per app call that creates boxes, covering L1 + L2 (+ CN
// on first use) with margin; unspent funding simply raises the app
// account's spendable balance for future box creations, it is not lost.
const DEFAULT_BOX_FUNDING_MICROALGOS = 200_000;

export class AlgorandLedgerInterface extends LedgerInterface {
  constructor({
    nodeUrl              = process.env.ALGORAND_NODE_URL   || 'http://localhost:4001',
    nodeToken             = process.env.ALGORAND_NODE_TOKEN ?? '',
    nodePort              = process.env.ALGORAND_NODE_PORT,
    appId                 = process.env.ALGORAND_APP_ID ? Number(process.env.ALGORAND_APP_ID) : undefined,
    mnemonic              = process.env.ALGORAND_ACCOUNT_MNEMONIC,
    algodClient           = null,   // override: pre-built algosdk.Algodv2
    account               = null,   // override: pre-derived { addr, sk }
    boxFundingMicroAlgos  = DEFAULT_BOX_FUNDING_MICROALGOS,
    waitRounds            = 6,
    tracer                = null,
  } = {}) {
    super();
    if (!appId) throw new Error('ALGORAND_APP_ID is required (deployed shyware_two_list application id)');
    if (!account && !mnemonic) throw new Error('ALGORAND_ACCOUNT_MNEMONIC is required (or pass an `account` override)');

    this._cfg = { nodeUrl, nodeToken, nodePort, appId, mnemonic, boxFundingMicroAlgos, waitRounds };
    this._tracer = tracer;
    this._algosdkMod = null;
    this._algod = algodClient;
    this._account = account;
    this._contractSpec = null;
    this._appAddress = null;
  }

  get name() { return 'algorand'; }

  // --- lazy loading -------------------------------------------------------
  // algosdk is an optional peer dependency: it is only imported the first
  // time this adapter actually needs to talk to a node, so consumers that
  // never construct AlgorandLedgerInterface never need it installed.

  async _sdk() {
    if (!this._algosdkMod) this._algosdkMod = await import('algosdk');
    return this._algosdkMod.default ?? this._algosdkMod;
  }

  async _client() {
    if (this._algod) return this._algod;
    const algosdk = await this._sdk();
    const { nodeUrl, nodeToken, nodePort } = this._cfg;
    this._algod = nodePort
      ? new algosdk.Algodv2(nodeToken, nodeUrl, nodePort)
      : new algosdk.Algodv2(nodeToken, nodeUrl, '');
    return this._algod;
  }

  async _getAccount() {
    if (this._account) return this._account;
    const algosdk = await this._sdk();
    this._account = algosdk.mnemonicToSecretKey(this._cfg.mnemonic);
    return this._account;
  }

  async _getAppAddress() {
    if (this._appAddress) return this._appAddress;
    const algosdk = await this._sdk();
    this._appAddress = algosdk.getApplicationAddress(this._cfg.appId);
    return this._appAddress;
  }

  _getContractSpec() {
    if (!this._contractSpec) {
      this._contractSpec = JSON.parse(readFileSync(ABI_SPEC_PATH, 'utf8'));
    }
    return this._contractSpec;
  }

  async _getContract() {
    const algosdk = await this._sdk();
    return new algosdk.ABIContract(this._getContractSpec());
  }

  async _traced(name, annotations, fn) {
    if (this._tracer) return this._tracer.trace(name, annotations, fn);
    return fn();
  }

  // --- box-key derivation (must match shyware_two_list.py's box_key) -----

  static _boxName(prefix, ...parts) {
    const digest = createHash('sha256').update(parts.join('|'), 'utf8').digest();
    // Uint8Array.from(...) rather than a bare Buffer: algosdk's runtime
    // type checks use `instanceof Uint8Array`, which can fail across
    // realms (e.g. a test environment with its own TypedArray globals)
    // even though Buffer extends Uint8Array in a plain Node process.
    return Uint8Array.from(Buffer.concat([Buffer.from(prefix, 'ascii'), digest]));
  }

  _l1Box(scopingId, submissionId) { return AlgorandLedgerInterface._boxName('L1', scopingId, submissionId); }
  _l2Box(scopingId, identityHash) { return AlgorandLedgerInterface._boxName('L2', scopingId, identityHash); }
  _cnBox(scopingId)               { return AlgorandLedgerInterface._boxName('CN', scopingId); }
  _pcBox(scopingId)               { return AlgorandLedgerInterface._boxName('PC', scopingId); }

  // Fail-fast client-side mirror of the on-chain rejection predicate.
  // This is a courtesy early-exit only — the contract enforces the real
  // check on-chain regardless of whether this method is bypassed, edited,
  // or skipped by a modified client.
  _rejectIfJoinable(submissionId, identityHash) {
    const digestHex = createHash('sha256').update(submissionId, 'utf8').digest('hex');
    if (digestHex === identityHash) {
      throw new Error('Rejection predicate: sha256(submissionId) must not equal identityHash');
    }
  }

  // --- shared atomic-call plumbing ----------------------------------------

  async _buildComposer() {
    const algosdk = await this._sdk();
    return new algosdk.AtomicTransactionComposer();
  }

  async _fundingPaymentTxn(sender, suggestedParams, microAlgos) {
    const algosdk = await this._sdk();
    const appAddress = await this._getAppAddress();
    return algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender,
      receiver: appAddress,
      amount: microAlgos,
      suggestedParams,
    });
  }

  /**
   * Submit one ABI method call as its own atomic group (optionally preceded
   * by a box-MBR funding payment), wait for confirmation, and return the
   * confirmed round + decoded ABI return value + txId.
   */
  async _callMethod(methodName, methodArgs, { boxNames = [], fundBoxes = false } = {}) {
    const algosdk = await this._sdk();
    const algod = await this._client();
    const account = await this._getAccount();
    const contract = await this._getContract();
    const method = contract.getMethodByName(methodName);
    const suggestedParams = await algod.getTransactionParams().do();
    const signer = algosdk.makeBasicAccountTransactionSigner(account);

    const atc = await this._buildComposer();

    if (fundBoxes && this._cfg.boxFundingMicroAlgos > 0) {
      const paymentTxn = await this._fundingPaymentTxn(account.addr, suggestedParams, this._cfg.boxFundingMicroAlgos);
      atc.addTransaction({ txn: paymentTxn, signer });
    }

    atc.addMethodCall({
      appID: this._cfg.appId,
      method,
      methodArgs,
      sender: account.addr,
      signer,
      suggestedParams,
      boxes: boxNames.map((name) => ({ appIndex: this._cfg.appId, name })),
    });

    const result = await atc.execute(algod, this._cfg.waitRounds);
    const [methodResult] = result.methodResults;
    if (methodResult.decodeError) throw methodResult.decodeError;
    return { txId: methodResult.txID, returnValue: methodResult.returnValue, confirmedRound: result.confirmedRound };
  }

  // --- LedgerInterface ------------------------------------------------------

  async submitTwoListWrite(scopingId, list1, list2) {
    return this._traced('algorand.app.submit', { scopingId }, async () => {
      const { submissionId, payloadCommitment } = list1;
      const { identityHash } = list2;
      if (!submissionId || !payloadCommitment) throw new Error('list1 requires submissionId and payloadCommitment');
      if (!identityHash) throw new Error('list2 requires identityHash');
      this._rejectIfJoinable(submissionId, identityHash);

      const { txId, returnValue } = await this._callMethod(
        'submit_two_list_write',
        [scopingId, submissionId, payloadCommitment, identityHash],
        {
          boxNames: [this._l1Box(scopingId, submissionId), this._l2Box(scopingId, identityHash), this._cnBox(scopingId)],
          fundBoxes: true,
        }
      );
      const [l1Count, l2Count, countMatch] = returnValue.valueOf();
      return { txId, l1Count: Number(l1Count), l2Count: Number(l2Count), countMatch: Boolean(countMatch) };
    });
  }

  async getCount(scopingId) {
    // Read-only: no transaction needed. Box contents are public canonical
    // state readable directly from any algod node.
    return this._traced('algorand.box.read', { scopingId }, async () => {
      const algod = await this._client();
      const boxName = this._cnBox(scopingId);
      try {
        const box = await algod.getApplicationBoxByName(this._cfg.appId, boxName).do();
        const value = Buffer.from(box.value);
        const l1Count = Number(value.readBigUInt64BE(0));
        return { l1Count, l2Count: l1Count, countMatch: true };
      } catch (err) {
        // 404 from algod means the box has never been created for this
        // scopingId — count is legitimately zero, not an error.
        if (err?.status === 404 || /not found/i.test(String(err?.message))) {
          return { l1Count: 0, l2Count: 0, countMatch: true };
        }
        throw err;
      }
    });
  }

  async rescindTwoListWrite(scopingId, submissionId, identityHash) {
    return this._traced('algorand.app.rescind', { scopingId }, async () => {
      const { returnValue } = await this._callMethod(
        'rescind_two_list_write',
        [scopingId, submissionId, identityHash],
        { boxNames: [this._l1Box(scopingId, submissionId), this._l2Box(scopingId, identityHash), this._cnBox(scopingId)] }
      );
      const [rescinded, countMatch] = returnValue.valueOf();
      return { countMatch: Boolean(countMatch), rescinded: Boolean(rescinded) };
    });
  }

  async replaceTwoListWrite(scopingId, oldSubmissionId, newList1, identityHash) {
    return this._traced('algorand.app.replace', { scopingId }, async () => {
      const { submissionId: newSubmissionId, payloadCommitment: newPayloadCommitment } = newList1;
      if (!newSubmissionId || !newPayloadCommitment) throw new Error('newList1 requires submissionId and payloadCommitment');
      this._rejectIfJoinable(newSubmissionId, identityHash);

      const { returnValue } = await this._callMethod(
        'replace_two_list_write',
        [scopingId, oldSubmissionId, newSubmissionId, newPayloadCommitment, identityHash],
        {
          boxNames: [
            this._l1Box(scopingId, oldSubmissionId),
            this._l1Box(scopingId, newSubmissionId),
            this._l2Box(scopingId, identityHash),
          ],
          fundBoxes: true,
        }
      );
      const [replaced, countMatch] = returnValue.valueOf();
      return { countMatch: Boolean(countMatch), replaced: Boolean(replaced), newSubmissionId };
    });
  }

  async commitPeriodClose(scopingId, l1MerkleRoot, l2MerkleRoot, attestation) {
    return this._traced('algorand.app.period-close', { scopingId }, async () => {
      const { txId, returnValue } = await this._callMethod(
        'commit_period_close',
        [scopingId, l1MerkleRoot, l2MerkleRoot, attestation],
        { boxNames: [this._pcBox(scopingId)], fundBoxes: true }
      );
      const [, timestampSeconds] = returnValue.valueOf();
      const timestamp = new Date(Number(timestampSeconds) * 1000).toISOString();
      return { txId, timestamp };
    });
  }

  async disconnect() {
    // algosdk.Algodv2 is a stateless HTTPS client with no persistent
    // connection to tear down; drop the cached client so a later call
    // rebuilds it from scratch. The derived/overridden account is kept —
    // it is a credential, not a connection.
    this._algod = null;
  }
}
