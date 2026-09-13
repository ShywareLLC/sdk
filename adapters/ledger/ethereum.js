import { LedgerInterface } from './interface.js';

/**
 * EthereumLedgerInterface — chain-enforced two-list invariant on any
 * EVM-compatible chain (mainnet, an L2, or a private/consortium chain).
 *
 * The four checks (required-field presence, join-key rejection predicate,
 * sybil resistance, replay protection) run inside the deployed
 * `ShywareTwoList` contract's state-transition function (see
 * ./ethereum/contracts/ShywareTwoList.sol) and are therefore validated by
 * every node executing the chain, not merely asserted by this client. A
 * write that violates any check reverts on-chain — this adapter never
 * fabricates a success response for a reverted transaction.
 *
 * Required env vars (or pass the equivalent constructor option):
 *   ETHEREUM_RPC_URL          — JSON-RPC endpoint (default http://127.0.0.1:8545)
 *   ETHEREUM_CONTRACT_ADDRESS — deployed ShywareTwoList address (required)
 *   ETHEREUM_PRIVATE_KEY      — signer key for submit/rescind/replace/period-close
 *                                (not required for read-only getCount if a
 *                                 provider-only override is supplied)
 *
 * Constructor overrides (take precedence over env vars, for callers that
 * already hold an ethers Provider/Signer — e.g. a browser wallet):
 *   { provider }  — an ethers.Provider; used for read-only calls
 *   { signer }    — an ethers.Signer; used for all state-changing calls
 *
 * Peer dependency (optional — loaded via dynamic import so it is not a hard
 * dependency of @shyware/sdk itself): ethers ^6
 *   npm add ethers   (in the consumer workspace)
 *
 * Field encoding: scopingId / submissionId / payloadCommitment / identityHash /
 * l1MerkleRoot / l2MerkleRoot are bytes32 on-chain. Values already shaped as a
 * 0x-prefixed 32-byte hex string are used as-is (the common case — callers
 * typically already pass a hash, e.g. identityHash = H(uid || scopingId)).
 * Any other string is keccak256-hashed into bytes32 automatically so the
 * adapter is a drop-in swap for the string-typed LedgerInterface contract.
 */

const SHYWARE_TWO_LIST_ABI = [
  'function submitTwoListWrite(bytes32 scopingId, bytes32 submissionId, bytes32 payloadCommitment, bytes32 identityHash) returns (uint256 l1Count, uint256 l2Count, bool countMatch)',
  'function getCount(bytes32 scopingId) view returns (uint256 l1Count, uint256 l2Count, bool countMatch)',
  'function rescindTwoListWrite(bytes32 scopingId, bytes32 submissionId, bytes32 identityHash) returns (uint256 l1Count, uint256 l2Count, bool countMatch, bool rescinded)',
  'function replaceTwoListWrite(bytes32 scopingId, bytes32 oldSubmissionId, bytes32 newSubmissionId, bytes32 newPayloadCommitment, bytes32 identityHash) returns (bool countMatch, bool replaced, bytes32 newSubmissionIdOut)',
  'function commitPeriodClose(bytes32 scopingId, bytes32 l1MerkleRoot, bytes32 l2MerkleRoot, bytes attestation) returns (bytes32 scopingIdOut, uint256 timestamp)',
  'function getPeriodClose(bytes32 scopingId) view returns (bool closed, bytes32 l1MerkleRoot, bytes32 l2MerkleRoot, bytes attestation, uint256 timestamp)',
  'event TwoListWritten(bytes32 indexed scopingId, bytes32 indexed submissionId, bytes32 indexed identityHash, bytes32 payloadCommitment, uint256 l1Count, uint256 l2Count)',
  'event TwoListRescinded(bytes32 indexed scopingId, bytes32 indexed submissionId, bytes32 indexed identityHash, uint256 l1Count, uint256 l2Count)',
  'event TwoListReplaced(bytes32 indexed scopingId, bytes32 indexed oldSubmissionId, bytes32 indexed newSubmissionId, bytes32 identityHash, bytes32 newPayloadCommitment)',
  'event PeriodClosed(bytes32 indexed scopingId, bytes32 l1MerkleRoot, bytes32 l2MerkleRoot, bytes attestation, uint256 timestamp)',
  'error EmptyField(string field)',
  'error RejectionPredicateViolated()',
  'error SybilResistanceViolated()',
  'error ReplayProtectionViolated()',
  'error SubmissionNotFound()',
  'error IdentityMismatch()',
  'error PeriodAlreadyClosed()',
];

const BYTES32_HEX_RE = /^0x[0-9a-fA-F]{64}$/;

export class EthereumLedgerInterface extends LedgerInterface {
  constructor({
    rpcUrl          = process.env.ETHEREUM_RPC_URL || 'http://127.0.0.1:8545',
    contractAddress = process.env.ETHEREUM_CONTRACT_ADDRESS,
    privateKey      = process.env.ETHEREUM_PRIVATE_KEY,
    provider = null,
    signer   = null,
    tracer   = null,
  } = {}) {
    super();
    if (!contractAddress) throw new Error('ETHEREUM_CONTRACT_ADDRESS is required (or pass contractAddress)');
    if (!signer && !privateKey && !provider) {
      throw new Error('ETHEREUM_PRIVATE_KEY is required for state-changing calls (or pass a signer/provider override)');
    }
    this._cfg = { rpcUrl, contractAddress, privateKey };
    this._providerOverride = provider;
    this._signerOverride = signer;
    this._tracer = tracer;
    this._ethers = null;
    this._provider = null;
    this._signer = null;
    this._contract = null;
  }

  get name() { return 'ethereum'; }

  async _traced(name, annotations, fn) {
    if (this._tracer) return this._tracer.trace(name, annotations, fn);
    return fn();
  }

  async _getContract() {
    if (this._contract) return this._contract;
    const { ethers } = await import('ethers');
    this._ethers = ethers;
    this._provider = this._providerOverride || new ethers.JsonRpcProvider(this._cfg.rpcUrl);
    // Wrapped in ethers' NonceManager so back-to-back writes from the same
    // signer (submit, then rescind/replace on the same submission) never race
    // against the provider's "pending" transaction-count view — the manager
    // tracks the next nonce locally instead of re-querying the network on
    // every send.
    this._signer = this._signerOverride || (this._cfg.privateKey
      ? new ethers.NonceManager(new ethers.Wallet(this._cfg.privateKey, this._provider))
      : null);
    // A provider-only instance (no signer) can still serve read-only calls
    // (getCount) by connecting the contract to the provider directly.
    this._contract = new ethers.Contract(this._cfg.contractAddress, SHYWARE_TWO_LIST_ABI, this._signer || this._provider);
    return this._contract;
  }

  _toBytes32(value) {
    if (typeof value === 'string' && BYTES32_HEX_RE.test(value)) return value;
    return this._ethers.keccak256(this._ethers.toUtf8Bytes(String(value)));
  }

  _findEvent(contract, receipt, eventName) {
    for (const log of receipt.logs) {
      try {
        const parsed = contract.interface.parseLog(log);
        if (parsed && parsed.name === eventName) return parsed;
      } catch {
        // Not a log from this contract's ABI (e.g. from another contract in the
        // same tx) — skip.
      }
    }
    return null;
  }

  async submitTwoListWrite(scopingId, list1, list2) {
    return this._traced('ethereum.tx.submit', { scopingId }, async () => {
      const c = await this._getContract();
      const scopingId32 = this._toBytes32(scopingId);
      const submissionId32 = this._toBytes32(list1.submissionId);
      const payloadCommitment32 = this._toBytes32(list1.payloadCommitment);
      const identityHash32 = this._toBytes32(list2.identityHash);

      const tx = await c.submitTwoListWrite(scopingId32, submissionId32, payloadCommitment32, identityHash32);
      const receipt = await tx.wait();
      const evt = this._findEvent(c, receipt, 'TwoListWritten');
      const l1Count = evt ? Number(evt.args.l1Count) : Number((await c.getCount(scopingId32))[0]);
      const l2Count = evt ? Number(evt.args.l2Count) : l1Count;
      return { txId: receipt.hash, l1Count, l2Count, countMatch: l1Count === l2Count };
    });
  }

  async getCount(scopingId) {
    return this._traced('ethereum.call.getCount', { scopingId }, async () => {
      const c = await this._getContract();
      const [l1Count, l2Count, countMatch] = await c.getCount(this._toBytes32(scopingId));
      return { l1Count: Number(l1Count), l2Count: Number(l2Count), countMatch };
    });
  }

  async rescindTwoListWrite(scopingId, submissionId, identityHash) {
    return this._traced('ethereum.tx.rescind', { scopingId }, async () => {
      const c = await this._getContract();
      const tx = await c.rescindTwoListWrite(
        this._toBytes32(scopingId),
        this._toBytes32(submissionId),
        this._toBytes32(identityHash),
      );
      const receipt = await tx.wait();
      const evt = this._findEvent(c, receipt, 'TwoListRescinded');
      const l1Count = evt ? Number(evt.args.l1Count) : null;
      const l2Count = evt ? Number(evt.args.l2Count) : null;
      return { countMatch: l1Count === null ? true : l1Count === l2Count, rescinded: true };
    });
  }

  async replaceTwoListWrite(scopingId, oldSubmissionId, newList1, identityHash) {
    return this._traced('ethereum.tx.replace', { scopingId }, async () => {
      const c = await this._getContract();
      const tx = await c.replaceTwoListWrite(
        this._toBytes32(scopingId),
        this._toBytes32(oldSubmissionId),
        this._toBytes32(newList1.submissionId),
        this._toBytes32(newList1.payloadCommitment),
        this._toBytes32(identityHash),
      );
      await tx.wait();
      return { countMatch: true, replaced: true, newSubmissionId: newList1.submissionId };
    });
  }

  async commitPeriodClose(scopingId, l1MerkleRoot, l2MerkleRoot, attestation) {
    return this._traced('ethereum.tx.period-close', { scopingId }, async () => {
      const c = await this._getContract();
      const attestationBytes = this._ethers.toUtf8Bytes(String(attestation));
      const tx = await c.commitPeriodClose(
        this._toBytes32(scopingId),
        this._toBytes32(l1MerkleRoot),
        this._toBytes32(l2MerkleRoot),
        attestationBytes,
      );
      const receipt = await tx.wait();
      const evt = this._findEvent(c, receipt, 'PeriodClosed');
      const timestamp = evt
        ? new Date(Number(evt.args.timestamp) * 1000).toISOString()
        : new Date().toISOString();
      return { txId: receipt.hash, timestamp };
    });
  }

  async disconnect() {
    this._contract = null;
    this._signer = null;
    if (this._provider && typeof this._provider.destroy === 'function') {
      this._provider.destroy();
    }
    this._provider = null;
  }
}
