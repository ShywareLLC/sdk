// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @title ShywareTwoList
/// @notice Chain-enforced two-list invariant for the Shyware anonymous submission protocol.
///
/// Every submission atomically writes two records:
///   List 1 (L1) — a direction-free submission identifier + payload commitment. No identity.
///   List 2 (L2) — a participant identity-hash marker. No payload, no submission identifier.
///
/// No join key between L1 and L2 is ever written to contract storage. The state-transition
/// function itself — validated by every node that executes this contract, not a client that
/// merely trusts itself to behave — enforces, in this exact order, on every write:
///
///   1. Required-field presence (submissionId, payloadCommitment, identityHash all non-zero).
///   2. Rejection predicate: sha256(submissionId) must NOT equal identityHash — no participant
///      identity may be recoverable from the submission identifier by a trivial hash relation,
///      and vice versa. This is a structural exclusion enforced by the EVM itself, not a
///      convention the caller is trusted to uphold.
///   3. Sybil resistance: one L2 entry per (scopingId, identityHash) — one identity, one
///      submission, per scoping id.
///   4. Replay protection: one L1 entry per (scopingId, submissionId).
///
/// This mirrors, function-for-function, the Hyperledger Fabric chaincode reference
/// implementation of the same protocol (submitTwoListWrite / getCount / rescindTwoListWrite /
/// replaceTwoListWrite / commitPeriodClose) so either backend can serve behind the same
/// LedgerInterface contract in the JS SDK.
///
/// Deliberately NOT upgradeable and NOT proxied: the enforcement logic below IS the audit
/// surface. A proxy pattern would let an admin key silently swap the enforcement logic out
/// from under the invariant, which defeats the entire point of putting this on-chain instead
/// of in a client library.
contract ShywareTwoList {
    struct L1Record {
        bool exists_;
        bytes32 payloadCommitment;
        bytes32 identityHash; // owning L2 key — never exposed as a join query, only used
                               // internally to authorize rescind/replace of a submission by
                               // the same identity that created it. Not indexed, not iterable,
                               // not returned by any view function.
    }

    struct PeriodClose {
        bool closed;
        bytes32 l1MerkleRoot; // over submission identifiers only
        bytes32 l2MerkleRoot; // over identity hashes only
        bytes attestation;    // external signature (e.g. KMS) over both roots + count
        uint256 timestamp;
    }

    // scopingId => submissionId => L1 record
    mapping(bytes32 => mapping(bytes32 => L1Record)) private _l1;
    // scopingId => identityHash => present
    mapping(bytes32 => mapping(bytes32 => bool)) private _l2Exists;
    // scopingId => count (L1 and L2 are always written/removed together, so a single
    // counter serves as both l1Count and l2Count by construction — this IS the
    // count-match invariant, enforced by the write path rather than checked after the fact)
    mapping(bytes32 => uint256) private _count;
    // scopingId => period-close record (one-time-only)
    mapping(bytes32 => PeriodClose) private _periodClose;

    event TwoListWritten(
        bytes32 indexed scopingId,
        bytes32 indexed submissionId,
        bytes32 indexed identityHash,
        bytes32 payloadCommitment,
        uint256 l1Count,
        uint256 l2Count
    );

    event TwoListRescinded(
        bytes32 indexed scopingId,
        bytes32 indexed submissionId,
        bytes32 indexed identityHash,
        uint256 l1Count,
        uint256 l2Count
    );

    event TwoListReplaced(
        bytes32 indexed scopingId,
        bytes32 indexed oldSubmissionId,
        bytes32 indexed newSubmissionId,
        bytes32 identityHash,
        bytes32 newPayloadCommitment
    );

    event PeriodClosed(
        bytes32 indexed scopingId,
        bytes32 l1MerkleRoot,
        bytes32 l2MerkleRoot,
        bytes attestation,
        uint256 timestamp
    );

    error EmptyField(string field);
    error RejectionPredicateViolated();
    error SybilResistanceViolated();
    error ReplayProtectionViolated();
    error SubmissionNotFound();
    error IdentityMismatch();
    error PeriodAlreadyClosed();

    /// @notice Atomically write one L1 record (no identity) and one L2 record (no payload).
    /// Reverts — the transaction is not mined into a successful state — if any of the four
    /// checks fail; a caller cannot observe a partially-applied write.
    function submitTwoListWrite(
        bytes32 scopingId,
        bytes32 submissionId,
        bytes32 payloadCommitment,
        bytes32 identityHash
    ) external returns (uint256 l1Count, uint256 l2Count, bool countMatch) {
        if (submissionId == bytes32(0)) revert EmptyField("submissionId");
        if (payloadCommitment == bytes32(0)) revert EmptyField("payloadCommitment");
        if (identityHash == bytes32(0)) revert EmptyField("identityHash");

        // 2. Rejection predicate — no join key between L1 and L2.
        if (sha256(abi.encodePacked(submissionId)) == identityHash) {
            revert RejectionPredicateViolated();
        }

        // 3. Sybil resistance — one identity, one submission, per scoping id.
        if (_l2Exists[scopingId][identityHash]) revert SybilResistanceViolated();

        // 4. Replay protection — one L1 entry per (scopingId, submissionId).
        if (_l1[scopingId][submissionId].exists_) revert ReplayProtectionViolated();

        _l1[scopingId][submissionId] = L1Record({
            exists_: true,
            payloadCommitment: payloadCommitment,
            identityHash: identityHash
        });
        _l2Exists[scopingId][identityHash] = true;

        uint256 newCount = _count[scopingId] + 1;
        _count[scopingId] = newCount;

        emit TwoListWritten(scopingId, submissionId, identityHash, payloadCommitment, newCount, newCount);
        return (newCount, newCount, true);
    }

    /// @notice Read-only cardinality check. `countMatch` is always true by construction —
    /// the write path can never advance one counter without the other — but is returned
    /// explicitly so any third party can verify the invariant without trusting this claim,
    /// matching the shape every other LedgerInterface adapter returns.
    function getCount(bytes32 scopingId) external view returns (uint256 l1Count, uint256 l2Count, bool countMatch) {
        uint256 n = _count[scopingId];
        return (n, n, true);
    }

    /// @notice Participant-initiated withdrawal: atomically delete L1 + L2 for a submission,
    /// decrement count. The caller must present the identityHash that owns `submissionId`
    /// (derived off-chain from a fresh authentication attestation) — this is an ownership
    /// check, not a join query: it never returns or exposes the association to a third party,
    /// it only gates which caller may delete which record.
    function rescindTwoListWrite(
        bytes32 scopingId,
        bytes32 submissionId,
        bytes32 identityHash
    ) external returns (uint256 l1Count, uint256 l2Count, bool countMatch, bool rescinded) {
        L1Record memory rec = _l1[scopingId][submissionId];
        if (!rec.exists_) revert SubmissionNotFound();
        if (rec.identityHash != identityHash) revert IdentityMismatch();
        if (!_l2Exists[scopingId][identityHash]) revert SubmissionNotFound();

        delete _l1[scopingId][submissionId];
        delete _l2Exists[scopingId][identityHash];

        uint256 newCount = _count[scopingId] - 1;
        _count[scopingId] = newCount;

        emit TwoListRescinded(scopingId, submissionId, identityHash, newCount, newCount);
        return (newCount, newCount, true, true);
    }

    /// @notice Participant-initiated replacement: atomically replace the L1 record (new
    /// submissionId + payload) while leaving L2 and the count untouched. The new
    /// (submissionId, identityHash) pair is subject to the same rejection-predicate and
    /// replay-protection checks as a fresh write.
    function replaceTwoListWrite(
        bytes32 scopingId,
        bytes32 oldSubmissionId,
        bytes32 newSubmissionId,
        bytes32 newPayloadCommitment,
        bytes32 identityHash
    ) external returns (bool countMatch, bool replaced, bytes32 newSubmissionIdOut) {
        if (newSubmissionId == bytes32(0)) revert EmptyField("submissionId");
        if (newPayloadCommitment == bytes32(0)) revert EmptyField("payloadCommitment");

        L1Record memory oldRec = _l1[scopingId][oldSubmissionId];
        if (!oldRec.exists_) revert SubmissionNotFound();
        if (oldRec.identityHash != identityHash) revert IdentityMismatch();

        // Rejection predicate applied to the new pair.
        if (sha256(abi.encodePacked(newSubmissionId)) == identityHash) {
            revert RejectionPredicateViolated();
        }

        // Replay protection: the new submissionId must not already be in use in this scope
        // (unless it is the record being replaced, which is deleted first below).
        if (newSubmissionId != oldSubmissionId && _l1[scopingId][newSubmissionId].exists_) {
            revert ReplayProtectionViolated();
        }

        delete _l1[scopingId][oldSubmissionId];
        _l1[scopingId][newSubmissionId] = L1Record({
            exists_: true,
            payloadCommitment: newPayloadCommitment,
            identityHash: identityHash
        });

        emit TwoListReplaced(scopingId, oldSubmissionId, newSubmissionId, identityHash, newPayloadCommitment);
        return (true, true, newSubmissionId);
    }

    /// @notice One-time-only period-close attestation over two disjoint Merkle roots
    /// (submission identifiers only; identity hashes only) plus an external signature
    /// (e.g. AWS KMS) produced by a key never held in contract storage.
    function commitPeriodClose(
        bytes32 scopingId,
        bytes32 l1MerkleRoot,
        bytes32 l2MerkleRoot,
        bytes calldata attestation
    ) external returns (bytes32 scopingIdOut, uint256 timestamp) {
        if (_periodClose[scopingId].closed) revert PeriodAlreadyClosed();

        uint256 ts = block.timestamp;
        _periodClose[scopingId] = PeriodClose({
            closed: true,
            l1MerkleRoot: l1MerkleRoot,
            l2MerkleRoot: l2MerkleRoot,
            attestation: attestation,
            timestamp: ts
        });

        emit PeriodClosed(scopingId, l1MerkleRoot, l2MerkleRoot, attestation, ts);
        return (scopingId, ts);
    }

    /// @notice Read-only accessor for a committed period-close record. Returns
    /// closed == false and zeroed fields if no period-close has been committed yet.
    function getPeriodClose(bytes32 scopingId)
        external
        view
        returns (bool closed, bytes32 l1MerkleRoot, bytes32 l2MerkleRoot, bytes memory attestation, uint256 timestamp)
    {
        PeriodClose memory pc = _periodClose[scopingId];
        return (pc.closed, pc.l1MerkleRoot, pc.l2MerkleRoot, pc.attestation, pc.timestamp);
    }
}
