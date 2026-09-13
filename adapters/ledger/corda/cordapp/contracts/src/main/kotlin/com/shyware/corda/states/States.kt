package com.shyware.corda.states

import com.shyware.corda.contracts.TwoListContract
import net.corda.core.contracts.BelongsToContract
import net.corda.core.contracts.LinearState
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.identity.AbstractParty

/**
 * Two-list invariant, mapped onto Corda's UTXO model.
 *
 * Corda has no shared global mutable map the way an account-based chain does; the unit
 * of consensus is a state that a notary will refuse to let be spent twice. We use that
 * primitive for BOTH of the ledger's uniqueness guarantees (L1 replay protection and L2
 * sybil resistance) by routing every write for a given [scopingId] through a single
 * evolving [ScopingRegistryState]:
 *
 *   - The registry is CONSUMED (spent) and reissued on every submit/rescind/replace/close.
 *     The notary will only let one transaction consume a given version of the registry,
 *     so two concurrent submissions for the same scopingId cannot both win a race against
 *     stale registry state -- exactly the "double-spend" guarantee a notary exists to give.
 *   - Because writes are serialized through the registry's consumption, the contract can
 *     safely check "is this submissionId/identityHash already used?" against the registry's
 *     usedL1Ids / usedL2Ids sets with no TOCTOU window: whichever transaction the notary
 *     commits first is the one whose used-sets become canonical for the next writer.
 *
 * L1State and L2State themselves are separate, independently-created, non-fungible
 * LinearStates with NO shared field: L1 carries a payload commitment and no identity;
 * L2 carries an identity hash and no payload, no submissionId. No transaction ever
 * consumes one to produce the other, and no query joins them -- the join key the
 * two-list invariant forbids is never written to canonical state.
 */

/**
 * List 1: a direction-free submission record. No participant identity field.
 *
 * [participants] lists only the Corda node(s) hosting this CorDapp (the ledger
 * operator / notary-adjacent party) so the state is visible to the nodes that must
 * process it -- this is Corda's data-distribution mechanism, not a submitter identity.
 * It carries no relationship to any real-world participant and must never be populated
 * with a party derived from list2.identityHash.
 */
@BelongsToContract(TwoListContract::class)
data class L1State(
    val scopingId: String,
    val submissionId: String,
    val payloadCommitment: String,
    override val linearId: UniqueIdentifier,
    override val participants: List<AbstractParty>
) : LinearState

/**
 * List 2: a participant registry record. No payload, no submissionId field.
 */
@BelongsToContract(TwoListContract::class)
data class L2State(
    val scopingId: String,
    val identityHash: String,
    override val linearId: UniqueIdentifier,
    override val participants: List<AbstractParty>
) : LinearState

/**
 * The per-scopingId serialization point described above. `usedL1Ids` / `usedL2Ids` are
 * the canonical duplicate-check sets; `l1Count` / `l2Count` are the count-match counters.
 *
 * Known scaling simplification: the used-id sets are carried inline on the state rather
 * than behind a Merkle/accumulator structure, so state size grows with volume per
 * scopingId. For very high-volume scopingIds this would be swapped for an accumulator
 * (e.g. a sorted Merkle tree with non-membership proofs) without changing the contract's
 * external behavior -- flagged here rather than silently built, since the requested
 * scope is "genuinely chain-enforced," not "infinitely scalable."
 */
@BelongsToContract(TwoListContract::class)
data class ScopingRegistryState(
    val scopingId: String,
    val usedL1Ids: Set<String>,
    val usedL2Ids: Set<String>,
    val l1Count: Int,
    val l2Count: Int,
    val closed: Boolean,
    override val linearId: UniqueIdentifier,
    override val participants: List<AbstractParty>
) : LinearState

/**
 * A one-time-only period-close attestation for a scopingId. `l1MerkleRoot` is computed
 * over submission identifiers only; `l2MerkleRoot` over identity hashes only. No field
 * on this state joins the two roots to any individual submission or identity.
 */
@BelongsToContract(TwoListContract::class)
data class PeriodCloseState(
    val scopingId: String,
    val l1MerkleRoot: String,
    val l2MerkleRoot: String,
    val attestation: String,
    val l1Count: Int,
    val l2Count: Int,
    val timestamp: String,
    override val linearId: UniqueIdentifier,
    override val participants: List<AbstractParty>
) : LinearState
