package com.shyware.corda.contracts

import com.shyware.corda.states.L1State
import com.shyware.corda.states.L2State
import com.shyware.corda.states.PeriodCloseState
import com.shyware.corda.states.ScopingRegistryState
import net.corda.core.contracts.CommandData
import net.corda.core.contracts.Contract
import net.corda.core.contracts.requireSingleCommand
import net.corda.core.contracts.requireThat
import net.corda.core.transactions.LedgerTransaction
import java.security.MessageDigest

/**
 * On-chain enforcement of the two-list invariant's four checks, mirroring the reference
 * Hyperledger Fabric chaincode's submitTwoListWrite ordering exactly, plus the lifecycle
 * operations (rescind / replace / period-close). This is validated by every node that
 * receives and resolves the transaction (contract verification runs at every party that
 * transitively sees the transaction, not just the party that built it) -- the guarantee
 * is not "the JS SDK promises to behave," it is "the transaction does not verify, and the
 * notary will not sign, otherwise."
 */
class TwoListContract : Contract {

    companion object {
        const val ID = "com.shyware.corda.contracts.TwoListContract"

        fun sha256Hex(input: String): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
            return digest.joinToString("") { "%02x".format(it) }
        }
    }

    interface Commands : CommandData {
        /** Steps 1-5 of the reference chaincode: parse/require, reject, sybil, replay, write. */
        class Submit : Commands
        /** Delete both L1 and L2 for a submission, decrement count. */
        class Rescind : Commands
        /** Delete old L1, write new L1 with the same rejection-predicate check, leave L2/count untouched. */
        class Replace : Commands
        /** One-time-only period-close record; reject if already closed. */
        class CommitPeriodClose : Commands
    }

    override fun verify(tx: LedgerTransaction) {
        val command = tx.commands.requireSingleCommand<Commands>()

        when (command.value) {
            is Commands.Submit -> verifySubmit(tx)
            is Commands.Rescind -> verifyRescind(tx)
            is Commands.Replace -> verifyReplace(tx)
            is Commands.CommitPeriodClose -> verifyCommitPeriodClose(tx)
            else -> throw IllegalArgumentException("Unrecognized command: ${command.value}")
        }
    }

    // ---- Step ordering below mirrors submitTwoListWrite(scopingId, list1Json, list2Json) ----

    private fun verifySubmit(tx: LedgerTransaction) = requireThat {
        val registryIn = tx.inputsOfType<ScopingRegistryState>().singleOrNull()
            ?: throw IllegalArgumentException("Submit requires exactly one input ScopingRegistryState")
        val registryOut = tx.outputsOfType<ScopingRegistryState>().singleOrNull()
        "Submit produces exactly one output ScopingRegistryState" using (registryOut != null)
        val l1 = tx.outputsOfType<L1State>().singleOrNull()
        "Submit produces exactly one output L1State" using (l1 != null)
        val l2 = tx.outputsOfType<L2State>().singleOrNull()
        "Submit produces exactly one output L2State" using (l2 != null)
        "Submit consumes no L1State or L2State (fresh evidence records only)" using
            (tx.inputsOfType<L1State>().isEmpty() && tx.inputsOfType<L2State>().isEmpty())

        // Step 1: required fields.
        "list1.submissionId must not be empty" using l1!!.submissionId.isNotBlank()
        "list1.payloadCommitment must not be empty" using l1.payloadCommitment.isNotBlank()
        "list2.identityHash must not be empty" using l2!!.identityHash.isNotBlank()

        "scopingId is consistent across registry, L1 and L2" using
            (registryIn.scopingId == registryOut!!.scopingId && registryOut.scopingId == l1.scopingId && l1.scopingId == l2.scopingId)

        "registry is not closed" using !registryIn.closed
        "registry output preserves closed = false" using !registryOut.closed
        "registry linearId is preserved across the write" using (registryIn.linearId == registryOut.linearId)

        // Step 2: rejection predicate -- no join key between L1 and L2 is ever written.
        "rejection predicate: sha256(list1.submissionId) must not equal list2.identityHash" using
            (sha256Hex(l1.submissionId) != l2.identityHash)

        // Step 3: sybil resistance -- one identity, one submission, per scopingId.
        "sybil resistance: identityHash must not already be registered for this scopingId" using
            !registryIn.usedL2Ids.contains(l2.identityHash)

        // Step 4: replay protection.
        "replay protection: submissionId must not already exist for this scopingId" using
            !registryIn.usedL1Ids.contains(l1.submissionId)

        // Step 5: write + count-match bookkeeping, enforced structurally (not just returned).
        "registry.usedL1Ids output = input + submissionId" using
            (registryOut.usedL1Ids == registryIn.usedL1Ids + l1.submissionId)
        "registry.usedL2Ids output = input + identityHash" using
            (registryOut.usedL2Ids == registryIn.usedL2Ids + l2.identityHash)
        "l1Count increments by exactly one" using (registryOut.l1Count == registryIn.l1Count + 1)
        "l2Count increments by exactly one" using (registryOut.l2Count == registryIn.l2Count + 1)
        "count-match: l1Count == l2Count after every submit" using (registryOut.l1Count == registryOut.l2Count)
    }

    private fun verifyRescind(tx: LedgerTransaction) = requireThat {
        val registryIn = tx.inputsOfType<ScopingRegistryState>().singleOrNull()
            ?: throw IllegalArgumentException("Rescind requires exactly one input ScopingRegistryState")
        val registryOut = tx.outputsOfType<ScopingRegistryState>().singleOrNull()
        "Rescind produces exactly one output ScopingRegistryState" using (registryOut != null)
        val l1 = tx.inputsOfType<L1State>().singleOrNull()
        "Rescind consumes exactly one input L1State" using (l1 != null)
        val l2 = tx.inputsOfType<L2State>().singleOrNull()
        "Rescind consumes exactly one input L2State" using (l2 != null)
        "Rescind produces no output L1State or L2State (both are deleted)" using
            (tx.outputsOfType<L1State>().isEmpty() && tx.outputsOfType<L2State>().isEmpty())

        "scopingId is consistent across registry, L1 and L2" using
            (registryIn.scopingId == registryOut!!.scopingId && registryOut.scopingId == l1!!.scopingId && l1.scopingId == l2!!.scopingId)
        "registry linearId is preserved across the rescission" using (registryIn.linearId == registryOut.linearId)
        "registry is not closed" using !registryIn.closed

        "the L1 being deleted was actually registered" using registryIn.usedL1Ids.contains(l1.submissionId)
        "the L2 being deleted was actually registered" using registryIn.usedL2Ids.contains(l2.identityHash)

        "registry.usedL1Ids output = input - submissionId" using
            (registryOut.usedL1Ids == registryIn.usedL1Ids - l1.submissionId)
        "registry.usedL2Ids output = input - identityHash" using
            (registryOut.usedL2Ids == registryIn.usedL2Ids - l2.identityHash)
        "l1Count decrements by exactly one" using (registryOut.l1Count == registryIn.l1Count - 1)
        "l2Count decrements by exactly one" using (registryOut.l2Count == registryIn.l2Count - 1)
        "count-match is preserved after deletion" using (registryOut.l1Count == registryOut.l2Count)
    }

    private fun verifyReplace(tx: LedgerTransaction) = requireThat {
        val registryIn = tx.inputsOfType<ScopingRegistryState>().singleOrNull()
            ?: throw IllegalArgumentException("Replace requires exactly one input ScopingRegistryState")
        val registryOut = tx.outputsOfType<ScopingRegistryState>().singleOrNull()
        "Replace produces exactly one output ScopingRegistryState" using (registryOut != null)
        val oldL1 = tx.inputsOfType<L1State>().singleOrNull()
        "Replace consumes exactly one input (old) L1State" using (oldL1 != null)
        val newL1 = tx.outputsOfType<L1State>().singleOrNull()
        "Replace produces exactly one output (new) L1State" using (newL1 != null)
        // L2 is untouched: passed as a REFERENCE input only, never consumed or produced.
        val l2Ref = tx.referenceInputRefsOfType<L2State>().map { it.state.data }.singleOrNull()
        "Replace references exactly one L2State (unchanged, for the rejection-predicate check)" using (l2Ref != null)
        "Replace consumes no L2State" using tx.inputsOfType<L2State>().isEmpty()
        "Replace produces no L2State" using tx.outputsOfType<L2State>().isEmpty()

        "scopingId is consistent across registry, old L1, new L1 and referenced L2" using
            (registryIn.scopingId == registryOut!!.scopingId &&
                registryOut.scopingId == oldL1!!.scopingId &&
                oldL1.scopingId == newL1!!.scopingId &&
                newL1.scopingId == l2Ref!!.scopingId)
        "registry linearId is preserved across the replacement" using (registryIn.linearId == registryOut.linearId)
        "registry is not closed" using !registryIn.closed

        "the old L1 being replaced was actually registered" using registryIn.usedL1Ids.contains(oldL1.submissionId)
        "new submissionId must not already exist for this scopingId" using
            !registryIn.usedL1Ids.contains(newL1.submissionId)

        // Same rejection-predicate check as step 2 of Submit, against the unchanged L2.
        "rejection predicate: sha256(newList1.submissionId) must not equal identityHash" using
            (sha256Hex(newL1.submissionId) != l2Ref.identityHash)

        "registry.usedL1Ids output = input - oldSubmissionId + newSubmissionId" using
            (registryOut.usedL1Ids == (registryIn.usedL1Ids - oldL1.submissionId) + newL1.submissionId)
        "registry.usedL2Ids is unchanged by a replace" using (registryOut.usedL2Ids == registryIn.usedL2Ids)
        "l1Count is unchanged by a replace" using (registryOut.l1Count == registryIn.l1Count)
        "l2Count is unchanged by a replace" using (registryOut.l2Count == registryIn.l2Count)
    }

    private fun verifyCommitPeriodClose(tx: LedgerTransaction) = requireThat {
        val registryIn = tx.inputsOfType<ScopingRegistryState>().singleOrNull()
            ?: throw IllegalArgumentException("CommitPeriodClose requires exactly one input ScopingRegistryState")
        val registryOut = tx.outputsOfType<ScopingRegistryState>().singleOrNull()
        "CommitPeriodClose produces exactly one output ScopingRegistryState" using (registryOut != null)
        val close = tx.outputsOfType<PeriodCloseState>().singleOrNull()
        "CommitPeriodClose produces exactly one output PeriodCloseState" using (close != null)
        "CommitPeriodClose consumes no PeriodCloseState" using tx.inputsOfType<PeriodCloseState>().isEmpty()

        "scopingId is consistent across registry and the close record" using
            (registryIn.scopingId == registryOut!!.scopingId && registryOut.scopingId == close!!.scopingId)
        "registry linearId is preserved across period-close" using (registryIn.linearId == registryOut.linearId)

        // One-time-only: reject if already closed.
        "registry must not already be closed" using !registryIn.closed
        "registry output is marked closed" using registryOut.closed
        "counts are not mutated by period-close" using
            (registryOut.l1Count == registryIn.l1Count && registryOut.l2Count == registryIn.l2Count)
        "the close record snapshots the counts at close time" using
            (close.l1Count == registryIn.l1Count && close.l2Count == registryIn.l2Count)

        "l1MerkleRoot must not be empty" using close.l1MerkleRoot.isNotBlank()
        "l2MerkleRoot must not be empty" using close.l2MerkleRoot.isNotBlank()
        "attestation must not be empty" using close.attestation.isNotBlank()
        // Disjoint-roots structural check: the two roots must not be identical unless both
        // lists are empty (a degenerate case), since a shared root over both lists would be
        // exactly the kind of L1/L2 join the invariant forbids.
        "l1MerkleRoot and l2MerkleRoot must be disjoint (not equal) unless counts are both zero" using
            (close.l1MerkleRoot != close.l2MerkleRoot || (close.l1Count == 0 && close.l2Count == 0))
    }
}
