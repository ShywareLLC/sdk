package com.shyware.corda.flows

import co.paralleluniverse.fibers.Suspendable
import com.shyware.corda.contracts.TwoListContract
import com.shyware.corda.states.L1State
import com.shyware.corda.states.L2State
import com.shyware.corda.states.ScopingRegistryState
import net.corda.core.contracts.Command
import net.corda.core.contracts.referenced
import net.corda.core.flows.FinalityFlow
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.FlowSession
import net.corda.core.flows.InitiatingFlow
import net.corda.core.flows.StartableByRPC
import net.corda.core.transactions.TransactionBuilder
import net.corda.core.utilities.ProgressTracker

/**
 * Participant-initiated replacement: atomically replace the L1 record (new submissionId +
 * payload) while leaving L2 unchanged. Count-match preserved. L2 is passed as a Corda
 * REFERENCE input state: the contract can read identityHash to re-run the rejection
 * predicate against the new submissionId, without the transaction consuming (spending)
 * L2 at all -- L2's registration and count are structurally untouched by a replace.
 */
@InitiatingFlow
@StartableByRPC
class ReplaceTwoListWriteFlow(
    private val scopingId: String,
    private val oldSubmissionId: String,
    private val newSubmissionId: String,
    private val newPayloadCommitment: String,
    private val identityHash: String
) : FlowLogic<ReplaceTwoListWriteFlow.Result>() {

    data class Result(val countMatch: Boolean, val replaced: Boolean, val newSubmissionId: String)

    override val progressTracker = ProgressTracker()

    @Suspendable
    override fun call(): Result {
        val notary = serviceHub.networkMapCache.notaryIdentities.first()
        val us = ourIdentity

        val registryRef = findUnconsumedByLinearId(ScopingRegistryState::class.java, RegistryUtils.registryLinearId(scopingId))
            ?: throw IllegalArgumentException("no registry exists for scopingId=$scopingId")
        val registryIn = registryRef.state.data

        val oldL1Ref = findUnconsumedByLinearId(L1State::class.java, RegistryUtils.l1LinearId(scopingId, oldSubmissionId))
            ?: throw IllegalArgumentException("no L1State found for submissionId=$oldSubmissionId")
        val l2Ref = findUnconsumedByLinearId(L2State::class.java, RegistryUtils.l2LinearId(scopingId, identityHash))
            ?: throw IllegalArgumentException("no L2State found for identityHash=$identityHash")

        require(!registryIn.closed) { "scopingId is closed" }
        require(registryIn.usedL1Ids.contains(oldSubmissionId)) { "oldSubmissionId not registered" }
        require(!registryIn.usedL1Ids.contains(newSubmissionId)) { "newSubmissionId already exists" }
        require(TwoListContract.sha256Hex(newSubmissionId) != identityHash) {
            "rejection predicate violated: sha256(newSubmissionId) == identityHash"
        }

        val registryOut = registryIn.copy(
            usedL1Ids = (registryIn.usedL1Ids - oldSubmissionId) + newSubmissionId
        )
        val newL1 = L1State(
            scopingId = scopingId,
            submissionId = newSubmissionId,
            payloadCommitment = newPayloadCommitment,
            linearId = RegistryUtils.l1LinearId(scopingId, newSubmissionId),
            participants = listOf(us)
        )

        val txBuilder = TransactionBuilder(notary)
            .addInputState(registryRef)
            .addInputState(oldL1Ref)
            .addReferenceState(l2Ref.referenced())
            .addOutputState(registryOut, TwoListContract.ID)
            .addOutputState(newL1, TwoListContract.ID)
            .addCommand(Command(TwoListContract.Commands.Replace(), us.owningKey))

        txBuilder.verify(serviceHub)
        val signedTx = serviceHub.signInitialTransaction(txBuilder)
        subFlow(FinalityFlow(signedTx, emptyList<FlowSession>()))

        return Result(
            countMatch = registryOut.l1Count == registryOut.l2Count,
            replaced = true,
            newSubmissionId = newSubmissionId
        )
    }
}
