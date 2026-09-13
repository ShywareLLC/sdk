package com.shyware.corda.flows

import co.paralleluniverse.fibers.Suspendable
import com.shyware.corda.contracts.TwoListContract
import com.shyware.corda.states.L1State
import com.shyware.corda.states.L2State
import com.shyware.corda.states.ScopingRegistryState
import net.corda.core.contracts.Command
import net.corda.core.contracts.StateAndRef
import net.corda.core.flows.FinalityFlow
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.FlowSession
import net.corda.core.flows.InitiatingFlow
import net.corda.core.flows.StartableByRPC
import net.corda.core.transactions.TransactionBuilder
import net.corda.core.utilities.ProgressTracker

/**
 * @return the same result shape the Fabric chaincode's submitTwoListWrite returns:
 * { scopingId, l1Count, l2Count, countMatch }, plus the Corda transaction id under `txId`
 * so callers (and the JS adapter) have a receipt to point at.
 */
@InitiatingFlow
@StartableByRPC
class SubmitTwoListWriteFlow(
    private val scopingId: String,
    private val submissionId: String,
    private val payloadCommitment: String,
    private val identityHash: String
) : FlowLogic<SubmitTwoListWriteFlow.Result>() {

    data class Result(
        val txId: String,
        val scopingId: String,
        val l1Count: Int,
        val l2Count: Int,
        val countMatch: Boolean
    )

    override val progressTracker = ProgressTracker()

    @Suspendable
    override fun call(): Result {
        require(submissionId.isNotBlank()) { "submissionId must not be empty" }
        require(payloadCommitment.isNotBlank()) { "payloadCommitment must not be empty" }
        require(identityHash.isNotBlank()) { "identityHash must not be empty" }

        val notary = serviceHub.networkMapCache.notaryIdentities.first()
        val us = ourIdentity

        val registryLinearId = RegistryUtils.registryLinearId(scopingId)
        val existingRegistry: StateAndRef<ScopingRegistryState>? =
            findUnconsumedByLinearId(ScopingRegistryState::class.java, registryLinearId)

        val registryIn: ScopingRegistryState = existingRegistry?.state?.data
            ?: ScopingRegistryState(
                scopingId = scopingId,
                usedL1Ids = emptySet(),
                usedL2Ids = emptySet(),
                l1Count = 0,
                l2Count = 0,
                closed = false,
                linearId = registryLinearId,
                participants = listOf(us)
            )

        // Client-side pre-checks give a fast, friendly failure; the contract re-checks
        // everything below unconditionally, so these are optimizations, not the guarantee.
        require(!registryIn.closed) { "scopingId is closed" }
        require(TwoListContract.sha256Hex(submissionId) != identityHash) {
            "rejection predicate violated: sha256(submissionId) == identityHash"
        }
        require(!registryIn.usedL2Ids.contains(identityHash)) { "identityHash already registered for this scopingId" }
        require(!registryIn.usedL1Ids.contains(submissionId)) { "submissionId already exists for this scopingId" }

        val registryOut = registryIn.copy(
            usedL1Ids = registryIn.usedL1Ids + submissionId,
            usedL2Ids = registryIn.usedL2Ids + identityHash,
            l1Count = registryIn.l1Count + 1,
            l2Count = registryIn.l2Count + 1
        )

        val l1 = L1State(
            scopingId = scopingId,
            submissionId = submissionId,
            payloadCommitment = payloadCommitment,
            linearId = RegistryUtils.l1LinearId(scopingId, submissionId),
            participants = listOf(us)
        )
        val l2 = L2State(
            scopingId = scopingId,
            identityHash = identityHash,
            linearId = RegistryUtils.l2LinearId(scopingId, identityHash),
            participants = listOf(us)
        )

        val txBuilder = TransactionBuilder(notary)
        if (existingRegistry != null) {
            txBuilder.addInputState(existingRegistry)
        } else {
            // First submission for this scopingId: nothing to consume yet. The notary's
            // uniqueness guarantee kicks in from the SECOND submission onward, once a
            // consumable registry state exists to serialize writers against.
        }
        txBuilder
            .addOutputState(registryOut, TwoListContract.ID)
            .addOutputState(l1, TwoListContract.ID)
            .addOutputState(l2, TwoListContract.ID)
            .addCommand(Command(TwoListContract.Commands.Submit(), us.owningKey))

        txBuilder.verify(serviceHub)
        val signedTx = serviceHub.signInitialTransaction(txBuilder)
        val finalizedTx = subFlow(FinalityFlow(signedTx, emptyList<FlowSession>()))

        return Result(
            txId = finalizedTx.id.toString(),
            scopingId = scopingId,
            l1Count = registryOut.l1Count,
            l2Count = registryOut.l2Count,
            countMatch = registryOut.l1Count == registryOut.l2Count
        )
    }
}
