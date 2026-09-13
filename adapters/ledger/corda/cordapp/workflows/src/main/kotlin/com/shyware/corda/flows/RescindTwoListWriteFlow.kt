package com.shyware.corda.flows

import co.paralleluniverse.fibers.Suspendable
import com.shyware.corda.contracts.TwoListContract
import com.shyware.corda.states.L1State
import com.shyware.corda.states.L2State
import com.shyware.corda.states.ScopingRegistryState
import net.corda.core.contracts.Command
import net.corda.core.flows.FinalityFlow
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.FlowSession
import net.corda.core.flows.InitiatingFlow
import net.corda.core.flows.StartableByRPC
import net.corda.core.transactions.TransactionBuilder
import net.corda.core.utilities.ProgressTracker

/**
 * Participant-initiated withdrawal: atomically delete L1 + L2 for a submission,
 * decrement count. No co-authorization required (mirrors reference chaincode's
 * rescindTwoListWrite -- no dual-key check on the ledger side of this adapter;
 * any two-party threshold policy lives at the caller/authority layer above this).
 */
@InitiatingFlow
@StartableByRPC
class RescindTwoListWriteFlow(
    private val scopingId: String,
    private val submissionId: String,
    private val identityHash: String
) : FlowLogic<RescindTwoListWriteFlow.Result>() {

    data class Result(val countMatch: Boolean, val rescinded: Boolean)

    override val progressTracker = ProgressTracker()

    @Suspendable
    override fun call(): Result {
        val notary = serviceHub.networkMapCache.notaryIdentities.first()
        val us = ourIdentity

        val registryRef = findUnconsumedByLinearId(ScopingRegistryState::class.java, RegistryUtils.registryLinearId(scopingId))
            ?: throw IllegalArgumentException("no registry exists for scopingId=$scopingId")
        val registryIn = registryRef.state.data

        val l1Ref = findUnconsumedByLinearId(L1State::class.java, RegistryUtils.l1LinearId(scopingId, submissionId))
            ?: throw IllegalArgumentException("no L1State found for submissionId=$submissionId")
        val l2Ref = findUnconsumedByLinearId(L2State::class.java, RegistryUtils.l2LinearId(scopingId, identityHash))
            ?: throw IllegalArgumentException("no L2State found for identityHash=$identityHash")

        require(!registryIn.closed) { "scopingId is closed" }
        require(registryIn.usedL1Ids.contains(submissionId)) { "submissionId not registered" }
        require(registryIn.usedL2Ids.contains(identityHash)) { "identityHash not registered" }

        val registryOut = registryIn.copy(
            usedL1Ids = registryIn.usedL1Ids - submissionId,
            usedL2Ids = registryIn.usedL2Ids - identityHash,
            l1Count = registryIn.l1Count - 1,
            l2Count = registryIn.l2Count - 1
        )

        val txBuilder = TransactionBuilder(notary)
            .addInputState(registryRef)
            .addInputState(l1Ref)
            .addInputState(l2Ref)
            .addOutputState(registryOut, TwoListContract.ID)
            .addCommand(Command(TwoListContract.Commands.Rescind(), us.owningKey))

        txBuilder.verify(serviceHub)
        val signedTx = serviceHub.signInitialTransaction(txBuilder)
        subFlow(FinalityFlow(signedTx, emptyList<FlowSession>()))

        return Result(countMatch = registryOut.l1Count == registryOut.l2Count, rescinded = true)
    }
}
