package com.shyware.corda.flows

import co.paralleluniverse.fibers.Suspendable
import com.shyware.corda.contracts.TwoListContract
import com.shyware.corda.states.PeriodCloseState
import com.shyware.corda.states.ScopingRegistryState
import net.corda.core.contracts.Command
import net.corda.core.flows.FinalityFlow
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.FlowSession
import net.corda.core.flows.InitiatingFlow
import net.corda.core.flows.StartableByRPC
import net.corda.core.transactions.TransactionBuilder
import net.corda.core.utilities.ProgressTracker
import java.time.Instant

/**
 * One-time-only period-close record for a scopingId; rejects if already closed
 * (contract-enforced: ScopingRegistryState.closed must be false going in, true coming out,
 * and the registry's linearId can only be consumed once per closed transition).
 */
@InitiatingFlow
@StartableByRPC
class CommitPeriodCloseFlow(
    private val scopingId: String,
    private val l1MerkleRoot: String,
    private val l2MerkleRoot: String,
    private val attestation: String
) : FlowLogic<CommitPeriodCloseFlow.Result>() {

    data class Result(val txId: String, val timestamp: String)

    override val progressTracker = ProgressTracker()

    @Suspendable
    override fun call(): Result {
        val notary = serviceHub.networkMapCache.notaryIdentities.first()
        val us = ourIdentity

        val registryRef = findUnconsumedByLinearId(ScopingRegistryState::class.java, RegistryUtils.registryLinearId(scopingId))
            ?: throw IllegalArgumentException("no registry exists for scopingId=$scopingId")
        val registryIn = registryRef.state.data

        require(!registryIn.closed) { "scopingId is already closed" }
        require(l1MerkleRoot.isNotBlank()) { "l1MerkleRoot must not be empty" }
        require(l2MerkleRoot.isNotBlank()) { "l2MerkleRoot must not be empty" }
        require(attestation.isNotBlank()) { "attestation must not be empty" }

        val registryOut = registryIn.copy(closed = true)
        val timestamp = Instant.now().toString()
        val close = PeriodCloseState(
            scopingId = scopingId,
            l1MerkleRoot = l1MerkleRoot,
            l2MerkleRoot = l2MerkleRoot,
            attestation = attestation,
            l1Count = registryIn.l1Count,
            l2Count = registryIn.l2Count,
            timestamp = timestamp,
            linearId = RegistryUtils.periodCloseLinearId(scopingId),
            participants = listOf(us)
        )

        val txBuilder = TransactionBuilder(notary)
            .addInputState(registryRef)
            .addOutputState(registryOut, TwoListContract.ID)
            .addOutputState(close, TwoListContract.ID)
            .addCommand(Command(TwoListContract.Commands.CommitPeriodClose(), us.owningKey))

        txBuilder.verify(serviceHub)
        val signedTx = serviceHub.signInitialTransaction(txBuilder)
        val finalizedTx = subFlow(FinalityFlow(signedTx, emptyList<FlowSession>()))

        return Result(txId = finalizedTx.id.toString(), timestamp = timestamp)
    }
}
