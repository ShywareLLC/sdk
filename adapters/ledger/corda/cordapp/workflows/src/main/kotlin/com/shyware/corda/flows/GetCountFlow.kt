package com.shyware.corda.flows

import co.paralleluniverse.fibers.Suspendable
import com.shyware.corda.states.ScopingRegistryState
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.StartableByRPC

/**
 * Read-only vault query -- no transaction, no notary round trip, no state change.
 * Mirrors getCount(scopingId) in the reference chaincode.
 */
@StartableByRPC
class GetCountFlow(private val scopingId: String) : FlowLogic<GetCountFlow.Result>() {

    data class Result(val scopingId: String, val l1Count: Int, val l2Count: Int, val countMatch: Boolean)

    @Suspendable
    override fun call(): Result {
        val registry: ScopingRegistryState? =
            findUnconsumedByLinearId(ScopingRegistryState::class.java, RegistryUtils.registryLinearId(scopingId))
                ?.state?.data

        return if (registry == null) {
            Result(scopingId = scopingId, l1Count = 0, l2Count = 0, countMatch = true)
        } else {
            Result(
                scopingId = scopingId,
                l1Count = registry.l1Count,
                l2Count = registry.l2Count,
                countMatch = registry.l1Count == registry.l2Count
            )
        }
    }
}
