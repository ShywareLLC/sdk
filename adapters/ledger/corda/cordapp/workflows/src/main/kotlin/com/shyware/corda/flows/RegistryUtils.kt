package com.shyware.corda.flows

import co.paralleluniverse.fibers.Suspendable
import net.corda.core.contracts.LinearState
import net.corda.core.contracts.StateAndRef
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.flows.FlowLogic
import net.corda.core.node.services.Vault
import net.corda.core.node.services.vault.QueryCriteria
import java.util.UUID

/**
 * Every flow that touches a scopingId's registry needs to find its current unconsumed
 * version (or create it, for the very first submission). Deterministic linearId derived
 * from the scopingId means every node resolving this scopingId converges on the same
 * external id, without any node having to broadcast "here is the registry's UUID."
 */
object RegistryUtils {

    fun registryLinearId(scopingId: String): UniqueIdentifier =
        UniqueIdentifier(externalId = "shyware-registry:$scopingId", id = UUID.nameUUIDFromBytes(
            "shyware-registry:$scopingId".toByteArray(Charsets.UTF_8)
        ))

    fun l1LinearId(scopingId: String, submissionId: String): UniqueIdentifier =
        UniqueIdentifier(externalId = "shyware-l1:$scopingId:$submissionId", id = UUID.nameUUIDFromBytes(
            "shyware-l1:$scopingId:$submissionId".toByteArray(Charsets.UTF_8)
        ))

    fun l2LinearId(scopingId: String, identityHash: String): UniqueIdentifier =
        UniqueIdentifier(externalId = "shyware-l2:$scopingId:$identityHash", id = UUID.nameUUIDFromBytes(
            "shyware-l2:$scopingId:$identityHash".toByteArray(Charsets.UTF_8)
        ))

    fun periodCloseLinearId(scopingId: String): UniqueIdentifier =
        UniqueIdentifier(externalId = "shyware-close:$scopingId", id = UUID.nameUUIDFromBytes(
            "shyware-close:$scopingId".toByteArray(Charsets.UTF_8)
        ))
}

/**
 * Local (non-consensus) helper for looking up an unconsumed StateAndRef by linearId.
 * Used by flows to build transactions; the actual uniqueness guarantee comes from the
 * contract + notary, not from this lookup (which is inherently racy across nodes, as
 * any vault query is -- it only needs to be "good enough to build a plausible tx").
 */
@Suspendable
fun <T : LinearState> FlowLogic<*>.findUnconsumedByLinearId(
    contractStateType: Class<T>,
    linearId: UniqueIdentifier
): StateAndRef<T>? {
    val criteria = QueryCriteria.LinearStateQueryCriteria(
        linearId = listOf(linearId),
        status = Vault.StateStatus.UNCONSUMED
    )
    return serviceHub.vaultService.queryBy(contractStateType, criteria).states.singleOrNull()
}
