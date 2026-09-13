package com.shyware.corda.flows

import net.corda.core.utilities.getOrThrow
import net.corda.testing.driver.DriverParameters
import net.corda.testing.driver.driver
import net.corda.testing.node.TestCordapp
import net.corda.testing.node.User
import org.junit.Test
import java.security.MessageDigest
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Corda's `driver` test framework spins up a real (in-process) network of node
 * processes + notary and drives them over the same RPC surface a production client
 * would use. This is the load-bearing verification for this CorDapp: unlike a unit
 * test against the contract class directly, this actually exercises FinalityFlow,
 * notarisation, and vault persistence end-to-end for every operation.
 */
class TwoListFlowTests {

    private fun sha256Hex(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    private val rpcUser = User("shyware", "test", permissions = setOf("ALL"))

    @Test
    fun `submit twice, get count, rescind, replace, and close a period, all notary-enforced`() {
        driver(DriverParameters(isDebug = true, startNodesInProcess = true,
            cordappsForAllNodes = listOf(
                TestCordapp.findCordapp("com.shyware.corda.contracts"),
                TestCordapp.findCordapp("com.shyware.corda.flows")
            ))) {
            val operator = startNode(providedName = null, rpcUsers = listOf(rpcUser)).getOrThrow()
            val rpc = operator.rpc

            val scopingId = "poll-${UUID.randomUUID()}"

            // -- First submission: no registry exists yet to consume. --
            val sub1 = "sub-${UUID.randomUUID()}"
            val identity1 = sha256Hex("voter-1:$scopingId")
            val r1 = rpc.startFlowDynamic(
                SubmitTwoListWriteFlow::class.java, scopingId, sub1, "payload-commitment-1", identity1
            ).returnValue.getOrThrow()
            assertEquals(1, r1.l1Count)
            assertEquals(1, r1.l2Count)
            assertTrue(r1.countMatch)

            // -- Second submission: this one DOES consume + reissue the registry, so it is
            //    the notary that is refusing to let a stale/duplicate registry version be
            //    spent twice, not merely an application-side check. --
            val sub2 = "sub-${UUID.randomUUID()}"
            val identity2 = sha256Hex("voter-2:$scopingId")
            val r2 = rpc.startFlowDynamic(
                SubmitTwoListWriteFlow::class.java, scopingId, sub2, "payload-commitment-2", identity2
            ).returnValue.getOrThrow()
            assertEquals(2, r2.l1Count)
            assertEquals(2, r2.l2Count)
            assertTrue(r2.countMatch)

            // -- getCount is a pure vault read, no new transaction. --
            val count = rpc.startFlowDynamic(GetCountFlow::class.java, scopingId).returnValue.getOrThrow()
            assertEquals(2, count.l1Count)
            assertEquals(2, count.l2Count)
            assertTrue(count.countMatch)

            // -- Rejection predicate: sha256(submissionId) == identityHash must be refused
            //    by the CONTRACT (every node that resolves the transaction re-checks this;
            //    it is not the JS client's responsibility to have behaved). --
            val poisonSub = "poison-${UUID.randomUUID()}"
            val poisonIdentity = sha256Hex(poisonSub)
            assertFailsWith<Exception> {
                rpc.startFlowDynamic(
                    SubmitTwoListWriteFlow::class.java, scopingId, poisonSub, "payload", poisonIdentity
                ).returnValue.getOrThrow()
            }

            // -- Sybil resistance: same identityHash twice for the same scopingId is refused. --
            assertFailsWith<Exception> {
                rpc.startFlowDynamic(
                    SubmitTwoListWriteFlow::class.java, scopingId, "sub-${UUID.randomUUID()}", "payload", identity1
                ).returnValue.getOrThrow()
            }

            // -- Replay protection: same submissionId twice for the same scopingId is refused. --
            assertFailsWith<Exception> {
                rpc.startFlowDynamic(
                    SubmitTwoListWriteFlow::class.java, scopingId, sub1, "payload", sha256Hex("voter-3:$scopingId")
                ).returnValue.getOrThrow()
            }

            // -- Replace: new L1, L2 (and its count) untouched. --
            val sub1b = "sub-${UUID.randomUUID()}"
            val replaceResult = rpc.startFlowDynamic(
                ReplaceTwoListWriteFlow::class.java, scopingId, sub1, sub1b, "payload-commitment-1b", identity1
            ).returnValue.getOrThrow()
            assertTrue(replaceResult.replaced)
            assertEquals(sub1b, replaceResult.newSubmissionId)
            val countAfterReplace = rpc.startFlowDynamic(GetCountFlow::class.java, scopingId).returnValue.getOrThrow()
            assertEquals(2, countAfterReplace.l1Count)
            assertEquals(2, countAfterReplace.l2Count)

            // -- Rescind: delete both L1 + L2, decrement count. --
            val rescindResult = rpc.startFlowDynamic(
                RescindTwoListWriteFlow::class.java, scopingId, sub1b, identity1
            ).returnValue.getOrThrow()
            assertTrue(rescindResult.rescinded)
            assertTrue(rescindResult.countMatch)
            val countAfterRescind = rpc.startFlowDynamic(GetCountFlow::class.java, scopingId).returnValue.getOrThrow()
            assertEquals(1, countAfterRescind.l1Count)
            assertEquals(1, countAfterRescind.l2Count)

            // -- Period close: one-time-only, disjoint roots. --
            val closeResult = rpc.startFlowDynamic(
                CommitPeriodCloseFlow::class.java, scopingId, "l1root-abc", "l2root-def", "sig-xyz"
            ).returnValue.getOrThrow()
            assertTrue(closeResult.txId.isNotBlank())

            // -- Closing twice must fail (one-time-only). --
            assertFailsWith<Exception> {
                rpc.startFlowDynamic(
                    CommitPeriodCloseFlow::class.java, scopingId, "l1root-2", "l2root-2", "sig-2"
                ).returnValue.getOrThrow()
            }

            // -- No further submissions after close. --
            assertFailsWith<Exception> {
                rpc.startFlowDynamic(
                    SubmitTwoListWriteFlow::class.java, scopingId, "sub-${UUID.randomUUID()}", "payload",
                    sha256Hex("voter-4:$scopingId")
                ).returnValue.getOrThrow()
            }
        }
    }
}
