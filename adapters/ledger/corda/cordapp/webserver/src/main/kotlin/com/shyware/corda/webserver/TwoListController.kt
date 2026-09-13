package com.shyware.corda.webserver

import com.shyware.corda.flows.CommitPeriodCloseFlow
import com.shyware.corda.flows.GetCountFlow
import com.shyware.corda.flows.RescindTwoListWriteFlow
import com.shyware.corda.flows.SubmitTwoListWriteFlow
import com.shyware.corda.flows.ReplaceTwoListWriteFlow
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

/**
 * REST bridge for corda.js. Every mutating endpoint starts the corresponding flow via
 * CordaRPCOps.startFlowDynamic and blocks on returnValue.getOrThrow() before responding
 * -- the HTTP response only comes back once the flow (and its FinalityFlow notarisation)
 * has actually completed, matching the "trigger the flow and wait for it to complete"
 * requirement for the JS adapter.
 */
@RestController
class TwoListController(private val rpc: NodeRpcConnection) {

    data class SubmitRequest(val scopingId: String, val submissionId: String, val payloadCommitment: String, val identityHash: String)
    data class RescindRequest(val scopingId: String, val submissionId: String, val identityHash: String)
    data class ReplaceRequest(val scopingId: String, val oldSubmissionId: String, val newSubmissionId: String, val newPayloadCommitment: String, val identityHash: String)
    data class PeriodCloseRequest(val scopingId: String, val l1MerkleRoot: String, val l2MerkleRoot: String, val attestation: String)

    @PostMapping("/two-list/submit")
    fun submit(@RequestBody req: SubmitRequest): ResponseEntity<Any> = wrap {
        rpc.proxy.startFlowDynamic(
            SubmitTwoListWriteFlow::class.java,
            req.scopingId, req.submissionId, req.payloadCommitment, req.identityHash
        ).returnValue.getOrThrow()
    }

    @GetMapping("/two-list/count/{scopingId}")
    fun getCount(@PathVariable scopingId: String): ResponseEntity<Any> = wrap {
        rpc.proxy.startFlowDynamic(GetCountFlow::class.java, scopingId).returnValue.getOrThrow()
    }

    @PostMapping("/two-list/rescind")
    fun rescind(@RequestBody req: RescindRequest): ResponseEntity<Any> = wrap {
        rpc.proxy.startFlowDynamic(
            RescindTwoListWriteFlow::class.java, req.scopingId, req.submissionId, req.identityHash
        ).returnValue.getOrThrow()
    }

    @PostMapping("/two-list/replace")
    fun replace(@RequestBody req: ReplaceRequest): ResponseEntity<Any> = wrap {
        rpc.proxy.startFlowDynamic(
            ReplaceTwoListWriteFlow::class.java,
            req.scopingId, req.oldSubmissionId, req.newSubmissionId, req.newPayloadCommitment, req.identityHash
        ).returnValue.getOrThrow()
    }

    @PostMapping("/two-list/period-close")
    fun periodClose(@RequestBody req: PeriodCloseRequest): ResponseEntity<Any> = wrap {
        rpc.proxy.startFlowDynamic(
            CommitPeriodCloseFlow::class.java, req.scopingId, req.l1MerkleRoot, req.l2MerkleRoot, req.attestation
        ).returnValue.getOrThrow()
    }

    private fun wrap(block: () -> Any): ResponseEntity<Any> {
        return try {
            ResponseEntity.ok(block())
        } catch (e: Exception) {
            // Surface the contract/flow rejection reason (e.g. "rejection predicate
            // violated...") to the caller rather than swallowing it as a bare 500.
            ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to (e.message ?: e.toString())))
        }
    }
}
