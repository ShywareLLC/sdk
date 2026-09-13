package com.shyware.corda.webserver

import net.corda.client.rpc.CordaRPCClient
import net.corda.client.rpc.CordaRPCConnection
import net.corda.core.messaging.CordaRPCOps
import net.corda.core.utilities.NetworkHostAndPort
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import javax.annotation.PostConstruct
import javax.annotation.PreDestroy

/**
 * Thin wrapper around CordaRPCClient. This IS the "mature first-party Node client" gap
 * this task calls out: Corda's own Node RPC client library (`corda-rpc`) is JVM-only,
 * so there is no equivalent of `fabric-network` or `@algorandfoundation/algosdk` to
 * `npm install` from JS. This Spring Boot service is the bridge -- it holds the one
 * long-lived RPC connection to the node, and the JS adapter (corda.js) talks to this
 * over plain HTTP instead of talking RPC directly.
 */
@Component
class NodeRpcConnection(
    @Value("\${config.rpc.host}") private val host: String,
    @Value("\${config.rpc.username}") private val username: String,
    @Value("\${config.rpc.password}") private val password: String,
    @Value("\${config.rpc.port}") private val rpcPort: Int
) {
    lateinit var proxy: CordaRPCOps
    private lateinit var rpcConnection: CordaRPCConnection

    @PostConstruct
    fun initialiseNodeRPCConnection() {
        val rpcAddress = NetworkHostAndPort(host, rpcPort)
        val rpcClient = CordaRPCClient(rpcAddress)
        rpcConnection = rpcClient.start(username, password)
        proxy = rpcConnection.proxy
    }

    @PreDestroy
    fun closeNodeRPCConnection() {
        rpcConnection.notifyServerAndClose()
    }
}
