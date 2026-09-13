package com.shyware.corda.webserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class WebserverApplication

fun main(args: Array<String>) {
    runApplication<WebserverApplication>(*args)
}
