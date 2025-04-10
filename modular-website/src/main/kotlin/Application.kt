package com.sundriedham

import com.sundriedham.Authentication.InMemoryUserRepository
import com.sundriedham.Authentication.JWTService
import com.sundriedham.Authentication.configureSecurity
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*

fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0", module = Application::module)
        .start(wait = true)
}

fun Application.module() {
    val userRepository = InMemoryUserRepository()
    val jwtService = JWTService(this, userRepository)

    configureSecurity(jwtService = jwtService)
    configureRouting()
    // TODO: Refactor into another place
    install(ContentNegotiation) {
        json()
    }
}
