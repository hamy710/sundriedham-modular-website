package com.sundriedham.plugins

import com.sundriedham.Authentication.token.JwtTokenService
import com.sundriedham.configureAuthRoutes
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.routing.*

fun Application.configureSecurity(
    jwtTokenService: JwtTokenService,
) {
    authentication {
        jwt("auth-jwt") {
            realm = this@configureSecurity.environment.config.property("jwt.realm").getString()
            verifier(jwtTokenService.verifier)
            validate { credential -> jwtTokenService.validate(credential) }
        }
    }
    routing {
        configureAuthRoutes(
            jwtTokenService
        )
    }
}




