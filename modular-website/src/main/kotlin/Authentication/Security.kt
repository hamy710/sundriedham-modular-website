package com.sundriedham.Authentication

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable

fun Application.configureSecurity(
    jwtService: JWTService,
) {
    authentication {
        jwt("auth-jwt") {
            realm = jwtService.realm
            verifier(jwtService.verifier)
            validate { credential -> jwtService.validate(credential) }
        }
    }
    routing {
        configureAuthRoutes(
            jwtService
        )
    }
}

private fun Routing.configureAuthRoutes(
    jwtService: JWTService
) {
    // "/auth/login, "/auth/refresh
    route("auth") {
        post("login") {
            val response = jwtService.authenticate(call.receive<LoginCredentialsRequest>())
            if (response == null) {
                call.respond(status = HttpStatusCode.Forbidden, message = "Failed to Authenticate")
            } else {
                call.respond(response)
            }
        }
        post("refresh") {
            val response = jwtService.authenticate(call.receive<RefreshAuthenticationRequest>())
            if (response == null) {
                call.respond(status = HttpStatusCode.Forbidden, message = "Refresh token is invalid")
            } else {
                call.respond(response)
            }
        }
        authenticate("auth-jwt") {
            get("/check") {
                val principal = call.principal<JWTPrincipal>()
                val username = principal!!.payload.getClaim("username").asString()
                val expiresAt = principal.expiresAt?.time?.minus(System.currentTimeMillis())
                call.respondText("Hello, $username! Token is expired at $expiresAt ms.")
            }
        }
    }
}

@Serializable
data class LoginCredentialsRequest(val username: String, val password: String)

@Serializable
data class AuthenticationResponse(val token: String, val refreshToken: String)

@Serializable
data class RefreshAuthenticationRequest(val token: String)