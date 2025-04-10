package com.sundriedham.Authentication

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable

fun Application.configureSecurity() {
    val jwtService = JWTService(this)
    authentication {
        jwt("auth-jwt") {
            realm = jwtService.realm
            verifier(jwtService.verifier)
            validate { credential -> jwtService.validate(credential) }
        }
    }
    routing {
        configureAuthRoutes(jwtService)
    }
}

private fun Routing.configureAuthRoutes(jwtService: JWTService) {
    route("auth") {
        post("login") {
            val credentials = call.receive<LoginCredentialsRequest>()
            if (credentials.username == "demo" && credentials.password == "demo") {
                val username = "demo"
                call.respond(
                    AuthenticationResponse(
                        token = jwtService.createAccessToken(username),
                        refreshToken = jwtService.createRefreshToken(username)
                    )
                )
            } else {
                call.respond(status = HttpStatusCode.Forbidden, message = "Failed to Authenticate")
            }
        }
        post("refresh") {
            val refreshRequest = call.receive<RefreshAuthenticationRequest>()
            val username = jwtService.userNameForToken(refreshRequest.token)
            if (jwtService.verifyRefreshToken(refreshRequest.token) && username != null) {
                call.respond(
                    AuthenticationResponse(
                        token = jwtService.createAccessToken(username),
                        refreshToken = jwtService.createRefreshToken(username)
                    )
                )
            } else {
                call.respond(status = HttpStatusCode.Forbidden, message = "Refresh token is invalid")
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