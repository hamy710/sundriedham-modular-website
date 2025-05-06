package com.sundriedham

import com.sundriedham.Authentication.token.JwtTokenService
import com.sundriedham.request.LoginCredentialsRequest
import com.sundriedham.request.RefreshAuthenticationRequest
import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Routing.configureAuthRoutes(
    jwtTokenService: JwtTokenService
) {
    // "/auth/login, "/auth/refresh
    route("auth") {
        post("login") {
            val response = jwtTokenService.authenticate(call.receive<LoginCredentialsRequest>())
            if (response == null) {
                call.respond(status = HttpStatusCode.Forbidden, message = "Failed to Authenticate")
            } else {
                call.respond(response)
            }
        }
        post("refresh") {
            val response = jwtTokenService.authenticate(call.receive<RefreshAuthenticationRequest>())
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

