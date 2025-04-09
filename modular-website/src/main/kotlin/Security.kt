package com.sundriedham

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import java.util.*

// TODO: Read from config file/environment variables
// Please read the jwt property from the config file if you are using EngineMain
const val jwtAudience = "jwt-audience"
const val jwtDomain = "https://jwt-provider-domain/"
const val jwtRealm = "ktor sample app"
const val jwtSecret = "secret"


fun Application.configureSecurity() {
    authentication {
        jwt("auth-jwt") {
            realm = jwtRealm
            verifier(
                JWT
                    .require(Algorithm.HMAC256(jwtSecret))
                    .withAudience(jwtAudience)
                    .withIssuer(jwtDomain)
                    .build()
            )
            validate { credential ->
                if (credential.payload.audience.contains(jwtAudience)) JWTPrincipal(credential.payload) else null
            }
        }
    }
    routing {
        configureAuthRoutes()
    }
}

private fun Routing.configureAuthRoutes() {
    route("auth") {
        post("login") {
            val credentials = call.receive<LoginCredentialsRequest>()
            if (credentials.username == "demo" && credentials.password == "demo") {
                val token = JWT.create()
                    .withAudience(jwtAudience)
                    .withIssuer(jwtDomain)
                    .withClaim("username", credentials.username)
                    .withExpiresAt(Date(System.currentTimeMillis() + 60000))
                    .sign(Algorithm.HMAC256(jwtSecret))
                call.respond(AuthenticationResponse(
                    token = token,
                    refreshToken = "Not Implemented" // TODO:
                ))
            } else {
                call.respond(status = HttpStatusCode.Forbidden, message = "Failed to Authenticate")
            }
        }
        post("refresh") {
            call.respond(HttpStatusCode.NotImplemented, "Not Implemented")
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