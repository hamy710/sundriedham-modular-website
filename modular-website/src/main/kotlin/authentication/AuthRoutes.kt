package com.sundriedham.authentication

import authentication.data.user.UserRepository
import authentication.service.hashing.HashService
import authentication.service.token.JwtTokenService
import authentication.router.AuthenticationRouter
import authentication.router.AuthenticationRequestError
import authentication.router.AuthenticationRefreshError
import authentication.domain.AuthenticationResponse
import authentication.domain.LoginCredentialsRequest
import authentication.domain.RefreshAuthenticationRequest
import com.sundriedham.utils.networking.NetworkResult
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*


suspend inline fun <reified T: Any> ApplicationCall.safeReceiveOrNull(): T? {
    try {
        return receive<T>()
    } catch (e: ContentTransformationException){
        respond(HttpStatusCode.BadRequest)
        return null
    }
}

fun Routing.configureAuthRoutes(
    jwtTokenService: JwtTokenService,
    userRepository: UserRepository,
    hashingService: HashService
) {
    val router = AuthenticationRouter(
        userRepository,
        hashingService,
        jwtTokenService
    )

    // "/auth/login, "/auth/refresh
    route("auth") {
        post("login") {
            val request = call.safeReceiveOrNull<LoginCredentialsRequest>() ?: return@post
            when (val result = router.authenticate(request)) {
                is NetworkResult.Failure<AuthenticationRequestError> -> when (result.error) {
                    AuthenticationRequestError.PasswordInvalid ->
                        call.respond(HttpStatusCode.Conflict, "Incorrect username or password")
                    AuthenticationRequestError.UserNotFound ->
                        call.respond(HttpStatusCode.Conflict, "Incorrect username or password")
                }
                is NetworkResult.Success<AuthenticationResponse> ->
                    call.respond(HttpStatusCode.OK, result.response)
            }
        }

        post("refresh") {
            val request = call.safeReceiveOrNull<RefreshAuthenticationRequest>() ?: return@post
            when(val result = router.authenticateRefresh(request)){
                is NetworkResult.Failure<AuthenticationRefreshError> -> when(result.error){
                    AuthenticationRefreshError.RefreshTokenInvalid,
                    AuthenticationRefreshError.UserIDNotFound,
                    AuthenticationRefreshError.UserNotFound ->
                        call.respond(HttpStatusCode.Conflict,"Refresh token Invalid")
                }
                is NetworkResult.Success<AuthenticationResponse> ->
                    call.respond(HttpStatusCode.OK, result.response)
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

