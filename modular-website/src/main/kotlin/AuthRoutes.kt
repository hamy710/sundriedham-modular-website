package com.sundriedham

import com.sundriedham.Authentication.hashing.HashService
import com.sundriedham.Authentication.hashing.SaltedHash
import com.sundriedham.Authentication.token.JwtTokenService
import com.sundriedham.data.user.User
import com.sundriedham.data.user.UserRepository
import com.sundriedham.request.AuthenticationResponse
import com.sundriedham.request.LoginCredentialsRequest
import com.sundriedham.request.RefreshAuthenticationRequest
import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.apache.commons.codec.digest.DigestUtils

sealed class NetworkResult<out T, out Error> {
    class Success<T>(val response: T): NetworkResult<T, Nothing>()
    class Failure<Error>(val error: Error): NetworkResult<Nothing, Error>()
}

sealed class AuthenticationRequestError {
    object UserNotFound: AuthenticationRequestError()
    object PasswordInvalid: AuthenticationRequestError()
}

class AuthenticationRouter(
    private val userRepository: UserRepository,
    private val hashingService: HashService,
    private val jwtTokenService: JwtTokenService
) {
    suspend fun authenticate(request: LoginCredentialsRequest): NetworkResult<AuthenticationResponse, AuthenticationRequestError> {
        //read user from db
        val user = userRepository.getUserByUserName(request.username)
        if (user == null) {
            return NetworkResult.Failure(AuthenticationRequestError.UserNotFound)
        }
        //validate password
        val isValidPassword = hashingService.verify(
            value = request.password,
            saltedHash = SaltedHash(
                hash = user.password,
                salt = user.salt
            )
        )
        if (!isValidPassword) {
            println("Entered hash: ${DigestUtils.sha256Hex("${user.salt}${user.password}")},Hashed password: ${user.password} ")
            return NetworkResult.Failure(AuthenticationRequestError.PasswordInvalid)
        }
        //generate token response
        return NetworkResult.Success(createAuthenticationResponse(user))
    }

    private fun createAuthenticationResponse(user: User): AuthenticationResponse =
        AuthenticationResponse(
            token = jwtTokenService.createAccessToken(user),
            refreshToken = jwtTokenService.createRefreshToken(user)
        )

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
        post("signin") {
            val request =
                kotlin.runCatching { call.receiveNullable<LoginCredentialsRequest>() }.getOrNull() ?: kotlin.run {
                    call.respond(HttpStatusCode.BadRequest)
                    return@post
                }

            val result = router.authenticate(request)
            when (result) {
                is NetworkResult.Failure<AuthenticationRequestError> -> when (result.error) {
                    AuthenticationRequestError.PasswordInvalid ->
                        call.respond(HttpStatusCode.Conflict, "Incorrect username or password")
                    AuthenticationRequestError.UserNotFound ->
                        call.respond(HttpStatusCode.Conflict, "Incorrect username or password")
                }
                is NetworkResult.Success<AuthenticationResponse> ->
                    call.respond(HttpStatusCode.OK, result.response)
            }

            //read user from db
            val user = userRepository.getUserByUserName(request.username)
            if (user == null) {
                call.respond(HttpStatusCode.Conflict, "Incorrect username or password")
                return@post
            }
            //validate password
            val isValidPassword = hashingService.verify(
                value = request.password,
                saltedHash = SaltedHash(
                    hash = user.password,
                    salt = user.salt
                )
            )
            if (!isValidPassword) {
                println("Entered hash: ${DigestUtils.sha256Hex("${user.salt}${user.password}")},Hashed password: ${user.password} ")
                call.respond(HttpStatusCode.Conflict, "Incorrect username or password")
                return@post
            }
            //generate token response
            val response = jwtTokenService.authenticate(request) ?: return@post
            //give response
            call.respond(
                status = HttpStatusCode.OK,
                message = response
            )
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

