package com.sundriedham.Authentication

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import com.fasterxml.jackson.databind.node.TextNode
import io.ktor.server.application.*
import io.ktor.server.auth.jwt.*
import java.util.*

class JWTService(
    private val application: Application,
    private val userRepository: UserRepository
) {
    // TODO: Read from config
    private val jwtAudience = "jwt-audience"
    private val refreshTokenAudience = "sundriedham-refresh"
    private val jwtIssuer = "https://jwt-provider-domain/"
    val realm = "ktor sample app"
    private val jwtSecret = "secret"

    val verifier: JWTVerifier = JWT
        .require(Algorithm.HMAC256(jwtSecret))
        .withAudience(jwtAudience)
        .withIssuer(jwtIssuer)
        .build()

    val refreshVerifier: JWTVerifier = JWT
        .require(Algorithm.HMAC256(jwtSecret))
        .withAudience(refreshTokenAudience)
        .withIssuer(jwtIssuer)
        .build()

    private fun createAccessToken(user: User): String =
        createJWTToken(user, 3_600_000, jwtAudience)

    private fun createRefreshToken(user: User): String =
        createJWTToken(user, 86_400_000, refreshTokenAudience)

    private fun createJWTToken(user: User, expireIn: Int, audience: String): String =
        JWT.create()
            .withAudience(audience)
            .withIssuer(jwtIssuer)
            .withClaim("username", user.username)
            .withClaim("userID", user.id.toString())
            .withExpiresAt(Date(System.currentTimeMillis() + expireIn))
            .sign(Algorithm.HMAC256(jwtSecret))

    fun authenticate(request: LoginCredentialsRequest): AuthenticationResponse? =
        userRepository
            .retrieveUser(request.username, request.password)
            ?.let(::createAuthenticationResponse)

    fun authenticate(request: RefreshAuthenticationRequest): AuthenticationResponse? =
        if (verifyRefreshToken(request.token)) {
            userIDForRefreshToken(request.token)
                ?.let(userRepository::retrieveUser)
                ?.let(::createAuthenticationResponse)
        } else {
            null
        }

    private fun createAuthenticationResponse(user: User): AuthenticationResponse =
        AuthenticationResponse(
            token = createAccessToken(user),
            refreshToken = createRefreshToken(user)
        )

    fun validate(credential: JWTCredential): JWTPrincipal? =
        if (credential.payload.audience.contains(jwtAudience))
            JWTPrincipal(credential.payload)
        else
            null


    private fun verifyRefreshToken(token: String): Boolean {
        val decodedJWT: DecodedJWT? = decodeRefreshJWT(token)

        return decodedJWT?.let {
            return it.audience.contains(refreshTokenAudience)
        } ?: false
    }

    private fun userIDForRefreshToken(token: String): Identifier<User>? =
        if (verifyRefreshToken(token)) {
            decodeRefreshJWT(token)
                ?.claims
                ?.get("userID")
                ?.`as`(TextNode::class.java) // If we use `.toString` directly Java inserts an extra set of quotes with causes the UUID conversion to fail
                ?.asText()
                ?.let(UUID::fromString)
                ?.let(::Identifier)
        } else {
            null
        }


    private fun decodeRefreshJWT(token: String): DecodedJWT? =
        try {
            refreshVerifier.verify(token)
        } catch (ex: Exception) {
            null
        }

}