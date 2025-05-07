package com.sundriedham.Authentication.token

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import com.fasterxml.jackson.databind.node.TextNode
import com.sundriedham.Authentication.hashing.HashService
import com.sundriedham.Authentication.hashing.SaltedHash
import com.sundriedham.data.user.Identifier
import com.sundriedham.data.user.User
import com.sundriedham.data.user.UserRepository
import com.sundriedham.request.AuthenticationResponse
import com.sundriedham.request.LoginCredentialsRequest
import com.sundriedham.request.RefreshAuthenticationRequest
import io.ktor.server.auth.jwt.*
import kotlinx.coroutines.runBlocking
import java.util.*

class JwtTokenService (
    private val userRepository: UserRepository,
    private val config: TokenConfig,
    private val hashingService: HashService,
) : TokenService{
    val verifier: JWTVerifier = JWT
        .require(Algorithm.HMAC256(config.secret))
        .withAudience(config.jwtAudience)
        .withIssuer(config.issuer)
        .build()

    val refreshVerifier: JWTVerifier = JWT
        .require(Algorithm.HMAC256(config.secret))
        .withAudience(config.refreshTokenAudience)
        .withIssuer(config.issuer)
        .build()

    override suspend fun authenticate(request: LoginCredentialsRequest): AuthenticationResponse? {
        val user = userRepository.getUserByUserName(request.username) ?: return null
//        val isValid = hashingService.varify(
//            value = request.password,
//            saltedHash = SaltedHash(
//                hash = user.password,
//                salt = user.salt
//            )
//        )
//        if (!isValid) return null
        return createAuthenticationResponse(user)
    }



    override suspend fun authenticate(request: RefreshAuthenticationRequest): AuthenticationResponse? {
        if (verifyRefreshToken(request.token)) {
            val userID = userIDForRefreshToken(request.token) ?: return null
            val user = userRepository.getUserByUserid(userID) ?: return null
            return createAuthenticationResponse(user)
        } else {
            return null
        }
    }

    // TODO: Should be moved into AuthenticationRouter
    private fun createAuthenticationResponse(user: User): AuthenticationResponse =
        AuthenticationResponse(
            token = createAccessToken(user),
            refreshToken = createRefreshToken(user)
        )
    override fun validate(credential: JWTCredential): JWTPrincipal? =
        if (credential.payload.audience.contains(config.jwtAudience))
            JWTPrincipal(credential.payload)
        else
            null

    fun createAccessToken(user: User): String =
        createJWTToken(user, config.expiresIn, config.jwtAudience)

    fun createRefreshToken(user: User): String =
        createJWTToken(user, config.expiresIn, config.refreshTokenAudience)

    private fun createJWTToken(user: User, expireIn: Long, audience: String): String =
        JWT.create()
            .withAudience(audience)
            .withIssuer(config.issuer)
            .withClaim("username", user.username)
            .withClaim("userID", user.userid.toString())
            .withExpiresAt(Date(System.currentTimeMillis() + expireIn))
            .sign(Algorithm.HMAC256(config.secret))



    private fun verifyRefreshToken(token: String): Boolean {
        val decodedJWT: DecodedJWT? = decodeRefreshJWT(token)

        return decodedJWT?.let {
            return it.audience.contains(config.refreshTokenAudience)
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