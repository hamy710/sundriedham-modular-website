package com.sundriedham.Authentication.token

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import com.fasterxml.jackson.databind.node.TextNode
import com.sundriedham.authentication.data.user.Identifier
import com.sundriedham.authentication.data.user.User
import io.ktor.server.auth.jwt.*
import java.util.*

class JwtTokenService (
    private val config: TokenConfig,
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

    override fun createAccessToken(user: User): String =
        createJWTToken(user, config.expiresIn, config.jwtAudience)

    override fun createRefreshToken(user: User): String =
        createJWTToken(user, config.expiresIn, config.refreshTokenAudience)

    override fun validate(credential: JWTCredential): JWTPrincipal? =
        if (credential.payload.audience.contains(config.jwtAudience))
            JWTPrincipal(credential.payload)
        else
            null

    override fun verifyRefreshToken(token: String): Boolean {
        val decodedJWT: DecodedJWT? = decodeRefreshJWT(token)

        return decodedJWT?.let {
            return it.audience.contains(config.refreshTokenAudience)
        } ?: false
    }

    override fun userIDForRefreshToken(token: String): Identifier<User>? =
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

    private fun createJWTToken(user: User, expireIn: Long, audience: String): String =
        JWT.create()
            .withAudience(audience)
            .withIssuer(config.issuer)
            .withClaim("username", user.username)
            .withClaim("userID", user.userid.toString())
            .withExpiresAt(Date(System.currentTimeMillis() + expireIn))
            .sign(Algorithm.HMAC256(config.secret))

    private fun decodeRefreshJWT(token: String): DecodedJWT? =
        try {
            refreshVerifier.verify(token)
        } catch (ex: Exception) {
            null
        }

}