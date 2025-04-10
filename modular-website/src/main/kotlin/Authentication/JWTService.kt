package com.sundriedham.Authentication

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import io.ktor.server.application.*
import io.ktor.server.auth.jwt.*
import java.util.*

class JWTService(
    private val application: Application
) {
    // TODO: Read from config
    private val jwtAudience = "jwt-audience"
    private val jwtIssuer = "https://jwt-provider-domain/"
    val realm = "ktor sample app"
    private val jwtSecret = "secret"

    val verifier: JWTVerifier = JWT
        .require(Algorithm.HMAC256(jwtSecret))
        .withAudience(jwtAudience)
        .withIssuer(jwtIssuer)
        .build()

    fun createAccessToken(username: String): String =
        createJWTToken(username, 3_600_000)

    fun createRefreshToken(username: String): String =
        createJWTToken(username, 86_400_000)

    private fun createJWTToken(username: String, expireIn: Int): String =
        JWT.create()
            .withAudience(jwtAudience)
            .withIssuer(jwtIssuer)
            .withClaim("username", username)
            .withExpiresAt(Date(System.currentTimeMillis() + expireIn))
            .sign(Algorithm.HMAC256(jwtSecret))

    fun validate(credential: JWTCredential): JWTPrincipal? =
        if (credential.payload.audience.contains(jwtAudience))
            JWTPrincipal(credential.payload)
        else
            null


    fun verifyRefreshToken(token: String): Boolean {
        val decodedJWT: DecodedJWT? = getDecodedJWT(token)

        return decodedJWT?.let {
            return it.audience.contains(jwtAudience)
        } ?: false
    }

    fun userNameForToken(token: String): String? =
        if (verifyRefreshToken(token)) {
            getDecodedJWT(token)?.claims?.get("username").toString()
        } else {
            null
        }


    private fun getDecodedJWT(token: String): DecodedJWT? =
        try {
            verifier.verify(token)
        } catch (ex: Exception) {
            null
        }

}