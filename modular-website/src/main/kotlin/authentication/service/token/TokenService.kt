package com.sundriedham.Authentication.token

import com.sundriedham.authentication.data.user.Identifier
import com.sundriedham.authentication.data.user.User
import com.sundriedham.request.AuthenticationResponse
import com.sundriedham.request.LoginCredentialsRequest
import com.sundriedham.request.RefreshAuthenticationRequest
import io.ktor.server.auth.jwt.*

interface TokenService {
    fun createAccessToken(user: User): String
    fun createRefreshToken(user: User): String
    fun validate(credential: JWTCredential): JWTPrincipal?
    fun verifyRefreshToken(token: String): Boolean
    fun userIDForRefreshToken(token: String): Identifier<User>?
}