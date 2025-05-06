package com.sundriedham.Authentication.token

import com.sundriedham.request.AuthenticationResponse
import com.sundriedham.request.LoginCredentialsRequest
import com.sundriedham.request.RefreshAuthenticationRequest
import io.ktor.server.auth.jwt.*

interface TokenService {
    fun authenticate(request: LoginCredentialsRequest): AuthenticationResponse?
    fun authenticate(request: RefreshAuthenticationRequest): AuthenticationResponse?
    fun validate(credential: JWTCredential): JWTPrincipal?
}