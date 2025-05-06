package com.sundriedham.Authentication.token

data class TokenConfig (
    val secret: String,
    val issuer: String,
    val jwtAudience: String,
    val refreshTokenAudience :String,
    val expiresIn: Long
)