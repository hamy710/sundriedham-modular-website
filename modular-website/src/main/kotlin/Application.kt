package com.sundriedham

import com.sundriedham.data.user.InMemoryUserRepository
import com.sundriedham.Authentication.token.JwtTokenService
import com.sundriedham.Authentication.token.TokenConfig
import com.sundriedham.plugins.configureSecurity
import com.sundriedham.plugins.configureRouting
import com.sundriedham.plugins.configureSerialization
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*

fun main(args: Array<String>) {
    EngineMain.main(args)
}


fun Application.module() {
    val tokenConfig = TokenConfig(
        secret = System.getenv("JWT_SECRET"),
        issuer = environment.config.property("jwt.issuer").getString(),
        jwtAudience = environment.config.property("jwt.jwtAudience").getString(),
        refreshTokenAudience = environment.config.property("jwt.refreshTokenAudience").getString(),
        expiresIn = 3_600_000L

    )
    val userRepository = InMemoryUserRepository()
    val jwtTokenService = JwtTokenService(userRepository, tokenConfig)


    configureSecurity(jwtTokenService = jwtTokenService)
    configureRouting()
    configureSerialization()

}
