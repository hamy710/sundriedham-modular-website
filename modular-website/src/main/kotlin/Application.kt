package com.sundriedham

import authentication.data.user.DefaultUserRepository
import authentication.service.hash.DefaultHashService
import authentication.service.token.DefaultTokenService
import authentication.service.token.TokenConfig
import plugins.configureDatabases
import plugins.configureSecurity
import plugins.configureRouting
import plugins.configureSerialization
import io.ktor.server.application.*
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

    configureDatabases()
    val userRepository = DefaultUserRepository()
    val hashingService = DefaultHashService()
    val tokenService = DefaultTokenService(tokenConfig)

    configureSecurity(tokenService, userRepository, hashingService)
    configureRouting()
    configureSerialization()

}
