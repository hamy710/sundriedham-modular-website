package plugins

import authentication.data.user.UserRepository
import authentication.service.hashing.HashService
import authentication.service.token.JwtTokenService
import com.sundriedham.authentication.configureAuthRoutes
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.routing.*

fun Application.configureSecurity(
    jwtTokenService: JwtTokenService,
    userRepository: UserRepository,
    hashingService: HashService
) {
    authentication {
        jwt("auth-jwt") {
            realm = this@configureSecurity.environment.config.property("jwt.realm").getString()
            verifier(jwtTokenService.verifier)
            validate { credential -> jwtTokenService.validate(credential) }
        }
    }
    routing {
        configureAuthRoutes(
            jwtTokenService = jwtTokenService,
            userRepository = userRepository,
            hashingService = hashingService
        )
    }
}




