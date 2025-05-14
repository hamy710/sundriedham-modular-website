package plugins

import authentication.data.user.UserRepository
import authentication.service.hash.HashService
import authentication.service.token.TokenService
import com.sundriedham.authentication.configureAuthRoutes
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.routing.*

fun Application.configureSecurity(
    tokenService: TokenService,
    userRepository: UserRepository,
    hashingService: HashService
) {
    authentication {
        jwt("auth-jwt") {
            realm = this@configureSecurity.environment.config.property("jwt.realm").getString()
            verifier(tokenService.getVerifier())
            validate { credential -> tokenService.validate(credential) }
        }
    }
    routing {
        configureAuthRoutes(
            tokenService = tokenService,
            userRepository = userRepository,
            hashService = hashingService
        )
    }
}




