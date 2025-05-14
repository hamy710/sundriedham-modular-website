package authentication.service.token

import authentication.data.user.Identifier
import authentication.data.user.User
import com.auth0.jwt.JWTVerifier
import io.ktor.server.auth.jwt.*

interface TokenService {
    fun getVerifier(): JWTVerifier
    fun createAccessToken(user: User): String
    fun createRefreshToken(user: User): String
    fun validate(credential: JWTCredential): JWTPrincipal?
    fun verifyRefreshToken(token: String): Boolean
    fun userIDForRefreshToken(token: String): Identifier<User>?
}