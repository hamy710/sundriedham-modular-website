package authentication.router

import authentication.data.user.User
import authentication.data.user.UserRepository
import authentication.service.hashing.HashService
import authentication.service.hashing.SaltedHash
import authentication.service.token.TokenService
import authentication.domain.AuthenticationResponse
import authentication.domain.LoginCredentialsRequest
import authentication.domain.RefreshAuthenticationRequest
import com.sundriedham.utils.networking.NetworkResult
import org.apache.commons.codec.digest.DigestUtils

sealed class AuthenticationRequestError {
    object UserNotFound: AuthenticationRequestError()
    object PasswordInvalid: AuthenticationRequestError()
}

sealed class AuthenticationRefreshError{
    object RefreshTokenInvalid: AuthenticationRefreshError()
    object UserNotFound: AuthenticationRefreshError()
    object UserIDNotFound: AuthenticationRefreshError()
}

class AuthenticationRouter(
    private val userRepository: UserRepository,
    private val hashingService: HashService,
    private val jwtTokenService: TokenService
) {

    suspend fun authenticateRefresh(request: RefreshAuthenticationRequest): NetworkResult<AuthenticationResponse, AuthenticationRefreshError>{
        val token = request.token
        if (!jwtTokenService.verifyRefreshToken(token)) {
            NetworkResult.Failure(AuthenticationRefreshError.RefreshTokenInvalid)
        }
        val userID = jwtTokenService.userIDForRefreshToken(token) ?:
        return NetworkResult.Failure(AuthenticationRefreshError.UserIDNotFound)

        val user = userRepository.getUserByUserid(userID) ?:
        return NetworkResult.Failure(AuthenticationRefreshError.UserNotFound)

        return NetworkResult.Success(createAuthenticationResponse(user))
    }

    suspend fun authenticate(request: LoginCredentialsRequest): NetworkResult<AuthenticationResponse, AuthenticationRequestError> {
        //read user from db
        val user = userRepository.getUserByUserName(request.username)
            ?: return NetworkResult.Failure(AuthenticationRequestError.UserNotFound)
        //validate password
        val isValidPassword = hashingService.verify(
            value = request.password,
            saltedHash = SaltedHash(
                hash = user.password,
                salt = user.salt
            )
        )
        if (!isValidPassword) {
            println("Entered hash: ${DigestUtils.sha256Hex("${user.salt}${user.password}")},Hashed password: ${user.password} ")
            return NetworkResult.Failure(AuthenticationRequestError.PasswordInvalid)
        }
        //generate token response
        return NetworkResult.Success(createAuthenticationResponse(user))
    }

    private fun createAuthenticationResponse(user: User): AuthenticationResponse =
        AuthenticationResponse(
            token = jwtTokenService.createAccessToken(user),
            refreshToken = jwtTokenService.createRefreshToken(user)
        )

}