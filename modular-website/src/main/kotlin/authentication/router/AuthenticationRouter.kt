package authentication.router

import authentication.data.user.Identifier
import authentication.data.user.InsertUserResult
import authentication.data.user.User
import authentication.data.user.UserRepository
import authentication.service.hash.HashService
import authentication.service.hash.SaltedHash
import authentication.service.token.TokenService
import authentication.domain.AuthenticationResponse
import authentication.domain.LoginCredentialsRequest
import authentication.domain.RefreshAuthenticationRequest
import com.sundriedham.utils.networking.NetworkResult
import org.apache.commons.codec.digest.DigestUtils
import java.util.*

sealed class AuthenticationRequestError {
    data object UserNotFound : AuthenticationRequestError()
    data object PasswordInvalid : AuthenticationRequestError()
}

sealed class AuthenticationRefreshError {
    data object RefreshTokenInvalid : AuthenticationRefreshError()
    data object UserNotFound : AuthenticationRefreshError()
    data object UserIDNotFound : AuthenticationRefreshError()
}

sealed class AuthenticateSignInError {
    data object InvalidInput : AuthenticateSignInError()
    data object DatabaseError : AuthenticateSignInError()
    data object UnknownError : AuthenticateSignInError()
}

class AuthenticationRouter(
    private val userRepository: UserRepository,
    private val hashService: HashService,
    private val tokenService: TokenService
) {
    suspend fun authenticateSignup(request: LoginCredentialsRequest): NetworkResult<Unit, AuthenticateSignInError> {
        //check valid username and password
        if (request.username.isBlank()
            || request.password.isBlank()
        ) {
            return NetworkResult.Failure(AuthenticateSignInError.InvalidInput)
        }
        //Encode password
        val hashedPassword = hashService.generateSaltHash(request.password)
        val user = User(
            username = request.username,
            password = hashedPassword.hash,
            salt = hashedPassword.salt,
            userid = Identifier(UUID.randomUUID())
        )
        //Insert to db
        return when (userRepository.insertUser(user)) {
            is InsertUserResult.SQLError ->
                NetworkResult.Failure(AuthenticateSignInError.DatabaseError)

            is InsertUserResult.Success ->
                NetworkResult.Success(Unit)

            is InsertUserResult.UnknownFailure ->
                NetworkResult.Failure(AuthenticateSignInError.UnknownError)
        }
    }

    suspend fun authenticate(request: LoginCredentialsRequest): NetworkResult<AuthenticationResponse, AuthenticationRequestError> {
        //read user from db
        val user = userRepository.getUserByUserName(request.username)
            ?: return NetworkResult.Failure(AuthenticationRequestError.UserNotFound)
        //validate password
        val isValidPassword = hashService.verify(
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

    suspend fun authenticateRefresh(request: RefreshAuthenticationRequest): NetworkResult<AuthenticationResponse, AuthenticationRefreshError> {
        val token = request.refreshToken
        if (!tokenService.verifyRefreshToken(token)) {
            NetworkResult.Failure(AuthenticationRefreshError.RefreshTokenInvalid)
        }

        val userID = tokenService.userIDForRefreshToken(token) ?: return NetworkResult.Failure(
            AuthenticationRefreshError.UserIDNotFound
        )

        val user = userRepository.getUserByUserid(userID)
            ?: return NetworkResult.Failure(AuthenticationRefreshError.UserNotFound)

        return NetworkResult.Success(createAuthenticationResponse(user))
    }

    private fun createAuthenticationResponse(user: User): AuthenticationResponse =
        AuthenticationResponse(
            token = tokenService.createAccessToken(user),
            refreshToken = tokenService.createRefreshToken(user)
        )
}