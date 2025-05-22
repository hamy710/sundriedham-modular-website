package authentication.domain

import kotlinx.serialization.Serializable

@Serializable
data class LoginCredentialsRequest(val username: String, val password: String)
