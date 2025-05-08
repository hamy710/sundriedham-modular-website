package authentication.domain

import kotlinx.serialization.Serializable

@Serializable
data class RefreshAuthenticationRequest(val token: String)
