package com.sundriedham.request

import kotlinx.serialization.Serializable

@Serializable
data class RefreshAuthenticationRequest(val token: String)
