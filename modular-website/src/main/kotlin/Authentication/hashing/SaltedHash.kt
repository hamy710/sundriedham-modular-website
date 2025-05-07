package com.sundriedham.Authentication.hashing

data class SaltedHash (
    val hash: String,
    val salt: String
)