package com.sundriedham.authentication.data.user


data class User(
    val username: String,
    val password: String,
    val salt: String,
    val userid: Identifier<User>,
)