package com.sundriedham.data.user



data class User(
    val name: String,
    val id: Identifier<User>,
    val username: String,
    // TODO: Gotta bcrypt it and is there a cool way to enforce that?
    val password: String
)