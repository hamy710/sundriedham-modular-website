package com.sundriedham.Authentication

import java.util.*

data class User(
    val name: String,
    val id: Identifier<User>,
    val username: String,
    // TODO: Gotta bcrypt it and is there a cool way to enforce that?
    val password: String
)

data class Identifier<Entity>(
    val value: UUID
) {
    override fun toString(): String =
        value.toString()
}

interface UserRepository {
    fun retrieveUser(id: Identifier<User>): User?

    fun retrieveUser(username: String, password: String): User?
}