package com.sundriedham.data.user

import java.util.*

class InMemoryUserRepository : UserRepository {
    private val demoUser = User(
        "demo",
        Identifier<User>(UUID.randomUUID()),
        "demo",
        "demo"
    )

    private val users: Map<Identifier<User>, User> = mapOf(
        Pair(demoUser.id, demoUser)
    )

    private val usersByUsername: Map<String, User> = users
        .map { Pair(it.value.username, it.value) }
        .toMap()

    override fun retrieveUser(id: Identifier<User>): User? {
        return users[id]
    }

    override fun retrieveUser(username: String, password: String): User? {
        return usersByUsername[username]?.let { user ->
            if (user.password == password) {
                user
            } else {
                null
            }
        }
    }
}