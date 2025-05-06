package com.sundriedham.data.user

interface UserRepository {
    fun retrieveUser(id: Identifier<User>): User?
    fun retrieveUser(username: String, password: String): User?
}