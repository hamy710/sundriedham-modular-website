package com.sundriedham.authentication.data.user

interface UserRepository {
    suspend fun getUserByUserid(id: Identifier<User>): User?
    suspend fun getUserByUserName(username: String): User?
    suspend fun insertUser(user: User): Boolean
}