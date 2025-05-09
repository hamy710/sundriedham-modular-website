package authentication.data.user

sealed class InsertUserResult {
    data object Success: InsertUserResult()
    data class SQLError(val cause:Throwable?): InsertUserResult()
    data object UnknownFailure: InsertUserResult()
}

interface UserRepository {
    suspend fun getUserByUserid(id: Identifier<User>): User?
    suspend fun getUserByUserName(username: String): User?
    suspend fun insertUser(user: User): InsertUserResult
}