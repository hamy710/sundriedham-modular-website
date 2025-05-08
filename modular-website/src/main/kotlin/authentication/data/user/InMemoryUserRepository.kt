package authentication.data.user

import java.util.*

class InMemoryUserRepository : UserRepository {
    private val demoUser = User(
        username = "demo",
        userid = Identifier<User>(UUID.randomUUID()),
        salt = "demo",
        password = "demo"
    )

    private val users: Map<Identifier<User>, User> = mapOf(
        Pair(demoUser.userid, demoUser)
    )

    private val usersByUsername: Map<String, User> = users
        .map { Pair(it.value.username, it.value) }
        .toMap()

    override suspend fun getUserByUserid(id: Identifier<User>): User? {
        return users[id]
    }

    override suspend fun getUserByUserName(username: String): User? {
        TODO("Not yet implemented")
    }

    override suspend fun insertUser(user: User): Boolean {
        TODO("Not yet implemented")
    }
}