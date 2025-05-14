package authentication.data.user

import com.sundriedham.authentication.data.db.UserDAO
import com.sundriedham.authentication.data.db.UserTable
import com.sundriedham.authentication.data.db.daoToModel
import com.sundriedham.authentication.data.db.suspendTransaction
import org.jetbrains.exposed.exceptions.ExposedSQLException
import org.jetbrains.exposed.sql.insert

class DefaultUserRepository : UserRepository {
    override suspend fun getUserByUserName(username: String): User? = suspendTransaction {
        UserDAO.Query.find { UserTable.username eq username }
            .limit(1)
            .map(::daoToModel)
            .firstOrNull()
    }

    override suspend fun insertUser(user: User): InsertUserResult = suspendTransaction {
            try {
                UserTable.insert {
                    it[username] = user.username
                    it[password] = user.password
                    it[salt] = user.salt
                    it[id] = user.userid.value
                }
                InsertUserResult.Success
            } catch (e: ExposedSQLException) {
                InsertUserResult.SQLError(e.cause)
            } catch (e: Error) {
                InsertUserResult.UnknownFailure(e.cause)
            }
    }

    override suspend fun getUserByUserid(id: Identifier<User>): User? = suspendTransaction {
        UserDAO.Query.find { UserTable.id eq id.value }
            .limit(1)
            .map(::daoToModel)
            .firstOrNull()
    }
}