package authentication.data.user

import com.sundriedham.authentication.data.db.UserDAO
import com.sundriedham.authentication.data.db.UserTable
import com.sundriedham.authentication.data.db.daoToModel
import com.sundriedham.authentication.data.db.suspendTransaction
import org.jetbrains.exposed.sql.insert

class PostgresUserRepository : UserRepository {


    override suspend fun getUserByUserName(username: String): User? = suspendTransaction {
        UserDAO.Query.find (
            { UserTable.username eq username}
        ).limit(1)
            .map(::daoToModel)
            .firstOrNull()
    }

    override suspend fun insertUser(user: User): Boolean = suspendTransaction {
        val rowInsert = UserTable.insert {
            it[username] = user.username
            it[password] = user.password
            it[salt] = user.salt
            it[id] = user.userid.value
        }
        rowInsert.resultedValues?.isNotEmpty() ?: false
    }

    override suspend fun getUserByUserid(id: Identifier<User>): User? = suspendTransaction {
        UserDAO.Query.find(
            { UserTable.id eq id.value}
        ).limit(1)
            .map (::daoToModel)
            .firstOrNull()
    }
}