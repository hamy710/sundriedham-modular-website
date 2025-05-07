package com.sundriedham.data.db

import com.sundriedham.data.user.Identifier
import com.sundriedham.data.user.User
import kotlinx.coroutines.Dispatchers
import org.jetbrains.exposed.dao.UUIDEntity
import org.jetbrains.exposed.dao.UUIDEntityClass
import org.jetbrains.exposed.dao.id.EntityID
import org.jetbrains.exposed.dao.id.UUIDTable
import org.jetbrains.exposed.sql.Transaction
import org.jetbrains.exposed.sql.transactions.experimental.newSuspendedTransaction
import java.util.*

object UserTable: UUIDTable("usertable"){
    val username = varchar("username", 64)
    val password = varchar("password", 64)
    val salt = varchar("salt", 64)
}

class UserDAO(userid: EntityID<UUID>): UUIDEntity(userid){
    object Query: UUIDEntityClass<UserDAO>(UserTable)
    var username by UserTable.username
    var password by UserTable.password
    var salt by UserTable.salt
}

fun daoToModel(dao: UserDAO) = User(
    username = dao.username,
    password = dao.password,
    salt = dao.salt,
    userid = Identifier(dao.id.value)
)

suspend fun <T> suspendTransaction(block: Transaction.() -> T) : T = newSuspendedTransaction (
    Dispatchers.IO, statement = block
)