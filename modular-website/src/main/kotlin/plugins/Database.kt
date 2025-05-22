package plugins

import org.jetbrains.exposed.sql.Database

fun configureDatabases() {
    Database.connect(
        "jdbc:postgresql://localhost:5432/Userdb",
        user = "postgres",
        password = "postgres"
    )
}