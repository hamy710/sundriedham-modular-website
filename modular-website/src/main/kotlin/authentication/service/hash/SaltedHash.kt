package authentication.service.hash

data class SaltedHash(
    val hash: String,
    val salt: String
)