package authentication.service.hashing

interface HashService {
    fun generateSaltHash(
        value: String,
        saltLength: Int = 32,
    ): SaltedHash
    fun verify(value: String, saltedHash: SaltedHash):Boolean
}