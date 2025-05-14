package authentication.service.hash

import org.apache.commons.codec.binary.Hex
import org.apache.commons.codec.digest.DigestUtils
import java.security.SecureRandom

class DefaultHashService : HashService {
    override fun generateSaltHash(value: String, saltLength: Int): SaltedHash {
        val salt = SecureRandom
            .getInstance("SHA1PRNG")
            .generateSeed(saltLength)
            .run(Hex::encodeHexString)
        val hash = DigestUtils.sha256Hex("$salt$value")
        return SaltedHash(
            hash = hash,
            salt = salt
        )
    }

    override fun verify(value: String, saltedHash: SaltedHash): Boolean {
        return DigestUtils.sha256Hex(saltedHash.salt + value) == saltedHash.hash
    }
}