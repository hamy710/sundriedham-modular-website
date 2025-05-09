package authentication.data.user

import java.util.*

data class Identifier<T>(
    val value: UUID
) {
    override fun toString(): String =
        value.toString()
}