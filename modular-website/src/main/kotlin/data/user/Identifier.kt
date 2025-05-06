package com.sundriedham.data.user

import java.util.*

data class Identifier<Entity>(
    val value: UUID
) {
    override fun toString(): String =
        value.toString()
}