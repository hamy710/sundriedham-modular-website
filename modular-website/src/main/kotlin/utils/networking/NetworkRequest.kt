package com.sundriedham.utils.networking

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*

suspend inline fun <reified T : Any> ApplicationCall.safeReceiveOrNull(): T? {
    try {
        return receive<T>()
    } catch (e: ContentTransformationException) {
        respond(HttpStatusCode.BadRequest)
        return null
    }
}