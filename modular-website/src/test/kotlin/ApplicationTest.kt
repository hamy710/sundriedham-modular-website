package com.sundriedham

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.testing.*
import kotlin.test.Test
import kotlin.test.assertEquals

private fun myTestApplication(block: suspend (HttpClient) -> Unit) {
    testApplication {
        application { module() }
        block(createTestClient())
    }
}

private fun ApplicationTestBuilder.createTestClient(): HttpClient {
    return createClient {
        install(ContentNegotiation) {
            json()
        }
    }
}

class ApplicationTest {

    @Test
    fun testRoot() = myTestApplication { client ->
        client.get("/").apply {
            assertEquals(HttpStatusCode.OK, status)
        }
    }

    @Test
    fun testLogin() = myTestApplication { client ->
        client.post("/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginCredentialsRequest("demo", "demo"))
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
        }
    }

    @Test
    fun testRefreshToken() = myTestApplication { client ->
        val response: AuthenticationResponse = client.post("/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginCredentialsRequest("demo", "demo"))
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
        }.body()

        client.post("/auth/refresh") {
            contentType(ContentType.Application.Json)
            setBody(RefreshAuthenticationRequest(response.refreshToken))
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
        }
    }


}
