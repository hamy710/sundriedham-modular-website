package com.sundriedham.utils.networking

sealed class NetworkResult<out T, out Error> {
    class Success<T>(val response: T) : NetworkResult<T, Nothing>()
    class Failure<Error>(val error: Error) : NetworkResult<Nothing, Error>()
}