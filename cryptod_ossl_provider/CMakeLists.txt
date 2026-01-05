# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

cmake_minimum_required(VERSION 3.16)
project(crypto_daemon_openssl_provider LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(${PROJECT_NAME}
    SHARED
    src/cdp_hmac.c
    src/cryptod_provider.c
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC
    $<$<BOOL:${USE_RPC_SOCKET}>:socket_crypto_client>
    $<$<BOOL:${USE_RPC_CAPNP}>:capnp_crypto_client>
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
    ${CRYPTOD_COMMON_INCLUDE}
)

set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME cryptod_provider)

set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_subdirectory(crypto_client/capnp_client)
add_subdirectory(crypto_client/socket_client)
