# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

cmake_minimum_required(VERSION 3.10)
project(cryptod)

add_executable(${PROJECT_NAME}
    src/main.cpp
    src/crypto_daemon.cpp
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
    ${PROJECT_SOURCE_DIR}/../common/include
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
    keystore
    $<$<BOOL:${USE_RPC_SOCKET}>:socket_crypto_service>
    $<$<BOOL:${USE_RPC_CAPNP}>:capnp_crypto_service>
    $<$<BOOL:${USE_CRYPTO_BACKEND_OPENSSL}>:openssl_backend>
    $<$<BOOL:${USE_CRYPTO_BACKEND_DUMMY}>:dummy_backend>
)

target_compile_definitions(${PROJECT_NAME}
    PRIVATE
    $<$<BOOL:${USE_RPC_SOCKET}>:USE_RPC_SOCKET>
    $<$<BOOL:${USE_RPC_CAPNP}>:USE_RPC_CAPNP>
    $<$<BOOL:${USE_CRYPTO_BACKEND_OPENSSL}>:USE_CRYPTO_BACKEND_OPENSSL>
    $<$<BOOL:${USE_CRYPTO_BACKEND_DUMMY}>:USE_CRYPTO_BACKEND_DUMMY>
)

add_subdirectory(crypto_backend/ossl)
add_subdirectory(crypto_backend/dummy)
add_subdirectory(crypto_service/capnp_service)
add_subdirectory(crypto_service/socket_service)
add_subdirectory(keystore)
add_subdirectory(test)
