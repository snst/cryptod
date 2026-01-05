# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

cmake_minimum_required(VERSION 3.16)
project(MyProject VERSION 1.0 LANGUAGES CXX)

enable_testing()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(USE_RPC_SOCKET OFF)
set(USE_RPC_CAPNP ON)

set(USE_CRYPTO_BACKEND_OPENSSL ON)
set(USE_CRYPTO_BACKEND_DUMMY OFF)


#set(OPENSSL_USE_STATIC_LIBS ON)

set(OPENSSL_ROOT_DIR "/usr/local/ssl")
set(OPENSSL_INCLUDE_DIR "/usr/local/ssl/include")
set(OPENSSL_CRYPTO_LIBRARY "/usr/local/ssl/lib64/libcrypto.so")
set(OPENSSL_SSL_LIBRARY "/usr/local/ssl/lib64/libssl.so")
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")

find_package(CapnProto CONFIG REQUIRED)

set(CRYPTOD_COMMON_INCLUDE ${PROJECT_SOURCE_DIR}/common/include)
set(CRYPTOD_PROTOCOL ${PROJECT_SOURCE_DIR}/common/protocol)

add_subdirectory(cryptod_ossl_provider)
add_subdirectory(crypto_daemon)
add_subdirectory(keystore_cli)
add_subdirectory(test/benchmark)
