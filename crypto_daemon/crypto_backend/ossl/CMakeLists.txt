# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

cmake_minimum_required(VERSION 3.10)
project(openssl_backend LANGUAGES CXX)

find_package(OpenSSL REQUIRED)

add_library(${PROJECT_NAME} STATIC
    src/ossl_hmac.cpp
    src/ossl_ecdsa.cpp
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CRYPTOD_COMMON_INCLUDE}
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC
    OpenSSL::Crypto
)

target_compile_options(${PROJECT_NAME} PRIVATE -Wno-deprecated-declarations)


add_subdirectory(test)
