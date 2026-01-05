# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

cmake_minimum_required(VERSION 3.16)
project(keystore LANGUAGES CXX)

add_library(${PROJECT_NAME} STATIC
    src/keystore.cpp
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${CRYPTOD_COMMON_INCLUDE}
)


target_link_libraries(${PROJECT_NAME}
    PUBLIC
    OpenSSL::Crypto
)

target_compile_options(${PROJECT_NAME} PRIVATE -Wno-deprecated-declarations)

