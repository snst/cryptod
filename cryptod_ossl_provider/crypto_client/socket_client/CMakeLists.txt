# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

cmake_minimum_required(VERSION 3.16)
project(socket_crypto_client LANGUAGES CXX)


add_library(${PROJECT_NAME} STATIC
    src/socket_crypto_client.cpp
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${CRYPTOD_COMMON_INCLUDE}
)

set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)
