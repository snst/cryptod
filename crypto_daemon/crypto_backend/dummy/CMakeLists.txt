# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

cmake_minimum_required(VERSION 3.10)
project(dummy_backend LANGUAGES CXX)

add_library(${PROJECT_NAME} STATIC
    src/dummy_hmac.cpp
    src/dummy_ecdsa.cpp
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CRYPTOD_COMMON_INCLUDE}
)
