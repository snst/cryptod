# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

cmake_minimum_required(VERSION 3.10)
project(hmac_benchmark)

find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME}
    src/main.cpp
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
        ${CRYPTOD_COMMON_INCLUDE}
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        OpenSSL::Crypto
)
