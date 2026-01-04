# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

cmake_minimum_required(VERSION 3.16)
project(MyProject VERSION 1.0 LANGUAGES CXX)

enable_testing()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(CapnProto CONFIG REQUIRED)

set(CRYPTOD_COMMON_INCLUDE ${PROJECT_SOURCE_DIR}/common/include)
set(CRYPTOD_PROTOCOL ${PROJECT_SOURCE_DIR}/common/protocol)

add_subdirectory(cryptod_ossl_provider)
add_subdirectory(crypto_daemon)
add_subdirectory(keystore_cli)
add_subdirectory(test/benchmark)
