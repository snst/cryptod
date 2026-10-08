# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

cmake_minimum_required(VERSION 3.16)
project(cryptod_ossl_provider LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(${PROJECT_NAME}
    SHARED
    src/cdp_hmac_mac.cpp
    src/cdp_cryptod_keymgmt.cpp
    src/cdp_cryptod_store.cpp
    src/cdp_tls1_prf.cpp
    src/cdp_common.cpp
    src/cryptod_provider.cpp
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        cryptod_client_lib
)

set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME cryptod_provider)

set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)
