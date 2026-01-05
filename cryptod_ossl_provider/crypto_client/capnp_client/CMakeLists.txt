# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

cmake_minimum_required(VERSION 3.16)
project(capnp_crypto_client LANGUAGES CXX)

set(CAPNPC_SRC_PREFIX "${CRYPTOD_PROTOCOL}" CACHE STRING "" FORCE)
set(CAPNPC_OUTPUT_DIR "${PROJECT_SOURCE_DIR}/src" CACHE STRING "" FORCE)
capnp_generate_cpp(CAPNP_SOURCES CAPNP_HEADERS ${CRYPTOD_PROTOCOL}/crypto.capnp)


add_library(${PROJECT_NAME} STATIC
    src/crypto_client.cpp
    ${CAPNP_SOURCES}
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${CRYPTOD_COMMON_INCLUDE}
)

target_link_libraries(${PROJECT_NAME} PRIVATE CapnProto::capnp-rpc)

set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)
