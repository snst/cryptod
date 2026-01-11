# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

cmake_minimum_required(VERSION 3.10)
project(test_hmac_concurrent)

find_package(GTest REQUIRED)
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
    GTest::gtest_main
)


set_target_properties(test_hmac_concurrent PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)

include(GoogleTest)
gtest_discover_tests(test_hmac_concurrent
    TEST_EXECUTABLE ${CMAKE_BINARY_DIR}/tests/test_hmac_concurrent
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
