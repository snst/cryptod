# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

find_package(GTest REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(test_keystore
    main.cpp
)

target_include_directories(test_keystore
    PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(test_keystore
    PRIVATE
    keystore
    OpenSSL::Crypto
    GTest::gtest_main
)

set_target_properties(test_keystore PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)

include(GoogleTest)
gtest_discover_tests(test_keystore
    TEST_EXECUTABLE ${CMAKE_BINARY_DIR}/tests/test_keystore
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
