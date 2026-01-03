# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

find_package(GTest REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(test_ossl_backend
    main.cpp
)

target_link_libraries(test_ossl_backend
    PRIVATE
    openssl_backend
    OpenSSL::Crypto
    GTest::gtest_main
)

set_target_properties(test_ossl_backend PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)

include(GoogleTest)
gtest_discover_tests(test_ossl_backend
    TEST_EXECUTABLE ${CMAKE_BINARY_DIR}/tests/test_ossl_backend
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
