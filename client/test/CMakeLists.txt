cmake_minimum_required(VERSION 3.16)
project(cryptod_client_tests VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(GTest REQUIRED)

# Tests executable
add_executable(cryptod_client_tests
    src/test_main.cpp
    src/test_connection.cpp
    src/test_hash.cpp
    src/test_mac.cpp
    src/test_cipher.cpp
    src/test_kdf.cpp
    src/test_find_key.cpp
    src/test_ossl_mac.cpp
)

target_link_libraries(cryptod_client_tests 
    PRIVATE
        cryptod_client_lib
        GTest::gtest
        GTest::gtest_main
        OpenSSL::Crypto
)

# Enable testing
enable_testing()
add_test(NAME cryptod_client_tests COMMAND cryptod_client_tests)

# Install targets
install(TARGETS cryptod_client_tests
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/cryptod
    DESTINATION include
)
