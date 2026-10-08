cmake_minimum_required(VERSION 3.16)
project(cryptod_client VERSION 0.1.0 LANGUAGES CXX)

# OpenSSL
set(OPENSSL_ROOT_DIR "/usr/local/ssl")
set(OPENSSL_INCLUDE_DIR "/usr/local/ssl/include")
set(OPENSSL_CRYPTO_LIBRARY "/usr/local/ssl/lib64/libcrypto.so")
set(OPENSSL_SSL_LIBRARY "/usr/local/ssl/lib64/libssl.so")
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")

add_subdirectory(lib)
add_subdirectory(ossl_provider)
add_subdirectory(test)