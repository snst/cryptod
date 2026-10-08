cmake_minimum_required(VERSION 3.16)
project(cryptod_client_lib VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


# Find dependencies
find_package(Protobuf REQUIRED)

# Generate protobuf C++ code
set(PROTO_FILES ${CMAKE_SOURCE_DIR}/../proto/crypto_api.proto)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})

# Include generated headers
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# Client library
add_library(cryptod_client_lib SHARED
    src/client.cpp
    src/connection.cpp
    src/hash.cpp
    src/mac.cpp
    src/cipher.cpp
    ${PROTO_SRCS}
)

target_include_directories(cryptod_client_lib 
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(cryptod_client_lib 
    PRIVATE 
        protobuf::libprotobuf
)

set_target_properties(cryptod_client_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Install targets
install(TARGETS cryptod_client_lib
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/cryptod
    DESTINATION include
)
