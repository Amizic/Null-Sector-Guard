cmake_minimum_required(VERSION 3.20)

project(NullSectorGuard VERSION 1.0.0 LANGUAGES CXX)

option(BUILD_SHARED_LIBS "Build Null-Sector Guard as a shared library" OFF)
option(NSG_BUILD_TESTS "Build Null-Sector Guard mini tests" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)

add_library(NullSectorGuard
    src/AES256.cpp
    src/RSA4096.cpp
    src/MLKEM1024.cpp
    src/KeyDerivation.cpp
)

add_library(NullSectorGuard::NullSectorGuard ALIAS NullSectorGuard)

set(NSG_OUTPUT_DIR "${CMAKE_BINARY_DIR}/output")

set_target_properties(NullSectorGuard PROPERTIES
    OUTPUT_NAME "Null-Sector-Guard"
    POSITION_INDEPENDENT_CODE ON
    RUNTIME_OUTPUT_DIRECTORY "${NSG_OUTPUT_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${NSG_OUTPUT_DIR}"
    ARCHIVE_OUTPUT_DIRECTORY "${NSG_OUTPUT_DIR}"
)

foreach(NSG_CONFIG Debug Release RelWithDebInfo MinSizeRel)
    string(TOUPPER "${NSG_CONFIG}" NSG_CONFIG_UPPER)
    set_target_properties(NullSectorGuard PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_${NSG_CONFIG_UPPER} "${NSG_OUTPUT_DIR}"
        LIBRARY_OUTPUT_DIRECTORY_${NSG_CONFIG_UPPER} "${NSG_OUTPUT_DIR}"
        ARCHIVE_OUTPUT_DIRECTORY_${NSG_CONFIG_UPPER} "${NSG_OUTPUT_DIR}"
    )
endforeach()

target_include_directories(NullSectorGuard
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(NullSectorGuard
    PUBLIC
        OpenSSL::Crypto
)

if(BUILD_SHARED_LIBS)
    target_compile_definitions(NullSectorGuard
        PUBLIC NSG_SHARED_LIBRARY
        PRIVATE NSG_BUILDING_LIBRARY
    )
endif()

if(MSVC)
    target_compile_options(NullSectorGuard PRIVATE /W4 /permissive-)
else()
    target_compile_options(NullSectorGuard PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(NSG_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
