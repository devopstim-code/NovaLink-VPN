cmake_minimum_required(VERSION 3.20)
project(NovaLink-VPN LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../bin)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

find_path(LIBOQS_INCLUDE_DIR NAMES oqs/oqs.h)
find_library(LIBOQS_LIBRARY NAMES oqs)

if(NOT LIBOQS_INCLUDE_DIR OR NOT LIBOQS_LIBRARY)
 message(FATAL_ERROR "liboqs not found! Please run 'sudo ninja install' in liboqs folder.")
else()
 message(STATUS "Found liboqs: ${LIBOQS_LIBRARY}")
endif()

set(LIBOQS_LIBRARY ${LIBOQS_LIBRARY} CACHE INTERNAL "")
set(LIBOQS_INCLUDE_DIR ${LIBOQS_INCLUDE_DIR} CACHE INTERNAL "")

add_subdirectory(core)
add_subdirectory(apps/client)
add_subdirectory(apps/server)
# add_subdirectory(apps/manager)