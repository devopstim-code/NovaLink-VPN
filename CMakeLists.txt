cmake_minimum_required(VERSION 3.20)
project(NovaLink-VPN LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../bin)

add_subdirectory(core)

add_subdirectory(apps/client)
 add_subdirectory(apps/server)
# add_subdirectory(apps/manager)
