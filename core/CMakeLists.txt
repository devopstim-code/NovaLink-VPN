find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
add_library(core_lib STATIC
        network/EpollEngine.cpp
        tunnel/TunDevice.cpp
        network/SslLayer.cpp
        network/UdpSocket.cpp
        crypto/CryptoEngine.cpp
)
if(MSVC)
    target_compile_options(core_lib PRIVATE /W4)
else()
    target_compile_options(core_lib PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wno-unused-parameter -O3)
endif()

target_include_directories(core_lib PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${LIBOQS_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(core_lib
        PUBLIC
        Threads::Threads
        OpenSSL::Crypto
        OpenSSL::SSL
        ${LIBOQS_LIBRARY}
)