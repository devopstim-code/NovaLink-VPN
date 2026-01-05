find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(core_lib STATIC
        network/EpollEngine.cpp
        tunnel/TunDevice.cpp
        network/UdpSocket.cpp
        crypto/CryptoEngine.cpp
)
target_include_directories(core_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(core_lib
        PRIVATE
        Threads::Threads
        OpenSSL::Crypto
)