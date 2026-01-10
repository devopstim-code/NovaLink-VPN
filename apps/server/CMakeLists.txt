add_executable(novalink_server main.cpp)
target_link_libraries(novalink_server
        PRIVATE
        core_lib
        OpenSSL::SSL
)

set_target_properties(novalink_server PROPERTIES
        OUTPUT_NAME "nova_srv"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../bin"
)