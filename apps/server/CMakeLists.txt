add_executable(novalink_server main.cpp)

target_link_libraries(novalink_server PRIVATE core_lib)

set_target_properties(novalink_server PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../bin"
)