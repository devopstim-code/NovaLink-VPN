add_executable(novalink_client main.cpp)
target_link_libraries(novalink_client
        PRIVATE
        core_lib
        OpenSSL::SSL
)
target_compile_features(novalink_client PRIVATE cxx_std_23)
set_target_properties(novalink_client PROPERTIES
        OUTPUT_NAME "nova_cl"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../bin"
)