find_package(OpenSSL REQUIRED)

add_executable(novalink_client main.cpp)
target_link_libraries(novalink_client PRIVATE
        core_lib
        OpenSSL::Crypto
)
target_compile_features(novalink_client PRIVATE cxx_std_23)