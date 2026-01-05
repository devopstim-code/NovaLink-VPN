find_package(CURL REQUIRED)

add_executable(novalink_client main.cpp)

target_include_directories(novalink_client PRIVATE ${CURL_INCLUDE_DIRS})

target_link_libraries(novalink_client PRIVATE
        core_lib
        CURL::libcurl
)