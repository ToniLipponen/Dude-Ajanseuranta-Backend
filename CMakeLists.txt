cmake_minimum_required(VERSION 3.10)
project(app)

set(CXX_STANDARD 17)

add_executable(
        app
        src/main.cpp
        src/Routes.cpp
        src/Housekeeping.cpp
        src/Application.cpp
        src/include/Application.h
        src/include/httplib.h
        src/include/json.hpp)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_definitions(app PRIVATE NO_LOGGING=1)
endif()

target_link_libraries(app httplib ssl crypto mariadb mariadbcpp)

target_include_directories(app PUBLIC 
    external/mariadb-connector-cpp/include)