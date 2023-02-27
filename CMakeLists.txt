cmake_minimum_required(VERSION 3.10)

project(app)

add_subdirectory(external/csv-parser)
set(CXX_STANDARD 17)

add_executable(
    app 
    main.cpp
    Routes.cpp
    Housekeeping.cpp
    Application.cpp
    Application.h 
    httplib.h 
    json.hpp)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_definitions(app PRIVATE NO_LOGGING=1)
endif()

target_link_libraries(app httplib ssl crypto mariadb mariadbcpp csv)
target_include_directories(app PUBLIC 
    external/mariadb-connector-cpp/include
    external/csv-parser/include 
    .)