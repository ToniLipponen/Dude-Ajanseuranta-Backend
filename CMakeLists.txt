cmake_minimum_required(VERSION 3.10)

project(app)

add_subdirectory(external/csv-parser)

add_executable(
    app 
    main.cpp 
    Housekeeping.cpp
    Application.cpp
    Application.h 
    httplib.h 
    json.hpp)

target_link_libraries(app httplib ssl crypto mariadb mariadbcpp csv)
target_include_directories(app PUBLIC 
    external/mariadb-connector-cpp/include
    external/csv-parser/include 
    .)