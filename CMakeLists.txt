cmake_minimum_required(VERSION 3.10)

project(app)

add_executable(
    app 
    main.cpp 
    Application.cpp
    Application.h 
    httplib.h 
    json.hpp)

target_link_libraries(app httplib ssl crypto mariadb mariadbcpp)