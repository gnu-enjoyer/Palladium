cmake_minimum_required(VERSION 3.16)
project(Palladium)
set(CMAKE_CXX_STANDARD 17)

if(WIN32)
    add_executable(Palladium
            src/main.cpp
            src/palladium.cpp)

    target_link_libraries(Palladium PRIVATE
            ws2_32
            winmm)
endif()