cmake_minimum_required(VERSION 3.10)
project(robloxdumper)
set(CMAKE_CXX_STANDARD 17)

add_library(internal SHARED
    internal/dllmain.cpp
    common/patternscanner.cpp
    common/memoryutils.cpp
)
target_include_directories(internal PRIVATE common)

add_executable(external
    external/main.cpp
    common/patternscanner.cpp
    common/memoryutils.cpp
)
target_include_directories(external PRIVATE common)
target_link_libraries(external psapi)
