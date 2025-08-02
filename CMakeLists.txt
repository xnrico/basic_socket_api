cmake_minimum_required(VERSION 3.22)
project(basic_socket_api)

set(CXX_STANDARD_REQUIRED true)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 20)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
set(CMAKE_BUILD_TYPE Debug)

include_directories(${PROJECT_SOURCE_DIR}/include)
aux_source_directory(${PROJECT_SOURCE_DIR}/src SRC_DIR)
aux_source_directory(${PROJECT_SOURCE_DIR}/test TEST_DIR)

# Find all test cpp files
file(GLOB TEST_FILES "${PROJECT_SOURCE_DIR}/test/*.cpp")

foreach(test_file ${TEST_FILES})
    # Get the filename without path and extension
    get_filename_component(test_name ${test_file} NAME_WE)
    add_executable(${test_name} ${SRC_DIR} ${test_file})
endforeach()
