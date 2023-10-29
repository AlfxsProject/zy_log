cmake_minimum_required(VERSION 3.26)
project(zy_log C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED True)

include_directories(zy_alloc)

file(GLOB_RECURSE SOURCES LIST_DIRECTORIES true "zy_alloc/*.h" "zy_alloc/*.c")

set(SOURCES ${SOURCES} zy_log.h zy_log.c)

add_library(${CMAKE_PROJECT_NAME} STATIC ${SOURCES})