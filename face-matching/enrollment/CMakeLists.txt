# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(FaceMatching VERSION 1.1 LANGUAGES CXX)

# Executable will be in ../../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "../../../bin")

add_executable(enrollment-bfv-1-to-1 enrollment-bfv-1-to-1.cpp)
add_executable(enrollment-bfv-1-to-n enrollment-bfv-1-to-n.cpp)
add_executable(enrollment-ckks-1-to-1 enrollment-ckks-1-to-1.cpp)
add_executable(enrollment-ckks-1-to-n enrollment-ckks-1-to-n.cpp)

# Import Microsoft SEAL
find_package(SEAL 4.1.1 EXACT REQUIRED)

if(SEAL_FOUND)
    message("SEAL Found")
    include_directories(${SEAL_INCLUDE_DIRS}, "../../include/")
    target_link_libraries(enrollment-bfv-1-to-1 SEAL::seal)
    target_link_libraries(enrollment-bfv-1-to-n SEAL::seal)
    target_link_libraries(enrollment-ckks-1-to-1 SEAL::seal)
    target_link_libraries(enrollment-ckks-1-to-n SEAL::seal)
elseif(NOT SEAL_FOUND)
    error("SEAL Not Found")
endif()
