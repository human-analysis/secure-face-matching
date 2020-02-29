# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(FaceMatching VERSION 1.1 LANGUAGES CXX)

# Executable will be in ../../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "../../../bin")

add_executable(authentication-bfv-1-to-1 authentication-bfv-1-to-1.cpp)
add_executable(authentication-bfv-1-to-n authentication-bfv-1-to-n.cpp)
add_executable(authentication-ckks-1-to-1 authentication-ckks-1-to-1.cpp)
add_executable(authentication-ckks-1-to-n authentication-ckks-1-to-n.cpp)

# Import Microsoft SEAL
find_package(SEAL 3.4.5 EXACT REQUIRED)

if(SEAL_FOUND)
    message("SEAL Found")
    include_directories(${SEAL_INCLUDE_DIRS}, "../../include/")
    target_link_libraries(authentication-bfv-1-to-1 SEAL::seal)
    target_link_libraries(authentication-bfv-1-to-n SEAL::seal)
    target_link_libraries(authentication-ckks-1-to-1 SEAL::seal)
    target_link_libraries(authentication-ckks-1-to-n SEAL::seal)
elseif(NOT SEAL_FOUND)
    error("SEAL Not Found")
endif()
