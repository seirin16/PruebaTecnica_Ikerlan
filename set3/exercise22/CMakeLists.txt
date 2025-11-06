cmake_minimum_required(VERSION 3.10)
project(Set3_Exercise21 C)  # Especifica C

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Solo el ejecutable principal
add_executable(exercise22 main.cpp)
target_link_libraries(exercise22 PUBLIC common)


find_package(OpenSSL)
target_link_libraries(exercise22 PUBLIC common OpenSSL::Crypto OpenSSL::SSL)
