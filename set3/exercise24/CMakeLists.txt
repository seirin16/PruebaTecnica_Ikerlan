cmake_minimum_required(VERSION 3.10)
project(Set3_Exercise24 C)  # Especifica C

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Solo el ejecutable principal
add_executable(exercise24 main.cpp)
target_link_libraries(exercise24 PUBLIC common)


find_package(OpenSSL)
target_link_libraries(exercise24 PUBLIC common OpenSSL::Crypto OpenSSL::SSL)
