cmake_minimum_required(VERSION 3.10)
project(Set1_Exercise4 CXX)  # Especifica C

set(CMAKE_CXX_STANDARD 11)


# Solo el ejecutable principal
add_executable(exercise6 main.cpp)

find_package(OpenSSL)
target_link_libraries(exercise6 PUBLIC common OpenSSL::Crypto OpenSSL::SSL)