cmake_minimum_required(VERSION 3.10)
project(Set1_Exercise4 CXX)  # Especifica C

set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL)


# Solo el ejecutable principal
add_executable(exercise7 main.cpp)
target_link_libraries(exercise7 PUBLIC common OpenSSL::Crypto OpenSSL::SSL)
