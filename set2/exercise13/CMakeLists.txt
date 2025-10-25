cmake_minimum_required(VERSION 3.10)
project(Set2_Exercise13 C)  # Especifica C

set(CMAKE_C_STANDARD 11)

# Solo el ejecutable principal
add_executable(exercise13 main.cpp)
target_link_libraries(exercise13 PUBLIC common)


find_package(OpenSSL)
target_link_libraries(exercise13 PUBLIC common OpenSSL::Crypto OpenSSL::SSL)
