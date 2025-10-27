cmake_minimum_required(VERSION 3.10)
project(Set3_Exercise18 C)  # Especifica C

set(CMAKE_C_STANDARD 11)

# Solo el ejecutable principal
add_executable(exercise18 main.cpp)
target_link_libraries(exercise18 PUBLIC common)


find_package(OpenSSL)
target_link_libraries(exercise18 PUBLIC common OpenSSL::Crypto OpenSSL::SSL)
