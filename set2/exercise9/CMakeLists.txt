cmake_minimum_required(VERSION 3.10)
project(Set2_Exercise1 C)  # Especifica C

set(CMAKE_C_STANDARD 11)

# Solo el ejecutable principal
add_executable(exercise9 main.cpp)
target_link_libraries(exercise9 PUBLIC common)



