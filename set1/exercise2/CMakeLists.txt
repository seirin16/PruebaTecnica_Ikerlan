cmake_minimum_required(VERSION 3.10)
project(Set1_Exercise2 C)  # Especifica C

set(CMAKE_C_STANDARD 11)

# Solo el ejecutable principal
add_executable(exercise2 main.c)
target_link_libraries(exercise2 PUBLIC common)
