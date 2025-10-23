cmake_minimum_required(VERSION 3.10)

project(PruebIkerlan C)

add_library(common INTERFACE)
target_include_directories(common INTERFACE common)

add_subdirectory(set1/exercise1)
add_subdirectory(set1/exercise2)
add_subdirectory(set1/exercise3)