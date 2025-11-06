cmake_minimum_required(VERSION 3.10)

project(PruebIkerlan LANGUAGES C CXX)

add_library(common INTERFACE)
target_include_directories(common INTERFACE common)

add_subdirectory(set1/exercise1)
add_subdirectory(set1/exercise2)
add_subdirectory(set1/exercise3)
add_subdirectory(set1/exercise4)
add_subdirectory(set1/exercise5)
add_subdirectory(set1/exercise6)
add_subdirectory(set1/exercise7)
add_subdirectory(set1/exercise8)

add_subdirectory(set2/exercise9)
add_subdirectory(set2/exercise10)
add_subdirectory(set2/exercise11)
add_subdirectory(set2/exercise12)
add_subdirectory(set2/exercise13)
add_subdirectory(set2/exercise14)
add_subdirectory(set2/exercise15)
add_subdirectory(set2/exercise16)

add_subdirectory(set3/exercise18)
add_subdirectory(set3/exercise21)
add_subdirectory(set3/exercise22)





