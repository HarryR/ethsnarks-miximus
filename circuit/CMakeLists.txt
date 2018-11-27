cmake_minimum_required(VERSION 3.8)
project(ethsnarks-miximus)
add_subdirectory(../ethsnarks ../.build/ethsnarks EXCLUDE_FROM_ALL)

add_library(miximus SHARED miximus.cpp)
target_link_libraries(miximus ethsnarks_common)
set_property(TARGET miximus PROPERTY POSITION_INDEPENDENT_CODE ON)

add_executable(miximus_cli miximus_cli.cpp)
target_link_libraries(miximus_cli ethsnarks_common)
