cmake_minimum_required(VERSION 2.6)
project(wireless_test)

add_executable(wireless_test main.cpp)

install(TARGETS wireless_test RUNTIME DESTINATION bin)
