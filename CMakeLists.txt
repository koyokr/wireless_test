cmake_minimum_required(VERSION 2.6)
project(wireless_test CXX)

find_library(TINS_LIBRARY tins)
set(CMAKE_CXX_STANDARD 14)

set(PTHREAD_LINK_LIBRARIES -pthread)
add_compile_options(${PTHREAD_LINK_LIBRARIES})

set(SOURCE_FILES
    main.cpp
    driver.cpp
    cli.cpp
    dot11sniff.cpp
    )

set(HEADER_FILES
    driver.hpp
    cli.hpp
    dot11sniff.hpp
    )

add_executable(wireless_test ${SOURCE_FILES} ${HEADER_FILES})
target_link_libraries(wireless_test ${TINS_LIBRARY} ${PTHREAD_LINK_LIBRARIES})
