cmake_minimum_required(VERSION 3.0)
project(wireless_test CXX)
set(CMAKE_CXX_STANDARD 14)

find_library(PCAP_LIBRARY pcap)
find_library(TINS_LIBRARY tins)

set(PTHREAD_LINK_LIBRARIES -pthread)
add_compile_options(${PTHREAD_LINK_LIBRARIES})

set(SOURCE_FILES
    main.cpp
    driver.cpp
    cli.cpp
    info.cpp
    )

set(HEADER_FILES
    driver.hpp
    cli.hpp
    info.hpp
    )

add_executable(wireless_test
               ${SOURCE_FILES}
               ${HEADER_FILES}
               )
target_link_libraries(wireless_test
                      ${PCAP_LIBRARY}
                      ${TINS_LIBRARY}
                      ${PTHREAD_LINK_LIBRARIES}
                      )
