cmake_minimum_required(VERSION 3.28)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
project(RouteSim)

add_executable(RouteSim
        main/main.c
        main/forward.c
        main/common.c
        main/rip.c
)
find_package(PkgConfig REQUIRED)

find_library(PCAP_LIBRARY pcap)
if (PCAP_LIBRARY)
    target_link_libraries(RouteSim ${PCAP_LIBRARY})
endif ()