cmake_minimum_required(VERSION 2.8.4)
project(masscan)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

SET(SOURCE_FILES /src/smack1.c /src/smack.h /src/proto-banner1.c /src/proto-banner1.h)

add_custom_target(masscan COMMAND make -C ${masscan_SOURCE_DIR}
        CLION_EXE_DIR=${PROJECT_BINARY_DIR})
