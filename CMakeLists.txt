cmake_minimum_required(VERSION 3.11)
project(dnp3_workspace LANGUAGES C CXX)

add_subdirectory(opendnp3)
if(NOT TARGET dnp3-cli)
    add_subdirectory(cli)
endif()

add_executable(master apps/master/main.cpp)
target_link_libraries(master PRIVATE opendnp3)

add_executable(outstation apps/outstation/main.cpp)
target_link_libraries(outstation PRIVATE opendnp3)
