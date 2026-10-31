add_executable(dnp3-cli main.cpp)
target_compile_features(dnp3-cli PRIVATE cxx_std_14)
target_link_libraries(dnp3-cli PRIVATE opendnp3)
