include(FetchContent)

FetchContent_Declare(
    ser4cpp
    URL      https://github.com/automatak/ser4cpp/archive/3c449734dc530a8f465eb0982de29165cc4e23d5.zip
    URL_HASH SHA1=937B759B7CC80180DA26B47037E796B59798A672
)

FetchContent_GetProperties(ser4cpp)
if(NOT ser4cpp_POPULATED)
    FetchContent_Populate(ser4cpp)

    # Keep the pinned dependency intact. Its binary32 codec loses signed zero
    # on read and uses the wrong exponent for subnormal values.
    set(ser4cpp_patch_dir "${CMAKE_CURRENT_BINARY_DIR}/ser4cpp-patched")
    set(ser4cpp_single_float "ser4cpp/serialization/SingleFloat.h")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${ser4cpp_SOURCE_DIR}/src/${ser4cpp_single_float}")
    file(READ "${ser4cpp_SOURCE_DIR}/src/${ser4cpp_single_float}" ser4cpp_float_header)
    string(REPLACE "return 0.0f;" "return sign ? -0.0f : 0.0f;"
        ser4cpp_float_header "${ser4cpp_float_header}")
    string(REPLACE "2 - (uint16_t{1} << 8)" "-126"
        ser4cpp_float_header "${ser4cpp_float_header}")
    string(REPLACE "else if (value != 0.0f)"
        "else if (std::fpclassify(value) == FP_SUBNORMAL)\n        {\n            encoded_value = static_cast<uint32_t>(std::ldexp(std::abs(value), 149));\n        }\n        else if (value != 0.0f)"
        ser4cpp_float_header "${ser4cpp_float_header}")
    file(GENERATE OUTPUT "${ser4cpp_patch_dir}/${ser4cpp_single_float}" CONTENT "${ser4cpp_float_header}")

    add_library(ser4cpp INTERFACE)
    target_include_directories(ser4cpp INTERFACE "${ser4cpp_patch_dir}" "${ser4cpp_SOURCE_DIR}/src")
    target_compile_features(ser4cpp INTERFACE cxx_std_14)
endif()
