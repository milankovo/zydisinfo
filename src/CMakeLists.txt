cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(zydisinfo)

set(CMAKE_CXX_STANDARD 20)
option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-Wnullability-completeness"
                        COMPILER_HAS_W_NULLABILITY_COMPLETENESS)
if(COMPILER_HAS_W_NULLABILITY_COMPLETENESS)
  string(APPEND CMAKE_CXX_FLAGS " -Wno-nullability-completeness")
endif()

check_cxx_compiler_flag("-Wno-varargs" COMPILER_HAS_W_NO_VARARGS)
if(COMPILER_HAS_W_NO_VARARGS)
    string(APPEND CMAKE_CXX_FLAGS " -Wno-varargs")
endif()

if (MSVC)
  string(APPEND CMAKE_CXX_FLAGS " /O2")
endif (MSVC)

CHECK_CXX_COMPILER_FLAG("-O3" COMPILER_SUPPORTS_MARCH_NATIVE)
if(COMPILER_SUPPORTS_MARCH_NATIVE)
    string(APPEND CMAKE_CXX_FLAGS " -O3")
endif()


set(PLUGIN_LINK_LIBRARIES "Zydis")

include($ENV{IDASDK}/ida-cmake/common.cmake)

set(PLUGIN_NAME              zydisinfo)
set(PLUGIN_SOURCES           zydisinfo.cpp)
set(PLUGIN_RUN_ARGS          "-t -z10000") # Debug messages for the debugger
generate()

disable_ida_warnings(zydisinfo)