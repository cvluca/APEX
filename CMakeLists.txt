cmake_minimum_required(VERSION 3.13)

project(apex CXX)

set(CMAKE_CXX_STANDARD 17)

set(BUILD_SHARED OFF CACHE BOOL "Build OpenFHE as a static library" FORCE)
set(BUILD_STATIC ON CACHE BOOL "Build OpenFHE as a static library" FORCE)
set(BUILD_UNITTESTS OFF CACHE BOOL "Build OpenFHE unit tests" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "Build OpenFHE examples" FORCE)
set(BUILD_BENCHMARKS OFF CACHE BOOL "Build OpenFHE benchmarks" FORCE)

# turn on for max performance
set(WITH_OPENMP OFF CACHE BOOL "Control OpenMP in OpenFHE")

add_subdirectory(third-party/openfhe-development)

add_subdirectory(src)

option(APEX_BUILD_EXAMPLES "Build examples" ON)
option(APEX_BUILD_BENCHMARKS "Build benchmarks" ON)
option(APEX_BUILD_TESTS "Build tests" ON)
add_subdirectory(examples)
add_subdirectory(benchmark)
add_subdirectory(tests)
