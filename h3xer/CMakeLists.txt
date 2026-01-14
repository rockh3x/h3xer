# H3XER Build Configuration
cmake_minimum_required(VERSION 3.18)
project(h3xer LANGUAGES CXX CUDA)

set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)

# Target modern GPUs: Ampere (8.6), Ada (8.9)
set(CMAKE_CUDA_ARCHITECTURES "86;89")

# Optimization flags
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -O3 --use_fast_math")
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --expt-relaxed-constexpr")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

include_directories(${PROJECT_SOURCE_DIR}/include)

# Main h3xer executable
add_executable(h3xer src/main.cu)
target_link_libraries(h3xer PRIVATE cuda cudart)
set_target_properties(h3xer PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
    CUDA_RESOLVE_DEVICE_SYMBOLS ON
)

# Hash extractor utility (CPU only)
add_executable(h3xer_extract src/h3xer_extract.cpp)

# Crypto test suite
add_executable(h3xer_test src/test_crypto.cu)
target_link_libraries(h3xer_test PRIVATE cuda cudart)
set_target_properties(h3xer_test PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
)

# Install
install(TARGETS h3xer h3xer_extract DESTINATION bin)

# Profiling option
option(ENABLE_PROFILING "Enable line info for NSight" OFF)
if(ENABLE_PROFILING)
    set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -lineinfo")
endif()

message(STATUS "H3XER: CUDA ${CMAKE_CUDA_ARCHITECTURES}, ${CMAKE_BUILD_TYPE}")
