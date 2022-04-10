cmake_minimum_required(VERSION 3.13)

project(ethrecovery VERSION 1.0 LANGUAGES CXX CUDA)
include(CTest)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(MSVC)     
    # Use the static C++ library for all build types 
    foreach(var 
        CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO
      )
      if(${var}  MATCHES  "/MD")
        string(REGEX REPLACE "/MD"  "/MT"  ${var}  "${${var}}")
      endif()
    endforeach()

    # The same for CUDA...
    foreach(var 
        CMAKE_CUDA_FLAGS CMAKE_CUDA_FLAGS_DEBUG CMAKE_CUDA_FLAGS_RELEASE
        CMAKE_CUDA_FLAGS_MINSIZEREL CMAKE_CUDA_FLAGS_RELWITHDEBINFO
      )
      if(${var}  MATCHES  "-MD")
        string(REGEX REPLACE "-MD"  "-MT"  ${var}  "${${var}}")
      endif()
    endforeach()
endif(MSVC)

add_executable(ethrecover "main.cpp" "posgen.cpp" "ethrecover.cu" "dictionary.cpp" "./sha256/SHA256.cpp")

find_package(CLI11 CONFIG REQUIRED)

target_link_libraries(ethrecover PRIVATE CLI11::CLI11)

set_property(TARGET ethrecover PROPERTY CUDA_ARCHITECTURES "70;75;80")