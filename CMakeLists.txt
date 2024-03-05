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

set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --ptxas-options=-v -maxrregcount 80")

add_executable(ethrecover 
    "main.cpp"
    "posgen.cpp"
    "ethrecover.cu"
    "dictionary.cpp"
    "./sha256/SHA256.cpp"
    #"./hashcat/inc_platform.cu"
    "./hashcat/inc_common.cu"
    "./hashcat/inc_hash_sha256.cu"
    "./hashcat/inc_hash_sha512.cu"
    "./hashcat/inc_ecc_secp256k1.cu"
    "./pbkdf2/pbkdf2.cu"
    "./pbkdf2/sha512.cu"
     "derivpathstorage.cpp"
     "./keccak256/keccak256.cu"
     "params.cpp" "addressdb.cpp" )

find_package(CLI11 CONFIG REQUIRED)

target_link_libraries(ethrecover PRIVATE CLI11::CLI11)
target_include_directories(ethrecover PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/hashcat
    ${CMAKE_CURRENT_SOURCE_DIR}/pbkdf2
    ${CMAKE_CURRENT_SOURCE_DIR}/keccak256)

#set_property(TARGET ethrecover PROPERTY CUDA_ARCHITECTURES "70;75;80")
set_property(TARGET ethrecover PROPERTY CUDA_ARCHITECTURES "61;75;86")
set_property(TARGET ethrecover PROPERTY CUDA_SEPARABLE_COMPILATION ON)