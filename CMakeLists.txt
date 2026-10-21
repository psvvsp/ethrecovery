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

#set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --ptxas-options=-v -maxrregcount 128 --dlink-time-opt -arch=sm_61 -arch=sm_86 -arch=sm_89 --gen-opt-lto")
#set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --ptxas-options=-v -maxrregcount 128 --dlink-time-opt -arch=all-major --gen-opt-lto")
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --ptxas-options=-v -arch=sm_89 -maxrregcount 64")
#set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --ptxas-options=-v")

install(DIRECTORY data/wordlists DESTINATION .)
install(DIRECTORY data/derivationpath-lists DESTINATION .)
install(FILES data/mnemonics.txt DESTINATION .)

file(GLOB batch_files launch_examples/*.bat)
install(FILES ${batch_files} DESTINATION .)
install(FILES launch_examples/Mnemo-Gen.exe DESTINATION .)

file(GLOB test_files tests/*)
install(FILES ${test_files} DESTINATION .)

add_subdirectory(source)
