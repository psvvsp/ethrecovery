add_library(common
    "posgen.cpp"
    "ethrecover.cu"
    "dictionary.cpp"
    "./sha256/SHA256.cpp"
    "./hashcat/inc_common.cu"
    "./hashcat/inc_hash_sha256.cu"
    "./hashcat/inc_hash_sha512.cu"
    "./hashcat/inc_ecc_secp256k1.cu"
    "./pbkdf2/pbkdf2.cu"
    "./pbkdf2/sha512.cu"
     "derivpathstorage.cpp"
     "./keccak256/keccak256.cu"
     "params.cpp" "addressdb.cpp" )

target_include_directories(common PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/hashcat
    ${CMAKE_CURRENT_SOURCE_DIR}/pbkdf2
    ${CMAKE_CURRENT_SOURCE_DIR}/keccak256)

#set_property(TARGET ethrecover PROPERTY CUDA_ARCHITECTURES "70;75;80")
set_property(TARGET common PROPERTY CUDA_ARCHITECTURES "61;75;86")
set_property(TARGET common PROPERTY CUDA_SEPARABLE_COMPILATION ON)

find_package(uni-algo CONFIG REQUIRED)
target_link_libraries(common PRIVATE uni-algo::uni-algo)
