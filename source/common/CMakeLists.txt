add_library(common
    "posgen.cpp"
    "mnemrecover.cu"
    "dictionary.cpp"
    "./sha256/SHA256.cpp"
    "./hashcat/inc_common.cu"
    "./hashcat/inc_hash_sha256.cu"
    "./hashcat/inc_hash_sha512.cu"
    "./hashcat/inc_ecc_secp256k1.cu"
    "./fastpbkdf2/fastpbkdf2.cu"
     "derivpathstorage.cpp"
     "./keccak256/keccak256.cu"
     "params.cpp"
     "addressdb.cpp"
     "ripemd160/ripemd160.cu"
     "base58/base58.cpp" 
     "bech32/bech32.cpp")

target_include_directories(common PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/hashcat
    ${CMAKE_CURRENT_SOURCE_DIR}/keccak256
    ${CMAKE_CURRENT_SOURCE_DIR}/ripemd160
    ${CMAKE_CURRENT_SOURCE_DIR}/base58
    ${CMAKE_CURRENT_SOURCE_DIR}/bech32
    ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES})

#set_property(TARGET ethrecover PROPERTY CUDA_ARCHITECTURES "70;75;80")
#set_property(TARGET common PROPERTY CUDA_ARCHITECTURES "61;86;89")
set_property(TARGET common PROPERTY CUDA_ARCHITECTURES OFF)
set_property(TARGET common PROPERTY CUDA_SEPARABLE_COMPILATION ON)


find_package(uni-algo CONFIG REQUIRED)
target_link_libraries(common PRIVATE uni-algo::uni-algo)
