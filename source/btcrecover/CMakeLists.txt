add_executable(btcrecover "main.cpp")

find_package(CLI11 CONFIG REQUIRED)
target_link_libraries(btcrecover PRIVATE common CLI11::CLI11)

target_include_directories(btcrecover PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

#set_property(TARGET btcrecover PROPERTY CUDA_ARCHITECTURES "61;86;89")
set_property(TARGET btcrecover PROPERTY CUDA_ARCHITECTURES OFF)

install(TARGETS btcrecover DESTINATION .)
