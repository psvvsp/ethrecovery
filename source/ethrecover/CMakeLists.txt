add_executable(ethrecover "main.cpp")

find_package(CLI11 CONFIG REQUIRED)
target_link_libraries(ethrecover PRIVATE common CLI11::CLI11)

target_include_directories(ethrecover PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

#set_property(TARGET ethrecover PROPERTY CUDA_ARCHITECTURES "61;86;89")
set_property(TARGET ethrecover PROPERTY CUDA_ARCHITECTURES OFF)

install(TARGETS ethrecover DESTINATION .)
