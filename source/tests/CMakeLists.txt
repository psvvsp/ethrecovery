add_executable(tests "main.cpp")

find_package(CLI11 CONFIG REQUIRED)
target_link_libraries(tests PRIVATE common CLI11::CLI11)

install(TARGETS tests DESTINATION .)

# makes cmake happy
set_property(TARGET tests PROPERTY CUDA_ARCHITECTURES "61;75;86")
