add_executable(tests "main.cpp")

find_package(CLI11 CONFIG REQUIRED)
target_link_libraries(tests PRIVATE common CLI11::CLI11)

install(TARGETS tests DESTINATION .)
