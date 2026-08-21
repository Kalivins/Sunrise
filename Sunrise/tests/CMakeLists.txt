# Standalone build for the encounter-engine test. Kept separate from the root DLL build so it can
# never affect steam_api64. Configure/build it on its own:
#
#   cmake -S Sunrise/tests -B build/tests
#   cmake --build build/tests
#   ./build/tests/blueprint_activity_policy_test        # exit 0 == pass
#
# The project builds on the fork CI toolchain (MSVC/clang + Windows SDK); it is not built locally.
# If the logical WorldRunner pulls extra translation units at link time, add their globs below
# (mechanics/*.cpp) — that is the expected CI-iteration step, not a redesign.

cmake_minimum_required(VERSION 3.20)
project(sunrise_encounter_tests CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SRC "${CMAKE_CURRENT_SOURCE_DIR}/../src")

file(GLOB_RECURSE WORLD_SOURCES CONFIGURE_DEPENDS
    "${SRC}/server/gameplay/physics/world/*.cpp"
    "${SRC}/server/gameplay/encounter/*.cpp"
)

add_executable(blueprint_activity_policy_test
    blueprint_activity_policy_test.cpp
    log_stub.cpp
    ${WORLD_SOURCES}
)

target_include_directories(blueprint_activity_policy_test PRIVATE "${SRC}")

target_compile_definitions(blueprint_activity_policy_test PRIVATE
    WIN32 _WINDOWS WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE
)

target_link_libraries(blueprint_activity_policy_test PRIVATE
    kernel32 synchronization bcrypt
)
