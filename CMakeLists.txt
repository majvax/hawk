cmake_minimum_required(VERSION 3.30)
include(cmake/warning.cmake)

if (NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 23)
endif()

set(CMAKE_CXX_EXTENSIONS OFF)


# One version for every component, from the VERSION file at the root (see
# scripts/bump-version). A prerelease suffix ("1.1.0-rc.1") is kept in
# HAWK_VERSION; CMake's own version is only the numeric part.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" HAWK_VERSION)
string(STRIP "${HAWK_VERSION}" HAWK_VERSION)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION")
string(REGEX MATCH "^[0-9]+[.][0-9]+[.][0-9]+" HAWK_VERSION_CORE "${HAWK_VERSION}")
if(NOT HAWK_VERSION_CORE)
    message(FATAL_ERROR "VERSION must start with MAJOR.MINOR.PATCH, not \"${HAWK_VERSION}\"")
endif()

project(
    hawk
    VERSION ${HAWK_VERSION_CORE}
    DESCRIPTION "Self-hosted remote desktop"
    HOMEPAGE_URL ""
    LANGUAGES CXX
)


set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# bin/ by default; CI and side-by-side builds pass their own.
if(NOT DEFINED CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
endif()

# Explicitly disable automatic C++20 module scanning to avoid injecting
# unsupported experimental flags like -fmodules-ts with some GCC/MinGW builds.
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

include(cmake/version.cmake)
include(Dependencies.cmake)

# Add source tree
add_subdirectory(src)
