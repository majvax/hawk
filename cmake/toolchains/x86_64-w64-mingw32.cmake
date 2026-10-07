# CMake toolchain file for cross-compiling Windows x64 binaries from Linux
# using the mingw-w64 GCC toolchain.
#
# Usage:
#   cmake -B build-win -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/x86_64-w64-mingw32.cmake
#   cmake --build build-win

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)

set(MINGW_TRIPLE x86_64-w64-mingw32)

find_program(CMAKE_C_COMPILER   NAMES ${MINGW_TRIPLE}-gcc)
find_program(CMAKE_CXX_COMPILER NAMES ${MINGW_TRIPLE}-g++)
find_program(CMAKE_RC_COMPILER  NAMES ${MINGW_TRIPLE}-windres)
find_program(CMAKE_AR           NAMES ${MINGW_TRIPLE}-gcc-ar ${MINGW_TRIPLE}-ar)
find_program(CMAKE_RANLIB       NAMES ${MINGW_TRIPLE}-gcc-ranlib ${MINGW_TRIPLE}-ranlib)

if(NOT CMAKE_C_COMPILER OR NOT CMAKE_CXX_COMPILER)
    message(FATAL_ERROR "mingw-w64 toolchain '${MINGW_TRIPLE}' not found. Install the mingw-w64-gcc package.")
endif()

# Target environment: only look for libraries/headers under the mingw sysroot,
# but still allow finding host programs (e.g. CMake-bundled tools).
set(CMAKE_FIND_ROOT_PATH /usr/${MINGW_TRIPLE})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Static-link the mingw/gcc runtime so the resulting .exe doesn't depend on
# libstdc++/libgcc/winpthread DLLs being present on the target machine.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static -static-libgcc -static-libstdc++")
