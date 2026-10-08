if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
    message(FATAL_ERROR
        "This project targets the Windows service API (winhttp/advapi32) and "
        "must be built with a Windows toolchain, e.g. via "
        "-DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/x86_64-w64-mingw32.cmake"
    )
endif()

add_executable(hawk-service
    service/main.cpp
    service/capture_host.cpp
    service/credential_store.cpp
    service/websocket/websocket.cpp
)

target_include_directories(hawk-service PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_compile_definitions(hawk-service PRIVATE
    UNICODE
    _UNICODE
)

target_link_libraries(hawk-service PRIVATE
    fmt::fmt
    spdlog::spdlog
    glaze::glaze
    winhttp
    advapi32
    wtsapi32
    userenv
    crypt32
)

# ServiceMain's entry point is wmain(); mingw needs -municode to select the
# wide-character CRT startup instead of the default main()-based one.
target_link_options(hawk-service PRIVATE -municode)

target_set_warning(hawk-service OFF)

# Standalone per-session helper: captures the desktop via DXGI Desktop
# Duplication. Must run as an ordinary process in the interactive user's own
# session — a Session 0 service has no desktop to see at all, so this is
# deliberately a separate executable from hawk-service rather than a thread
# inside it.
add_executable(hawk-capture
    capture/main.cpp
    capture/duplication.cpp
    capture/encoder.cpp
)

target_include_directories(hawk-capture PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(hawk-capture PRIVATE
    fmt::fmt
    spdlog::spdlog
    d3d11
    dxgi
    dxguid
    mfplat
    mfuuid
    ole32
    oleaut32
    winmm
)

target_set_warning(hawk-capture OFF)
