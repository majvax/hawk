include(cmake/CPM.cmake)



cpmaddpackage("gh:fmtlib/fmt#11.2.0")
cpmaddpackage(URI "gh:gabime/spdlog@1.15.3" OPTIONS "SPDLOG_FMT_EXTERNAL ON")
cpmaddpackage("gh:stephenberry/glaze@8.4.0")

# Audio: Opus, built static for hawk-capture.
cpmaddpackage(
    NAME opus
    GITHUB_REPOSITORY xiph/opus
    GIT_TAG v1.5.2
    OPTIONS "OPUS_BUILD_TESTING OFF" "OPUS_BUILD_PROGRAMS OFF" "OPUS_BUILD_SHARED_LIBRARY OFF"
            "OPUS_INSTALL_PKG_CONFIG_MODULE OFF" "OPUS_INSTALL_CMAKE_CONFIG_MODULE OFF"
)
