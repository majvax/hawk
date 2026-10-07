include(cmake/CPM.cmake)



cpmaddpackage("gh:fmtlib/fmt#11.2.0")
cpmaddpackage(URI "gh:gabime/spdlog@1.15.3" OPTIONS "SPDLOG_FMT_EXTERNAL ON")
