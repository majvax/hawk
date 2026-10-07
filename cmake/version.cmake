configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.hpp.in"
  "${CMAKE_CURRENT_BINARY_DIR}/generated/${PROJECT_NAME}/version.hpp"
  @ONLY
)


include_directories(
  "${CMAKE_CURRENT_BINARY_DIR}/generated"
)
