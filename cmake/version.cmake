configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.hpp.in"
  "${CMAKE_CURRENT_BINARY_DIR}/generated/${PROJECT_NAME}/version.hpp"
  @ONLY
)


include_directories(
  "${CMAKE_CURRENT_BINARY_DIR}/generated"
)

# Version information for the executables' resources.
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.rc.in"
  "${CMAKE_CURRENT_BINARY_DIR}/generated/${PROJECT_NAME}/version.rc"
  @ONLY
)
set(HAWK_VERSION_RC "${CMAKE_CURRENT_BINARY_DIR}/generated/${PROJECT_NAME}/version.rc")
