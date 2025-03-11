cmake_minimum_required(VERSION 3.10)
project(snap_packages_extension)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find osquery package
set(OSQUERY_TOOLCHAIN_DIR "/usr/local/osquery-toolchain" CACHE PATH "Path to osquery toolchain")
set(OSQUERY_SDK_PATH "/usr/local/osquery-sdk" CACHE PATH "Path to osquery SDK")

# Include directories
include_directories("${OSQUERY_SDK_PATH}/include")
include_directories("${OSQUERY_TOOLCHAIN_DIR}/usr/include/c++/v1")
include_directories("${OSQUERY_TOOLCHAIN_DIR}/legacy/include")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

# Link directories
link_directories("${OSQUERY_SDK_PATH}/lib")
link_directories("${OSQUERY_TOOLCHAIN_DIR}/legacy/lib")

# Set compiler flags
add_compile_options(
  -Wall
  -Wextra
  -Wno-unused-parameter
  -Wno-deprecated-declarations
)

# Extension source files
set(SOURCES
  snap_packages_table.cpp
  updated_main.cpp
)

# Create extension binary
add_executable(snap_packages_extension ${SOURCES})

# Link against osquery libraries
target_link_libraries(snap_packages_extension
  osquery_sdk
  thrift
  gflags
  glog
  boost_system
  boost_filesystem
  boost_thread
  dl
  z
  crypto
  ssl
)

# Installation
install(TARGETS snap_packages_extension DESTINATION bin)