cmake_minimum_required(VERSION 3.14)

include(cmake/dependencies.cmake)

set(TLS_MONITOR_BINARY_NAME "tlsmon")
set(TLS_MONITOR_BINARY_VERSION "1.0.0")

project(tls-monitor
		LANGUAGES CXX
		VERSION ${TLS_MONITOR_BINARY_VERSION})

set(CMAKE_VERBOSE_MAKEFILE ON CACHE BOOL "ON")

include(CheckCXXCompilerFlag)
include(cmake/validate.cmake)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# enable testing
enable_testing()

add_subdirectory(src)
#add_subdirectory(tests)