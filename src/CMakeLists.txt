cmake_minimum_required(VERSION 3.14)

set(TLS_MONITOR_HEADERS
  ${CMAKE_SOURCE_DIR}/include/attach_probe.h
  ${CMAKE_SOURCE_DIR}/include/interface_monitor.h
  ${CMAKE_SOURCE_DIR}/include/startup.h
  ${CMAKE_SOURCE_DIR}/include/trace_pipe.h
  ${CMAKE_SOURCE_DIR}/include/unix_socket_monitor.h
  )

  set(TLS_MONITOR_SOURCES
    ${CMAKE_SOURCE_DIR}/src/interface_monitor.cpp
    ${CMAKE_SOURCE_DIR}/src/trace_pipe.cpp
    ${CMAKE_SOURCE_DIR}/src/unix_socket_monitor.cpp
    ${CMAKE_SOURCE_DIR}/src/main.cpp
  )

add_executable(${TLS_MONITOR_BINARY_NAME} ${TLS_MONITOR_HEADERS} ${TLS_MONITOR_SOURCES})

#topdir
target_include_directories(${TLS_MONITOR_BINARY_NAME} PRIVATE ${CMAKE_SOURCE_DIR})

#include
target_include_directories(${TLS_MONITOR_BINARY_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)

#fmt
target_include_directories(${TLS_MONITOR_BINARY_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/3rdparty/fmt-git-src/include)

#bcc
target_include_directories(${TLS_MONITOR_BINARY_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/3rdparty/bcc-git-build/src/cc)
target_include_directories(${TLS_MONITOR_BINARY_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/3rdparty/bcc-git-src/src/cc)
target_include_directories(${TLS_MONITOR_BINARY_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/3rdparty/bcc-git-src/src/cc/api)
target_include_directories(${TLS_MONITOR_BINARY_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/3rdparty/bcc-git-src/src/cc/libbpf/include/uapi)
if(NOT CMAKE_USE_LIBBPF_PACKAGE)
  target_link_libraries(${TLS_MONITOR_BINARY_NAME} bcc-static)
else()
  target_link_libraries(${TLS_MONITOR_BINARY_NAME} bcc-shared)
endif()

target_link_libraries(${TLS_MONITOR_BINARY_NAME} fmt boost_coroutine)