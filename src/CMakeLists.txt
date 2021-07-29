file(GLOB_RECURSE TLS_MONITOR_HEADERS $<$<VERSION_GREATER_EQUAL:${CMAKE_VERSION},3.14>:CONFIGURE_DEPENDS>
    ${CMAKE_SOURCE_DIR}/include/*.h
)

file(GLOB_RECURSE TLS_MONITOR_SOURCES $<$<VERSION_GREATER_EQUAL:${CMAKE_VERSION},3.14>:CONFIGURE_DEPENDS>
    ${CMAKE_SOURCE_DIR}/src/*.cpp
)

add_executable(${TLS_MONITOR_BINARY_NAME} ${TLS_MONITOR_HEADERS} ${TLS_MONITOR_SOURCES})

#topdir
target_include_directories(${TLS_MONITOR_BINARY_NAME} PRIVATE ${CMAKE_SOURCE_DIR})

#include
target_include_directories(${TLS_MONITOR_BINARY_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)

#fmt
target_include_directories(${TLS_MONITOR_BINARY_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/3rdparty/fmt-git-src/include)
target_link_libraries(${TLS_MONITOR_BINARY_NAME} fmt)

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
