add_executable(${TLS_MONITOR_BINARY_NAME} tls_monitor.cpp utils/ip_convert.cpp)

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

target_link_libraries(${TLS_MONITOR_BINARY_NAME} fmt)