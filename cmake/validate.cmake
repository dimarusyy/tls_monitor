if (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "Clang required ${CMAKE_CXX_COMPILER_ID}")
endif()

if(NOT CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 12)
    message(FATAL_ERROR "Clang 12.0 or newer is required")
endif()