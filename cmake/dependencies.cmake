include(FetchContent)

set(FETCHCONTENT_BASE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty)

#bcc
FetchContent_Declare(
    bcc-git
    GIT_REPOSITORY "https://github.com/iovisor/bcc.git"
    GIT_TAG         origin/master
)
FetchContent_MakeAvailable(bcc-git)

#fmt
FetchContent_Declare(
    fmt-git
    GIT_REPOSITORY "https://github.com/fmtlib/fmt.git"
    GIT_TAG         origin/master
)
FetchContent_MakeAvailable(fmt-git)