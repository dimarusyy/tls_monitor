include(FetchContent)

set(FETCHCONTENT_BASE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty)

#smhasher
FetchContent_Declare(
    bcc-git
    GIT_REPOSITORY "https://github.com/iovisor/bcc.git"
    GIT_TAG         origin/master
)

FetchContent_MakeAvailable(bcc-git)

#vcpkg
#FetchContent_Declare(
#    vcpkg-git
#    GIT_REPOSITORY "https://github.com/microsoft/vcpkg.git"
#    GIT_TAG         origin/master
#)

#FetchContent_MakeAvailable(vcpkg-git)

#set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/vcpkg-git-src/scripts/buildsystems/vcpkg.cmake)