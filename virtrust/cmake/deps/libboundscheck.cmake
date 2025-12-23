# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set(_libboundscheck_src "${CMAKE_DEPS_SRCDIR}/libboundscheck-src")
if(EXISTS "${_libboundscheck_src}")
  message(STATUS "Using local source for libboundscheck: ${_libboundscheck_src}")
  ExternalProject_Add(
    libboundscheck-src
    PREFIX ${CMAKE_DEPS_PREFIX}
    SOURCE_DIR ${_libboundscheck_src}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
    DOWNLOAD_COMMAND ""
    UPDATE_COMMAND ""
    INSTALL_COMMAND cp include/securec.h ${CMAKE_DEPS_INCLUDEDIR}
    COMMAND cp include/securectype.h ${CMAKE_DEPS_INCLUDEDIR}
    COMMAND cp lib/libboundscheck${CMAKE_SHARED_LIBRARY_SUFFIX}
            ${CMAKE_DEPS_LIBDIR}
    BUILD_IN_SOURCE On
    EXCLUDE_FROM_ALL true
    LOG_CONFIGURE On
    LOG_BUILD On
    LOG_INSTALL On)
else()
  ExternalProject_Add(
    libboundscheck-src
    GIT_REPOSITORY https://gitcode.com/openeuler/libboundscheck
    GIT_TAG master
    GIT_SHALLOW On
    PREFIX ${CMAKE_DEPS_PREFIX}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
    UPDATE_COMMAND ""
    INSTALL_COMMAND cp include/securec.h ${CMAKE_DEPS_INCLUDEDIR}
    COMMAND cp include/securectype.h ${CMAKE_DEPS_INCLUDEDIR}
    COMMAND cp lib/libboundscheck${CMAKE_SHARED_LIBRARY_SUFFIX}
            ${CMAKE_DEPS_LIBDIR}
    BUILD_IN_SOURCE On
    EXCLUDE_FROM_ALL true
    LOG_DOWNLOAD On
    LOG_CONFIGURE On
    LOG_BUILD On
    LOG_INSTALL On)
endif()

add_library(libboundscheck-itf INTERFACE)
target_link_directories(libboundscheck-itf INTERFACE ${CMAKE_DEPS_LIBDIR})
target_link_libraries(libboundscheck-itf
                      INTERFACE libboundscheck${CMAKE_SHARED_LIBRARY_SUFFIX})
add_dependencies(libboundscheck-itf libboundscheck-src)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Deps::secure_c ALIAS libboundscheck-itf)
