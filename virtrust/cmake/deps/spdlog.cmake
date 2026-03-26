# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# HACK spdlog installs in lib64
file(MAKE_DIRECTORY ${CMAKE_DEPS_PREFIX}/lib64)

set(_spdlog_src "${CMAKE_DEPS_SRCDIR}/spdlog")
if(EXISTS "${_spdlog_src}")
  message(STATUS "Using local source for spdlog: ${_spdlog_src}")
  ExternalProject_Add(
    spdlog
    SOURCE_DIR ${_spdlog_src}
    CMAKE_ARGS -DCMAKE_POSITION_INDEPENDENT_CODE=On
               -DCMAKE_INSTALL_PREFIX=${CMAKE_DEPS_PREFIX}
               -DSPDLOG_BUILD_EXAMPLE=OFF
    PREFIX ${CMAKE_DEPS_PREFIX}
    DOWNLOAD_COMMAND ""
    UPDATE_COMMAND ""
    EXCLUDE_FROM_ALL true
    BUILD_BYPRODUCTS ${CMAKE_DEPS_LIBDIR}/libspdlog${CMAKE_STATIC_LIBRARY_SUFFIX}
    LOG_CONFIGURE On
    LOG_BUILD On
    LOG_INSTALL On)
else()
  ExternalProject_Add(
    spdlog
    # use gitee first
    GIT_REPOSITORY https://gitee.com/mirrors_trending/spdlog.git
    GIT_TAG v1.14.1
    GIT_SHALLOW On
    # alternatively, download through gitub
    URL https://github.com/gabime/spdlog/archive/refs/tags/v1.14.1.tar.gz
    URL_HASH
      SHA256=1586508029a7d0670dfcb2d97575dcdc242d3868a259742b69f100801ab4e16b
    CMAKE_ARGS -DCMAKE_POSITION_INDEPENDENT_CODE=On
               -DCMAKE_INSTALL_PREFIX=${CMAKE_DEPS_PREFIX}
               -DSPDLOG_BUILD_EXAMPLE=OFF
    PREFIX ${CMAKE_DEPS_PREFIX}
    UPDATE_COMMAND ""
    EXCLUDE_FROM_ALL true
    DOWNLOAD_EXTRACT_TIMESTAMP On
    BUILD_BYPRODUCTS ${CMAKE_DEPS_LIBDIR}/libspdlog${CMAKE_STATIC_LIBRARY_SUFFIX}
    LOG_DOWNLOAD On
    LOG_CONFIGURE On
    LOG_BUILD On
    LOG_INSTALL On)
endif()

import_static_lib_from(libspdlog spdlog)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Deps::spdlog ALIAS libspdlog)
