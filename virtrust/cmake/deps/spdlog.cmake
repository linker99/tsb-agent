# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# HACK spdlog installs in lib64
file(MAKE_DIRECTORY ${CMAKE_DEPS_INSTALL_PREFIX}/lib64)

ExternalProject_Add(
  spdlog
  URL https://github.com/gabime/spdlog/archive/refs/tags/v1.14.1.tar.gz
  URL_HASH
    SHA256=1586508029a7d0670dfcb2d97575dcdc242d3868a259742b69f100801ab4e16b
  CMAKE_ARGS -DCMAKE_POSITION_INDEPENDENT_CODE=On
             -DCMAKE_CXX_STANDARD=17
             -DCMAKE_C_STANDARD_REQUIRED=Yes
             -DCMAKE_INSTALL_PREFIX=${CMAKE_DEPS_INSTALL_PREFIX}
             -DCMAKE_CPP_FLAGS=-isystem\ ${CMAKE_DEPS_INCLUDEDIR}
  PREFIX ${CMAKE_DEPS_INSTALL_PREFIX}
  UPDATE_COMMAND ""
  EXCLUDE_FROM_ALL true
  DOWNLOAD_EXTRACT_TIMESTAMP On
  BUILD_BYPRODUCTS ${CMAKE_DEPS_LIBDIR}/libspdlog${CMAKE_STATIC_LIBRARY_SUFFIX}
  LOG_DOWNLOAD On
  LOG_CONFIGURE On
  LOG_BUILD On
  LOG_INSTALL On)

import_static_lib_from(libspdlog spdlog)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Deps::spdlog ALIAS libspdlog)
