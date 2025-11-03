# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

ExternalProject_Add(
  libboundscheck
  GIT_REPOSITORY
    https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
  GIT_TAG v1.1.16
  PREFIX ${CMAKE_DEPS_PREFIX}
  EXCLUDE_FROM_ALL true
  LOG_DOWNLOAD On
  LOG_CONFIGURE On
  LOG_BUILD On
  LOG_INSTALL On)

import_static_lib_from(libsecurec libboundscheck)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Deps::secure_c ALIAS libsecurec)
