# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

ExternalProject_Add(
  libboundscheck-src
  GIT_REPOSITORY https://gitee.com/openeuler/libboundscheck
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

add_library(libboundscheck-itf INTERFACE)
target_link_directories(libboundscheck-itf INTERFACE ${CMAKE_DEPS_LIBDIR})
target_link_libraries(libboundscheck-itf
                      INTERFACE libboundscheck${CMAKE_SHARED_LIBRARY_SUFFIX})
add_dependencies(libboundscheck-itf libboundscheck-src)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Deps::secure_c ALIAS libboundscheck-itf)
