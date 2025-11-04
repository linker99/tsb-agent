# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# HACK compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=pragmas")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-class-memaccess")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-implicit-fallthrough")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-template-body")

ExternalProject_Add(
  rapidjson
  URL https://github.com/Tencent/rapidjson/archive/refs/tags/v1.1.0.tar.gz
  URL_HASH
    SHA256=bf7ced29704a1e696fbccf2a2b4ea068e7774fa37f6d7dd4039d0787f8bed98e
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_DEPS_INSTALL_PREFIX}
             -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS} -DCMAKE_SKIP_RPATH=TRUE
  PREFIX ${CMAKE_DEPS_INSTALL_PREFIX}
  UPDATE_COMMAND ""
  EXCLUDE_FROM_ALL true
  DOWNLOAD_EXTRACT_TIMESTAMP On
  LOG_DOWNLOAD On
  LOG_CONFIGURE On
  LOG_BUILD On
  LOG_INSTALL On)

# NOTE rapidjson is a header-only lib
add_library(librapidjson INTERFACE)
target_include_directories(librapidjson INTERFACE ${CMAKE_DEPS_INCLUDEDIR})
add_dependencies(librapidjson rapidjson)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Deps::rapidjson ALIAS librapidjson)
