# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# HACK compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=pragmas")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-class-memaccess")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-implicit-fallthrough")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-template-body")

set(_rapidjson_src "${CMAKE_DEPS_SRCDIR}/rapidjson")
if(EXISTS "${_rapidjson_src}")
  message(STATUS "Using local source for rapidjson: ${_rapidjson_src}")
  ExternalProject_Add(
    rapidjson
    SOURCE_DIR ${_rapidjson_src}
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_DEPS_PREFIX}
               -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
               -DCMAKE_SKIP_RPATH=TRUE
               -DCMAKE_BUILD_TYPE=Release
               -DRAPIDJSON_BUILD_TESTS=OFF
               -DRAPIDJSON_BUILD_DOC=OFF
               -DRAPIDJSON_BUILD_EXAMPLES=OFF
               -DRAPIDJSON_BUILD_THIRDPARTY_GTEST=OFF
    PREFIX ${CMAKE_DEPS_PREFIX}
    DOWNLOAD_COMMAND ""
    UPDATE_COMMAND ""
    EXCLUDE_FROM_ALL true
    LOG_CONFIGURE On
    LOG_BUILD On
    LOG_INSTALL On)
else()
  ExternalProject_Add(
    rapidjson
    # use gitee first
    GIT_REPOSITORY https://gitee.com/Tencent/RapidJSON.git
    GIT_TAG v1.1.0
    GIT_SHALLOW On
    GIT_SUBMODULES "" # HACK no update of submodules, see CMP0097 policy
    # alternatively, download through gitub
    URL https://github.com/Tencent/rapidjson/archive/refs/tags/v1.1.0.tar.gz
    URL_HASH
      SHA256=bf7ced29704a1e696fbccf2a2b4ea068e7774fa37f6d7dd4039d0787f8bed98e
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_DEPS_PREFIX}
               -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
               -DCMAKE_SKIP_RPATH=TRUE
               -DCMAKE_BUILD_TYPE=Release
               -DRAPIDJSON_BUILD_TESTS=OFF
               -DRAPIDJSON_BUILD_DOC=OFF
               -DRAPIDJSON_BUILD_EXAMPLES=OFF
               -DRAPIDJSON_BUILD_THIRDPARTY_GTEST=OFF
    PREFIX ${CMAKE_DEPS_PREFIX}
    UPDATE_COMMAND ""
    EXCLUDE_FROM_ALL true
    DOWNLOAD_EXTRACT_TIMESTAMP On
    LOG_DOWNLOAD On
    LOG_CONFIGURE On
    LOG_BUILD On
    LOG_INSTALL On)
endif()

# NOTE rapidjson is a header-only lib
add_library(librapidjson INTERFACE)
target_include_directories(librapidjson INTERFACE ${CMAKE_DEPS_INCLUDEDIR})
add_dependencies(librapidjson rapidjson)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Deps::rapidjson ALIAS librapidjson)
