# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

ExternalProject_Add(
  openssl
  PREFIX ${CMAKE_DEPS_PREFIX}
  # use gitee first
  GIT_REPOSITORY https://gitee.com/mirrors/openssl.git
  GIT_TAG openssl-3.3.2
  GIT_SHALLOW On
  # alternatively, download through gitub
  URL https://github.com/openssl/openssl/archive/refs/tags/openssl-3.3.2.tar.gz
  URL_HASH
    SHA256=bedbb16955555f99b1a7b1ba90fc97879eb41025081be359ecd6a9fcbdf1c8d2
  CONFIGURE_COMMAND
    ./Configure no-legacy no-weak-ssl-ciphers no-tests no-shared no-ui-console
    no-docs no-apps --banner=Finished --release --libdir=${CMAKE_INSTALL_LIBDIR}
    --prefix=${CMAKE_DEPS_PREFIX} -w
  BUILD_COMMAND make build_sw
  UPDATE_COMMAND ""
  INSTALL_COMMAND make install_sw
  BUILD_IN_SOURCE On
  DOWNLOAD_EXTRACT_TIMESTAMP On
  BUILD_BYPRODUCTS ${CMAKE_DEPS_LIBDIR}/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}
  BUILD_BYPRODUCTS ${CMAKE_DEPS_LIBDIR}/libssl${CMAKE_STATIC_LIBRARY_SUFFIX}
  EXCLUDE_FROM_ALL true
  LOG_DOWNLOAD On
  LOG_CONFIGURE On
  LOG_BUILD On
  LOG_INSTALL On)

import_static_lib_from(libcrypto openssl)
import_static_lib_from(libssl openssl)

target_link_libraries(libssl INTERFACE libcrypto)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Deps::openssl ALIAS libssl)
