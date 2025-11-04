/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <dlfcn.h>

#include <cstdint>
#include <functional>
#include <string_view>

namespace virtrust {

// see: libguestfs.h, it's a forward declaration in original header file
struct guestfs_h;

struct guestfs_add_drive_opts_argv {
  uint64_t bitmask;
#define GUESTFS_ADD_DRIVE_OPTS_READONLY_BITMASK (UINT64_C(1) << 0)
  int readonly;
#define GUESTFS_ADD_DRIVE_OPTS_FORMAT_BITMASK (UINT64_C(1) << 1)
  const char *format;
#define GUESTFS_ADD_DRIVE_OPTS_IFACE_BITMASK (UINT64_C(1) << 2)
  const char *iface;
#define GUESTFS_ADD_DRIVE_OPTS_NAME_BITMASK (UINT64_C(1) << 3)
  const char *name;
#define GUESTFS_ADD_DRIVE_OPTS_LABEL_BITMASK (UINT64_C(1) << 4)
  const char *label;
#define GUESTFS_ADD_DRIVE_OPTS_PROTOCOL_BITMASK (UINT64_C(1) << 5)
  const char *protocol;
#define GUESTFS_ADD_DRIVE_OPTS_SERVER_BITMASK (UINT64_C(1) << 6)
  char *const *server;
#define GUESTFS_ADD_DRIVE_OPTS_USERNAME_BITMASK (UINT64_C(1) << 7)
  const char *username;
#define GUESTFS_ADD_DRIVE_OPTS_SECRET_BITMASK (UINT64_C(1) << 8)
  const char *secret;
#define GUESTFS_ADD_DRIVE_OPTS_CACHEMODE_BITMASK (UINT64_C(1) << 9)
  const char *cachemode;
#define GUESTFS_ADD_DRIVE_OPTS_DISCARD_BITMASK (UINT64_C(1) << 10)
  const char *discard;
#define GUESTFS_ADD_DRIVE_OPTS_COPYONREAD_BITMASK (UINT64_C(1) << 11)
  int copyonread;
#define GUESTFS_ADD_DRIVE_OPTS_BLOCKSIZE_BITMASK (UINT64_C(1) << 12)
  int blocksize;
};

} // namespace virtrust