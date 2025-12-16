/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#ifdef VIRTRUST_MOCK

#include <cstring>
#include <cstdlib>
#include <string_view>

#include "virtrust/dllib/common.h"
#include "virtrust/dllib/libguestfs_defines.h"

namespace virtrust {

// libguestfs Mock implementation for fuzzing
class LibguestfsMock : public DlLibBase {
public:
    ~LibguestfsMock() = default;
    LibguestfsMock(const LibguestfsMock &) = delete;
    void operator=(const LibguestfsMock &) = delete;

    // Singleton instance
    static LibguestfsMock &GetInstance()
    {
        static LibguestfsMock instance;
        return instance;
    }

    // Reload all functions (Mock implementation)
    DllibRc Reload()
    {
        // Mock implementation always succeeds
        return DllibRc::OK;
    }

    // Declare all functions that you need
    // Create guestfs context
    DlFun<guestfs_h *> guestfs_create;

    DlFun<int, guestfs_h *, const char *> guestfs_set_backend;

    DlFun<int, guestfs_h *, const char *, const struct guestfs_add_drive_opts_argv> guestfs_add_drive_opts_argv;

    DlFun<int, guestfs_h *> guestfs_launch;

    DlFun<char **, guestfs_h *> guestfs_inspect_os;

    DlFun<char **, guestfs_h *, const char *> guestfs_inspect_get_mountpoints;

    DlFun<int, guestfs_h *, const char *, const char *> guestfs_mount_ro;

    DlFun<int, guestfs_h *> guestfs_umount_all;

    DlFun<void, guestfs_h *> guestfs_close;

    DlFun<int, guestfs_h *, int> guestfs_set_trace;

    DlFun<int, guestfs_h *, const char *> guestfs_exists;

    DlFun<int, guestfs_h *, const char *> guestfs_is_file;

    DlFun<char *, guestfs_h *, const char *, size_t *> guestfs_read_file;

    DllibRc CheckOk() const;
private:
    void InitializeMockFunctions();

    LibguestfsMock() : DlLibBase("libguestfs.so")
    {
        InitializeMockFunctions();
    }
};

} // namespace virtrust

#endif // VIRTRUST_MOCK