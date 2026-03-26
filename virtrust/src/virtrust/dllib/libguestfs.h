/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <dlfcn.h>
#include <string_view>

#include "virtrust/dllib/common.h"
#include "virtrust/dllib/libguestfs_defines.h"

#ifdef VIRTRUST_MOCK
#include "virtrust/dllib/mock/libguestfs_mock.h"
#endif

namespace virtrust {

#ifdef VIRTRUST_MOCK
// Use Mock implementation in fuzz mode
using Libguestfs = LibguestfsMock;
#else
// Use real implementation in production mode
// libguestfs api
class Libguestfs : public DlLibBase {
public:
    ~Libguestfs() = default;
    Libguestfs(const Libguestfs &) = delete;
    void operator=(const Libguestfs &) = delete;

    // Singleton instance
    static Libguestfs &GetInstance()
    {
        static Libguestfs instance;
        return instance;
    }

    // Reload all functions
    DllibRc Reload()
    {
        SelfDlClose();
        LoadAll();
        return CheckOk();
    }

    // Declare all functions that you need
    // NOTE Please make sure the class instance is inited before calling those
    // functions

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

private:
    DllibRc LoadAll()
    {
        // NOTE explicitly dlopen shared library
        auto ret = SelfDlOpen();
        if (ret != DllibRc::OK) {
            return ret;
        }
        if (DLLIB_SELF_DLSYM(guestfs_create) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(guestfs_set_backend) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(guestfs_add_drive_opts_argv) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(guestfs_launch) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(guestfs_inspect_os) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(guestfs_inspect_get_mountpoints) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(guestfs_mount_ro) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(guestfs_umount_all) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(guestfs_close) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(guestfs_set_trace) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(guestfs_exists) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(guestfs_is_file) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(guestfs_read_file) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        return DllibRc::OK;
    }

    Libguestfs() : DlLibBase(LIB_NAME)
    {
        LoadAll();
    }

    static constexpr std::string_view LIB_NAME = "libguestfs.so";
};
#endif

} // namespace virtrust