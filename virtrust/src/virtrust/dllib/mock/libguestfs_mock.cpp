/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#ifdef VIRTRUST_MOCK

#include "virtrust/dllib/mock/libguestfs_mock.h"

#include <securec.h>

namespace virtrust {

DllibRc LibguestfsMock::CheckOk() const
{
    return DllibRc::OK;
}

void LibguestfsMock::InitializeMockFunctions()
{
    // Mock guestfs创建
    guestfs_create = DlFun<guestfs_h *>("guestfs_create",
        []() -> guestfs_h* {
            // Always succeed for stable unit testing - removed random failure logic
            return reinterpret_cast<guestfs_h*>(0x87654321); // Mock guestfs句柄
        });

    // Mock backend设置
    guestfs_set_backend = DlFun<int, guestfs_h *, const char *>("guestfs_set_backend",
        [](guestfs_h* g, const char* backend) -> int {
            (void)g; (void)backend;
            return 0; // 总是成功
        });

    // Mock drive添加
    guestfs_add_drive_opts_argv = DlFun<int, guestfs_h *, const char *, const struct guestfs_add_drive_opts_argv>("guestfs_add_drive_opts_argv",
        [](guestfs_h* g, const char* filename, const struct guestfs_add_drive_opts_argv optargs) -> int {
            (void)g; (void)filename; (void)optargs;
            // Always succeed for stable unit testing - removed random failure logic
            return 0; // 成功
        });

    // Mock launch
    guestfs_launch = DlFun<int, guestfs_h *>("guestfs_launch",
        [](guestfs_h* g) -> int {
            (void)g;
            // Always succeed for stable unit testing - removed random failure logic
            return 0; // 成功
        });

    // Mock inspect_os - 返回Mock的操作系统列表
    guestfs_inspect_os = DlFun<char **, guestfs_h *>("guestfs_inspect_os",
        [](guestfs_h* g) -> char** {
            (void)g;
            // Always succeed for stable unit testing - removed random failure logic
            // 分配并返回Mock的操作系统列表
            char **roots = static_cast<char**>(malloc(3 * sizeof(char*)));
            if (roots == nullptr) {
                return nullptr;
            }

            roots[0] = strdup("/dev/sda1"); // Mock根文件系统
            roots[1] = strdup("/dev/sda2"); // Mock第二个分区
            roots[2] = nullptr; // 列表结束

            return roots;
        });

    // Mock inspect_get_mountpoints - 返回Mock的挂载点
    guestfs_inspect_get_mountpoints = DlFun<char **, guestfs_h *, const char *>("guestfs_inspect_get_mountpoints",
        [](guestfs_h* g, const char* root) -> char** {
            (void)g; (void)root;
            // 分配并返回Mock的挂载点列表
            char **mountpoints = static_cast<char**>(malloc(7 * sizeof(char*)));
            if (mountpoints == nullptr) {
                return nullptr;
            }

            mountpoints[0] = strdup("/");         // 设备
            mountpoints[1] = strdup("/");         // 挂载点
            mountpoints[2] = strdup("/dev/sda1"); // 设备
            mountpoints[3] = strdup("/boot");     // 挂载点
            mountpoints[4] = strdup("/dev/sda2"); // 设备
            mountpoints[5] = strdup("/home");     // 挂载点
            mountpoints[6] = nullptr;             // 列表结束

            return mountpoints;
        });

    // Mock mount_ro
    guestfs_mount_ro = DlFun<int, guestfs_h *, const char *, const char *>("guestfs_mount_ro",
        [](guestfs_h* g, const char* device, const char* mountpoint) -> int {
            (void)g; (void)device; (void)mountpoint;
            // Always succeed for stable unit testing - removed random failure logic
            return 0; // 成功
        });

    // Mock umount_all
    guestfs_umount_all = DlFun<int, guestfs_h *>("guestfs_umount_all",
        [](guestfs_h* g) -> int {
            (void)g;
            return 0; // 总是成功
        });

    // Mock close
    guestfs_close = DlFun<void, guestfs_h *>("guestfs_close",
        [](guestfs_h* g) -> void {
            (void)g;
            // Mock实现，不做任何操作
        });

    // Mock set_trace
    guestfs_set_trace = DlFun<int, guestfs_h *, int>("guestfs_set_trace",
        [](guestfs_h* g, int trace) -> int {
            (void)g; (void)trace;
            return 0; // 总是成功
        });

    // Mock exists - 根据文件路径返回不同结果
    guestfs_exists = DlFun<int, guestfs_h *, const char *>("guestfs_exists",
        [](guestfs_h* g, const char* path) -> int {
            (void)g;
            // Mock常见系统文件存在
            if (strstr(path, "bios") != nullptr ||
                strstr(path, "grub") != nullptr ||
                strstr(path, "grubaa64") != nullptr ||
                strstr(path, "shimaa64") != nullptr ||
                strstr(path, "efi") != nullptr ||
                strstr(path, "vmlinuz") != nullptr ||
                strstr(path, "initramfs") != nullptr ||
                strstr(path, "boot") != nullptr ||
                strstr(path, ".cfg") != nullptr) {
                return 1; // 文件存在
            }
            return 0; // 文件不存在
        });

    // Mock is_file
    guestfs_is_file = DlFun<int, guestfs_h *, const char *>("guestfs_is_file",
        [](guestfs_h* g, const char* path) -> int {
            (void)g;
            // Mock常见系统文件都是文件
            if (strstr(path, "bios") != nullptr ||
                strstr(path, "grub") != nullptr ||
                strstr(path, "grubaa64") != nullptr ||
                strstr(path, "shimaa64") != nullptr ||
                strstr(path, ".efi") != nullptr ||
                strstr(path, "vmlinuz") != nullptr ||
                strstr(path, "initramfs") != nullptr ||
                strstr(path, ".cfg") != nullptr) {
                return 1; // 是文件
            }
            return 0; // 不是文件
        });

    // Mock read_file - 根据文件路径返回不同Mock内容
    guestfs_read_file = DlFun<char *, guestfs_h *, const char *, size_t *>("guestfs_read_file",
        [](guestfs_h* g, const char* path, size_t* size) -> char* {
            (void)g;
            // Always succeed for stable unit testing - removed random failure logic
            const char* content = nullptr;
            size_t content_size = 0;

            // 根据文件名关键字返回特定的Mock内容
            if (strstr(path, "grub.cfg") != nullptr) {
                // grub.cfg文件：2行内容
                content = "linux /vmlinuz-6.6.0\ninitrd /initramfs-6.6.0";
                content_size = strlen(content);
            } else if (strstr(path, "bios_version") != nullptr) {
                // bios_version文件：1行内容
                content = "6.66";
                content_size = strlen(content);
            } else if (strstr(path, "grubaa64") != nullptr) {
                // grubaa64.efi文件：2行内容
                content = "GRUB  version\n6.66";
                content_size = strlen(content);
            } else if (strstr(path, "shimaa64") != nullptr) {
                // shimaa64.efi文件：随机内容
                content = "mock-shim-binary-content-xyz123";
                content_size = strlen(content);
            } else if (strstr(path, "vmlinuz") != nullptr) {
                content = "mock-kernel-binary-content-abc456";
                content_size = strlen(content);
            } else if (strstr(path, "initramfs") != nullptr) {
                content = "mock-initramfs-binary-content-def789";
                content_size = strlen(content);
            } else {
                // 默认内容
                content = "mock-default-file-content";
                content_size = strlen(content);
            }

            // 分配内存并复制内容
            char* result = static_cast<char*>(malloc(content_size + 1));
            if (result != nullptr) {
                if (memcpy_s(result, content_size + 1, content, content_size) != EOK) {
                    free(result);
                    return nullptr;
                }
                result[content_size] = '\0';
                *size = content_size;
            }

            return result;
        });
}

} // namespace virtrust

#endif // VIRTRUST_MOCK