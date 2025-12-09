/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include "virtrust/utils/foreign_mounter.h"

#include <cstring>
#include <string>
#include <string_view>
#include <filesystem>
#include <regex>

#include "spdlog/fmt/fmt.h"

#include "virtrust/base/logger.h"
#include "virtrust/base/str_utils.h"
#include "virtrust/crypto/sm3.h"
#include "virtrust/dllib/common.h"
#include "virtrust/utils/file_io.h"

namespace virtrust {

namespace {
constexpr std::string_view DEFAULT_SHIM_EFI_REGEX_PATH = "/boot/efi/EFI/{}/shimaa64.efi";
constexpr std::string_view DEFAULT_GRUB_EFI_REGEX_PATH = "/boot/efi/EFI/{}/grubaa64.efi";
constexpr std::string_view DEFAULT_GRUB_CFG_REGEX_PATH = "/boot/efi/EFI/{}/grub.cfg";
constexpr std::string_view DEFAULT_BOOT_PATH = "/boot";
constexpr std::string_view DEFAULT_INITRD_PREFIX = "initrd";
constexpr std::string_view DEFAULT_LINUZ_PREFIX = "linux";
constexpr char PATH_SEPARATOR = '/';
constexpr std::string_view BACKEND_VALUE = "direct";
constexpr std::string_view BIOS_VERSION_FILE_PATH = "/sys/class/dmi/id/bios_version";
const std::regex GRUB_VERSION_REGEX(R"(GRUB\s+version)");

inline ForeignMounterRc ParseRc(DllibRc rc)
{
    switch (rc) {
        case DllibRc::OK:
            return ForeignMounterRc::OK;
        default:
            return ForeignMounterRc::ERROR;
    }
}

std::string LinuxDistroToString(LinuxDistro distro)
{
    switch (distro) {
        case LinuxDistro::OPENEULER:
            return "openEuler";
        case LinuxDistro::CENTOS:
            return "centos";
        case LinuxDistro::UBUNTU:
            return "ubuntu";
        case LinuxDistro::DEBIAN:
            return "debian";
        case LinuxDistro::FEDORA:
            return "fedora";
        default:
            return "unknown";
    }
}

size_t CountStrings(char **strs)
{
    size_t c = 0;
    if (strs != nullptr) {
        while (strs[c] != nullptr) {
            c++;
        }
    }
    return c;
}

void GuestfsFreeStringList(char **strs)
{
    if (strs == nullptr) {
        return;
    }
    for (size_t i = 0; strs[i] != nullptr; ++i) {
        free(strs[i]);
    }
    free(strs);
}
} // namespace

VerifyConfig::VerifyConfig(const std::string &guestName, const std::string &diskPath, const std::string &loaderPath,
                           const LinuxDistro distro)
    : guestName_(guestName), diskPath_(diskPath), loaderPath_(loaderPath), linuxDistro_(distro)
{}

std::string VerifyConfig::GetGuestName()
{
    return guestName_;
}

std::string VerifyConfig::GetDiskPath()
{
    return diskPath_;
}

std::string VerifyConfig::GetLoaderPath()
{
    return loaderPath_;
}

std::string VerifyConfig::GetShimPath()
{
    if (shimPath_.empty()) {
        shimPath_ = fmt::format(DEFAULT_SHIM_EFI_REGEX_PATH, LinuxDistroToString(linuxDistro_));
    }
    return shimPath_;
}

std::string VerifyConfig::GetGrubPath()
{
    if (grubPath_.empty()) {
        grubPath_ = fmt::format(DEFAULT_GRUB_EFI_REGEX_PATH, LinuxDistroToString(linuxDistro_));
    }
    return grubPath_;
}

std::string VerifyConfig::GetGrubCfgPath()
{
    if (grubCfgPath_.empty()) {
        grubCfgPath_ = fmt::format(DEFAULT_GRUB_CFG_REGEX_PATH, LinuxDistroToString(linuxDistro_));
    }
    return grubCfgPath_;
}

std::string VerifyConfig::GetInitrdPath()
{
    return initrdPath_;
}

std::string VerifyConfig::GetLinuzPath()
{
    return linuzPath_;
}

void VerifyConfig::ParseGrubCfgContent(const std::string &content)
{
    std::istringstream iss(content);
    std::string line;
    bool findInitrd = false;
    bool findLinuz = false;
    while (std::getline(iss, line)) {
        line = StrTrimWhitespace(line);
        if (line.empty()) {
            continue;
        }
        // find line which starts with "initrd" or "linux"
        if (StrStartsWith(line, DEFAULT_INITRD_PREFIX)) {
            initrdPath_ = ParseGrubCfgLine(line);
            if (initrdPath_.empty()) {
                VIRTRUST_LOG_ERROR("|ParseGrubCfgContent|END|||Get initrd path from grub.cfg failed.");
                return;
            }
            findInitrd = true;
        } else if (StrStartsWith(line, DEFAULT_LINUZ_PREFIX)) {
            linuzPath_ = ParseGrubCfgLine(line);
            if (linuzPath_.empty()) {
                VIRTRUST_LOG_ERROR("|ParseGrubCfgContent|END|||Get linuz path from grub.cfg failed.");
                return;
            }
            findLinuz = true;
        }
        // found all
        if (findInitrd && findLinuz) {
            return;
        }
    }
}

std::string VerifyConfig::ParseGrubCfgLine(const std::string &line)
{
    constexpr int lineSplitLimit = 2;

    auto parts = StrSplit(line);
    // if there are fewer than two substrings
    if (parts.size() < lineSplitLimit) {
        return "";
    }
    // the second substring is file name or path
    std::string filename = parts[1];

    // NOTE by cjm. We should check if the path is absolute
    // prefix already exists
    if (StrStartsWith(filename, DEFAULT_BOOT_PATH)) {
        return filename;
    }
    // add prefix
    return fmt::format("{}/{}", DEFAULT_BOOT_PATH, StrTrim(filename, PATH_SEPARATOR));
}

// read from vm
std::string VerifyConfig::GetBiosVersion(ForeignMounter &mounter)
{
    if (!mounter.CheckMount()) {
        VIRTRUST_LOG_ERROR("|GetBiosVersion|END|||Mounter should be mounted firstly.");
        return "";
    }

    std::string biosVersion;
    ForeignMounterRc rc = mounter.ReadFile(BIOS_VERSION_FILE_PATH, biosVersion);
    if (rc != ForeignMounterRc::OK) {
        VIRTRUST_LOG_ERROR("|GetBiosVersion|END|||Read file from image failed: {}.", BIOS_VERSION_FILE_PATH);
        return "";
    }

    return StrTrimWhitespace(biosVersion);
}

// read from host
std::string VerifyConfig::GetBiosVersion()
{
    std::string filePath(BIOS_VERSION_FILE_PATH);
    FileInputStream fis(filePath);
    auto biosVersion = fis.ReadAll();
    if (biosVersion.empty()) {
        VIRTRUST_LOG_ERROR("|GetBiosVersion|END|||Read BIOS version from {} failed.", BIOS_VERSION_FILE_PATH);
        return "";
    }
    return StrTrimWhitespace(biosVersion);
}

// 从grubaa64.efi文件中获取 GRUB 版本号
std::string VerifyConfig::GetGrubVersion(ForeignMounter &mounter) {
    if (!mounter.CheckMount()) {
        VIRTRUST_LOG_ERROR("|GetGrubVersion|END|||Mounter should be mounted firstly.");
        return "";
    }

    std::string content;
    ForeignMounterRc rc = mounter.ReadFile(GetGrubPath(), content);
    if (rc != ForeignMounterRc::OK) {
        VIRTRUST_LOG_ERROR("|GetGrubVersion|END|||Read file from image failed: {}.", GetGrubPath());
        return "";
    }

    auto lines = ExtractStringsFromBinary(content);
    std::string grubVersion;
    for (size_t i = 0; i < lines.size(); ++i) {
        if (std::regex_search(lines[i], GRUB_VERSION_REGEX)) {
            if (i + 1 < lines.size()) {
                grubVersion = lines[i + 1];  // 下一行即版本号
                break;
            }
        }
    }

    // 未找到
    if (grubVersion.empty()) {
        VIRTRUST_LOG_WARN(
            "|GetGrubVersion|END|||Failed to extract grub version, not found or has no following line in {}.",
            GetGrubPath());
        return "";
    }

    return StrTrimWhitespace(grubVersion);
}

std::string VerifyConfig::GetInitrdVersion()
{
    auto initrdPath = GetInitrdPath();
    if (initrdPath.empty()) {
        VIRTRUST_LOG_ERROR(
            "|GetInitrdVersion|END|||Should first initialize initrd path by parsing the grub config file.");
        return "";
    }

    std::filesystem::path p(initrdPath);
    return p.stem().string();
}


std::string VerifyConfig::GetLinuzVersion()
{
    auto linuzPath = GetLinuzPath();
    if (linuzPath.empty()) {
        VIRTRUST_LOG_ERROR(
            "|GetLinuzVersion|END|||Should first initialize linuz path by parsing the grub config file.");
        return "";
    }

    std::filesystem::path p(linuzPath);
    return p.filename().string();
}

ForeignMounterRc ForeignMounter::TryInit()
{
    if (libguestfs_.CheckOk() != DllibRc::OK) {
        return ParseRc(libguestfs_.Reload());
    }

    if (handle_ == nullptr) {
        handle_ = libguestfs_.guestfs_create();
    }

    if (handle_ == nullptr) {
        VIRTRUST_LOG_ERROR("|TryInit|END|returnF||Failed to create the guestfs handle.");
        return ForeignMounterRc::ERROR;
    }
    return ForeignMounterRc::OK;
}

ForeignMounterRc ForeignMounter::Mount(std::string_view imgPath, size_t osIndex)
{
    // Check whether our dllib has been successfully loaded
    if (!CheckOk()) {
        return ForeignMounterRc::ERROR;
    }

    auto res = libguestfs_.guestfs_set_backend(handle_, BACKEND_VALUE.data());
    if (res == -1) {
        VIRTRUST_LOG_ERROR("|Mount|END|returnF||Guestfs set backend failed.");
        return ForeignMounterRc::ERROR;
    }

    struct guestfs_add_drive_opts_argv optargs = {
        .bitmask = GUESTFS_ADD_DRIVE_OPTS_FORMAT_BITMASK | GUESTFS_ADD_DRIVE_OPTS_CACHEMODE_BITMASK,
        .format = "qcow2",
        .cachemode = "unsafe" // quick but unsafe
    };
    // Load qcow2 format image from imgPath
    // see: https://gitee.com/openeuler/qemu/issues/IADWBA
    res = libguestfs_.guestfs_add_drive_opts_argv(handle_, imgPath.data(), optargs);
    if (res == -1) {
        VIRTRUST_LOG_ERROR("|Mount|END|returnF||Guestfs adds drive opts failed.");
        return ForeignMounterRc::ERROR;
    }

    res = libguestfs_.guestfs_launch(handle_);
    if (res == -1) {
        VIRTRUST_LOG_ERROR("|Mount|END|returnF||Guestfs launch failed.");
        return ForeignMounterRc::ERROR;
    }

    char **roots = libguestfs_.guestfs_inspect_os(handle_);
    if (roots == nullptr) {
        VIRTRUST_LOG_ERROR("|Mount|END|returnF||No operating system found in image.");
        return ForeignMounterRc::ERROR;
    }

    size_t osCnt = CountStrings(roots);
    if (osIndex >= osCnt) {
        VIRTRUST_LOG_ERROR("|Mount|END|returnF||There are {} os in image, index out of range: {}.", osCnt, osIndex);
        GuestfsFreeStringList(roots);
        return ForeignMounterRc::ERROR;
    }

    char *root = roots[osIndex];
    ForeignMounterRc rc = MountFilesystems(root);
    GuestfsFreeStringList(roots);

    if (rc == ForeignMounterRc::OK) {
        isMount_ = true;
    }
    return rc;
}

ForeignMounterRc ForeignMounter::MountFilesystems(const std::string &root)
{
    // collect mountpoints and devices
    char **mountpoints = libguestfs_.guestfs_inspect_get_mountpoints(handle_, root.c_str());
    if (mountpoints == nullptr) {
        VIRTRUST_LOG_ERROR("|MountFilesystems|END|returnF||Get mountpoints failed.");
        return ForeignMounterRc::ERROR;
    }
    std::vector<MounterInfo> mps;
    constexpr int stepLen = 2;
    for (int i = 0; mountpoints[i] != nullptr && mountpoints[i + 1] != nullptr; i += stepLen) {
        mps.push_back(MounterInfo{mountpoints[i], mountpoints[i + 1], StrCountChar(mountpoints[i], PATH_SEPARATOR)});
    }

    // sort by directory level in ascending
    std::sort(mps.begin(), mps.end(), [](auto &a, auto &b) {
        return a.dirLevel != b.dirLevel ? a.dirLevel < b.dirLevel : a.mpt.size() < b.mpt.size();
    });

    // mount all file system
    for (auto &mp : mps) {
        auto &mountpoint = mp.mpt;
        auto &device = mp.device;
        // mount device to mountpoint
        int ret = libguestfs_.guestfs_mount_ro(handle_, device.c_str(), mountpoint.c_str());
        if (ret == -1) {
            GuestfsFreeStringList(mountpoints);
            VIRTRUST_LOG_ERROR("|MountFilesystems|END|returnF||Mount {} to {} failed.", device, mountpoint);
            GuestfsFreeStringList(mountpoints);
            return ForeignMounterRc::ERROR;
        }
    }

    GuestfsFreeStringList(mountpoints);
    return ForeignMounterRc::OK;
}

ForeignMounterRc ForeignMounter::ReadFile(std::string_view filePath, std::string &fileContent)
{
    if (!isMount_) {
        VIRTRUST_LOG_ERROR("|ReadFile|END|||The image has not been loaded.");
        return ForeignMounterRc::ERROR;
    }

    // check file whether exist in image
    int exists = libguestfs_.guestfs_exists(handle_, filePath.data());
    if (exists != 1) {
        VIRTRUST_LOG_WARN("|ReadFile|END||file path is: {}|File not exist in image.", filePath);
        return ForeignMounterRc::FILE_NOT_EXIST;
    }

    // check whether is a file
    int isFile = libguestfs_.guestfs_is_file(handle_, filePath.data());
    if (isFile != 1) {
        VIRTRUST_LOG_ERROR("|ReadFile|END|||file path is: {}|It is not a file.", filePath);
        return ForeignMounterRc::ERROR;
    }

    // read content
    size_t size;
    char *content = libguestfs_.guestfs_read_file(handle_, filePath.data(), &size);
    if (content == nullptr) {
        VIRTRUST_LOG_ERROR("|ReadFile|END|||file path is: {}|Read this file failed.", filePath);
        return ForeignMounterRc::ERROR;
    }

    fileContent = std::string(content, size);
    free(content);
    return ForeignMounterRc::OK;
}

ForeignMounterRc ForeignMounter::DoSm3OnVmFile(std::string_view filePath, std::vector<uint8_t> &sm3Data)
{
    std::string fileContent;
    ForeignMounterRc rc = ReadFile(filePath, fileContent);
    if (rc == ForeignMounterRc::FILE_NOT_EXIST) {
        return rc;
    }

    if (rc != ForeignMounterRc::OK) {
        VIRTRUST_LOG_ERROR("|DoSm3OnVmFile|END|returnF||Read file failed: {}.", filePath);
        return ForeignMounterRc::ERROR;
    }
    if (virtrust::DoSm3(fileContent, sm3Data) != Sm3Rc::OK) {
        return ForeignMounterRc::ERROR;
    }
    return ForeignMounterRc::OK;
}

ForeignMounterRc ForeignMounter::Unmount() noexcept
{
    if (handle_ == nullptr) {
        return ForeignMounterRc::OK;
    }
    isMount_ = false;
    if (libguestfs_.guestfs_umount_all(handle_) == -1) {
        VIRTRUST_LOG_ERROR("|Unmount|END|||Guestfs umount all failed.");
        return ForeignMounterRc::ERROR;
    }
    return ForeignMounterRc::OK;
}

ForeignMounterRc ForeignMounter::EnableStrErrTrace()
{
    return libguestfs_.guestfs_set_trace(handle_, 1) == 0 ? ForeignMounterRc::OK : ForeignMounterRc::ERROR;
}

ForeignMounterRc ForeignMounter::DisableStrErrTrace()
{
    return libguestfs_.guestfs_set_trace(handle_, 0) == 0 ? ForeignMounterRc::OK : ForeignMounterRc::ERROR;
}

} // namespace virtrust
