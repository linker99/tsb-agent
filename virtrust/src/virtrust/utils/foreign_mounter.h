/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <string>
#include <string_view>

#include "virtrust/base/logger.h"
#include "virtrust/dllib/libguestfs.h"

namespace virtrust {

enum class LinuxDistro { OPENEULER, CENTOS, UBUNTU, DEBIAN, FEDORA };

class VerifyConfig {
public:
  VerifyConfig() = default;

  VerifyConfig(const std::string &guestName, const std::string &diskPath,
               const std::string &loaderPath,
               LinuxDistro distro = LinuxDistro::OPENEULER);

  std::string GetGuestName();
  std::string GetDiskPath();
  std::string GetLoaderPath();
  std::string GetShimPath();
  std::string GetGrubPath();
  std::string GetGrubCfgPath();
  std::string GetInitrdPath();
  std::string GetLinuzPath();

  void ParseGrubCfgContent(const std::string &content);

private:
  std::string guestName_;
  std::string diskPath_;
  std::string loaderPath_;
  std::string shimPath_;
  std::string grubPath_;
  std::string grubCfgPath_;
  std::string initrdPath_;
  std::string linuzPath_;
  LinuxDistro linuxDistro_;

  std::string ParseGrubCfgLine(const std::string &line);
};

enum class ForeignMounterRc : uint32_t {
  OK = 0,
  ERROR = 1,
  FILE_NOT_EXIST = 2,
};

struct MounterInfo {
  std::string mpt;    // mount point
  std::string device; // mount device
  size_t dirLevel;
};

class ForeignMounter {
public:
  ForeignMounter() {
    // try to init handle, discarding the return process
    TryInit();
  };

  ~ForeignMounter() noexcept {
    Unmount();
    if (handle_ != nullptr) {
      libguestfs_.guestfs_close(handle_);
      handle_ = nullptr;
    }
  };

  ForeignMounter(const ForeignMounter &) = delete;
  ForeignMounter &operator=(const ForeignMounter &) = delete;
  ForeignMounter(ForeignMounter &&) = delete;
  ForeignMounter &operator=(ForeignMounter &&) = delete;

  // low-level api, try to initialize handle
  ForeignMounterRc TryInit();

  // Mount virtual machine img path to filesystem
  ForeignMounterRc Mount(std::string_view imgPath, size_t osIndex = 0);

  // Read file content to string
  ForeignMounterRc ReadFile(std::string_view filePath, std::string &content);

  // Get file sm3
  ForeignMounterRc DoSm3OnVmFile(std::string_view filePath,
                                 std::vector<uint8_t> &sm3Data);

  // Unmount
  ForeignMounterRc Unmount() noexcept;

  // Check if everything is okay
  bool CheckOk() {
    return handle_ != nullptr && libguestfs_.CheckOk() == DllibRc::OK;
  }

  bool CheckMount() const { return isMount_; }

  // Enable trace from libguestfs
  ForeignMounterRc EnableStrErrTrace();

  // Disable trace from libguestfs
  ForeignMounterRc DisableStrErrTrace();

private:
  bool isMount_ = false;
  guestfs_h *handle_ = nullptr;
  Libguestfs &libguestfs_ = Libguestfs::GetInstance();

  ForeignMounterRc MountFilesystems(const std::string &root);
};

} // namespace virtrust
