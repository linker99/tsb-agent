/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#ifndef USE_MOCK_TSB_AGENT
#error "USE_MOCK_TSB_AGENT is not defined. Please define it if your want to use mock TSB agent."
#else

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include "mock/tsb_agent_itf.h"
#include "mock/v_root.h"
#include <securec.h>
#include "spdlog/spdlog.h"

namespace virtrust::mock {
constexpr std::string_view STORAGE_FILENAME = "mock-tsb-agent.save";

enum class TsbAgentRc {
    OK,
    ERROR
};

class TsbAgentImpl {
public:
    // Destructor
    ~TsbAgentImpl() = default;

    TsbAgentImpl(const TsbAgentImpl &) = delete;

    TsbAgentImpl &operator=(const TsbAgentImpl &) = delete;

    // Get singleton isntance
    static TsbAgentImpl &GetInstance()
    {
        static TsbAgentImpl instance;
        return instance;
    }

    std::string GetPath()
    {
        return storageFilePath_.c_str();
    }

    // Lifetime management

    std::vector<Description> GetVRoots();

    TsbAgentRc CreateVRoot(const std::string &uuid, const std::string &name);

    TsbAgentRc StartVRoot(const std::string &uuid);

    TsbAgentRc StopVRoot(const std::string &uuid);

    TsbAgentRc RemoveVRoot(const std::string &uuid);

    // Update measure values
    TsbAgentRc UpdateMeasure(const std::string &uuid, MeasureInfo bios, MeasureInfo shim, MeasureInfo grub,
                             MeasureInfo grubCfg, MeasureInfo kernel, MeasureInfo initrd);

    TsbAgentRc CheckMeasure(const std::string &uuid, MeasureInfo bios, MeasureInfo shim, MeasureInfo grub,
                            MeasureInfo grubCfg, MeasureInfo kernel, MeasureInfo initrd);

    // Migration

    TsbAgentRc GetReport(const std::string &uuid);
    TsbAgentRc Migration1GetRandPk(const std::string &uuid);
    TsbAgentRc Migration2CheckPeerPk();
    TsbAgentRc Migration3GetVRootCipher();
    TsbAgentRc Migration4ImportVRootCipher();

    TsbAgentRc MigrationNotify();

private:
    TsbAgentImpl() = default;
    std::unordered_map<std::string, std::unique_ptr<VRoot>> vRootMap_;

    // REVIEW migration data
    std::vector<char> pk_;

    // default to current location
    std::filesystem::path storageFilePath_ = std::filesystem::current_path() / STORAGE_FILENAME;
};
} // namespace virtrust::mock

#endif
