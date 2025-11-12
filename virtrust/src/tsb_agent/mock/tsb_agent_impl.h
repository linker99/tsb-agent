/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "tsb_agent/mock/v_root.h"
#include "tsb_agent/tsb_agent.h"

namespace virtrust::mock {
constexpr std::string_view STORAGE_FILENAME = "mock-tsb-agent.save";

enum class TsbAgentRc { OK, ERROR };

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

    // Clear all virtual roots (for testing)
    void ClearAllVRoots();

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

    TsbAgentRc GetReport(const std::string &pUuid, const std::string &vUuid, struct trust_report_new *hostreport,
                         struct trust_report_new *vmreport);

    TsbAgentRc VerifyReport(const std::string &pUuid, const std::string &vUuid, struct trust_report_new *hostreport,
                            struct trust_report_new *vmreport);

    TsbAgentRc MigrationGetCert(const std::string &vUuid, std::vector<uint8_t> &cert, std::vector<uint8_t> &pubkey);

    // TsbAgentRc MigrationGetVRootCipher(char *vUuid, char **cipher);

    // TsbAgentRc MigrationImportVRootCipher(char *vUuid, char *cipher);

    // TsbAgentRc MigrationNotify(char *vUuid, int status);

private:
    TsbAgentImpl() = default;
    std::unordered_map<std::string, std::unique_ptr<VRoot>> vRootMap_;

    // REVIEW migration data
    std::vector<char> pk_;

    // default to current location
    std::filesystem::path storageFilePath_ = std::filesystem::current_path() / STORAGE_FILENAME;
};
} // namespace virtrust::mock
