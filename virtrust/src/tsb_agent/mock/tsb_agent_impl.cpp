/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include "tsb_agent/mock/tsb_agent_impl.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string_view>
#include <vector>

#include "spdlog/spdlog.h"

namespace virtrust::mock {
namespace {
constexpr std::string_view TSB_AGENT_FILE_SEP = ",";
constexpr uint32_t SM3_OUTPUT_BYTES = 32;
constexpr std::string_view DEFAULT_VERSION = "v1.0";

void StrSplit(std::string_view src, std::string_view sep, std::vector<std::string> &out)
{
    if (sep.empty() || src.empty()) {
        return;
    }
    std::string::size_type pos1 = 0;
    std::string::size_type pos2 = src.find(sep);

    while (std::string::npos != pos2) {
        out.emplace_back(src.substr(pos1, pos2 - pos1));
        pos1 = pos2 + sep.size();
        pos2 = src.find(sep, pos1);
    }

    if (pos1 != src.size()) {
        out.emplace_back(src.substr(pos1));
    }
}

template <size_t T> std::string ToStr(std::array<char, T> data)
{
    // HACK automatically convert char array to string depending on \0
    // must ensure that the input char array has an ending poing
    return data.data();
}

template <size_t T> std::array<char, T> FromStr(const std::string &in)
{
    if (in.size() + 1 > T) {
        return {};
    }
    std::array<char, T> out;
    // copy with extra '\0
    memcpy_s(out.data(), out.size(), in.data(), in.size() + 1);
    return out;
}

template <size_t T> std::string ToHexStr(std::array<char, T> data)
{
    std::stringstream sstream;
    sstream << std::hex;
    for (size_t i = 0; i < T; i++) {
        sstream << static_cast<int>(data[i]);
    }
    return sstream.str();
}

template <size_t T> std::array<char, T> FromHexStr(const std::string &in)
{
    if (in.size() != T * 2) {
        return {};
    }

    std::array<char, T> out;
    for (size_t i = 0; i < T; i++) {
        std::string byteString = in.substr(i * 2, 2);
        auto byteValue = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
        out[i] = byteValue;
    }
    return out;
}

void SaveVRootsToFile(const std::string &file, const std::unordered_map<std::string, std::unique_ptr<VRoot>> &map)
{
    std::ofstream f(file);
    if (f.is_open()) {
        // encode line format
        for (const auto &item : map) {
            f << ToStr(item.second->GetData().uuid) << TSB_AGENT_FILE_SEP;                   // uuid
            f << static_cast<uint32_t>(item.second->GetData().status) << TSB_AGENT_FILE_SEP; // status        }
            f << ToStr(item.second->GetData().version) << TSB_AGENT_FILE_SEP;                // version
            f << ToStr(item.second->GetData().name) << TSB_AGENT_FILE_SEP;                   // name
            f << ToHexStr(item.second->GetData().bios) << TSB_AGENT_FILE_SEP;                // bios
            f << ToHexStr(item.second->GetData().shim) << TSB_AGENT_FILE_SEP;                // shim
            f << ToHexStr(item.second->GetData().grub) << TSB_AGENT_FILE_SEP;                // grub
            f << ToHexStr(item.second->GetData().grubCfg) << TSB_AGENT_FILE_SEP;             // grubCfg
            f << ToHexStr(item.second->GetData().kernel) << TSB_AGENT_FILE_SEP;              // kernel
            f << ToHexStr(item.second->GetData().initrd) << TSB_AGENT_FILE_SEP;              // initrd
            f << (item.second->GetData().hasStarted ? "1" : "0") << TSB_AGENT_FILE_SEP;      // hasStarted
            f << std::endl;
        }
        f.close();
    }
}

std::unordered_map<std::string, std::unique_ptr<VRoot>> LoadVRootsFromFile(const std::string &file)
{
    // placeholder
    std::unordered_map<std::string, std::unique_ptr<VRoot>> map;
    std::ifstream f(file);
    std::string line;
    if (f.is_open()) {
        while (getline(f, line)) {
            // decode line format
            std::vector<std::string> lineVec;
            StrSplit(line, TSB_AGENT_FILE_SEP, lineVec);
            if (lineVec.size() < 10) {
                SPDLOG_ERROR("[MOCK-TSB-AGENT] Invalid line format in file: {}, line: {}", file, line);
                continue;
            }
            // decode descriptions
            VRootData data;
            data.uuid = FromStr<VROOT_VM_UUID_MAX_LEN>(lineVec[0]);                // uuid
            data.status = static_cast<VRootStatus>(std::atoi(lineVec[1].c_str())); // status
            data.version = FromStr<VROOT_VERSION_LEN>(lineVec[2]);                 // version
            data.name = FromStr<VROOT_VM_NAME_MAX_LEN>(lineVec[3]);                // name
            data.bios = FromHexStr<VROOT_SM3_OUTPUT_BYTES>(lineVec[4]);            // bios
            data.shim = FromHexStr<VROOT_SM3_OUTPUT_BYTES>(lineVec[5]);            // shim
            data.grub = FromHexStr<VROOT_SM3_OUTPUT_BYTES>(lineVec[6]);            // grub
            data.grubCfg = FromHexStr<VROOT_SM3_OUTPUT_BYTES>(lineVec[7]);         // grubCfg
            data.kernel = FromHexStr<VROOT_SM3_OUTPUT_BYTES>(lineVec[8]);          // kernel
            data.initrd = FromHexStr<VROOT_SM3_OUTPUT_BYTES>(lineVec[9]);          // initrd
            data.hasStarted = (lineVec.size() > 10 && lineVec[10] == "1");         // hasStarted

            // status are implicitly coverted to
            map.emplace(lineVec[0] /*uuid*/, std::make_unique<VRoot>(data));
        }
        f.close();
    }
    return map;
}
} // namespace

std::vector<Description> TsbAgentImpl::GetVRoots()
{
    vRootMap_ = LoadVRootsFromFile(storageFilePath_.c_str());
    std::vector<Description> out;
    out.reserve(vRootMap_.size());
    for (const auto &vroot : vRootMap_) {
        out.push_back(vroot.second->GetDescription());
    }
    return out;
}

bool TsbAgentImpl::HasVRootStarted(const std::string &uuid)
{
    vRootMap_ = LoadVRootsFromFile(storageFilePath_.c_str());
    auto it = vRootMap_.find(uuid);
    if (it != vRootMap_.end()) {
        return it->second->HasStarted();
    }
    return false;
}

TsbAgentRc TsbAgentImpl::CreateVRoot(const std::string &uuid, const std::string &name)
{
    vRootMap_ = LoadVRootsFromFile(storageFilePath_.c_str());
    if (vRootMap_.find(uuid) != vRootMap_.end()) {
        SPDLOG_ERROR("[MOCK-TSB-AGENT] uuid already exist");
        return TsbAgentRc::ERROR;
    }

    if (std::find_if(vRootMap_.begin(), vRootMap_.end(), [name](const auto &root) {
            return name == root.second->GetDescription().name;
        }) != vRootMap_.end()) {
        SPDLOG_ERROR("[MOCK-TSB-AGENT] name already exist");
        return TsbAgentRc::ERROR;
    }

    VRootData desc;
    if (uuid.size() >= desc.uuid.size() || name.size() >= desc.name.size()) {
        SPDLOG_ERROR("[MOCK-TSB-AGENT] uuid or name is too long.");
        return TsbAgentRc::ERROR;
    }
    if (memcpy_s(desc.uuid.data(), desc.uuid.size(), uuid.data(), uuid.size()) != EOK) {
        SPDLOG_ERROR("[MOCK-TSB-AGENT] copy uuid failed");

        return TsbAgentRc::ERROR;
    }
    desc.uuid[uuid.size()] = '\0';

    if (memcpy_s(desc.name.data(), desc.name.size(), name.data(), name.size()) != EOK) {
        SPDLOG_ERROR("[MOCK-TSB-AGENT] copy name failed");
        return TsbAgentRc::ERROR;
    }
    desc.name[name.size()] = '\0';

    if (memcpy_s(desc.version.data(), desc.version.size(), DEFAULT_VERSION.data(), DEFAULT_VERSION.size()) != EOK) {
        SPDLOG_ERROR("[MOCK-TSB-AGENT] copy version failed");
        return TsbAgentRc::ERROR;
    }
    desc.version[DEFAULT_VERSION.size()] = '\0';

    vRootMap_.emplace(uuid, std::make_unique<VRoot>(desc));
    SaveVRootsToFile(storageFilePath_.c_str(), vRootMap_);
    return TsbAgentRc::OK;
}

TsbAgentRc TsbAgentImpl::StopVRoot(const std::string &uuid)
{
    vRootMap_ = LoadVRootsFromFile(storageFilePath_.c_str());
    if (vRootMap_.find(uuid) == vRootMap_.end()) {
        SPDLOG_ERROR("[MOCK-TSB-AGENT] Cannot find uuid: {}", uuid);
        return TsbAgentRc::ERROR;
    }
    if (vRootMap_[uuid]->GetData().status != VRootStatus::RUNNING) {
        SPDLOG_ERROR("[MOCK-TSB-AGENT] uuid:{} status not RUNNING", uuid);
        return TsbAgentRc::ERROR;
    }
    vRootMap_[uuid]->GetDataRef().status = VRootStatus::OFF;
    SaveVRootsToFile(storageFilePath_.c_str(), vRootMap_);
    return TsbAgentRc::OK;
}

TsbAgentRc TsbAgentImpl::StartVRoot(const std::string &uuid)
{
    vRootMap_ = LoadVRootsFromFile(storageFilePath_.c_str());
    if (vRootMap_.find(uuid) == vRootMap_.end()) {
        SPDLOG_ERROR("[MOCK-TSB-AGENT] Cannot find uuid: {}", uuid);

        return TsbAgentRc::ERROR;
    }
    if (vRootMap_[uuid]->GetDataRef().status != VRootStatus::OFF) {
        SPDLOG_ERROR("[MOCK-TSB-AGENT] uuid:{} status not OFF", uuid);
        return TsbAgentRc::ERROR;
    }
    vRootMap_[uuid]->GetDataRef().status = VRootStatus::RUNNING;
    vRootMap_[uuid]->GetDataRef().hasStarted = true;  // 设置已启动过
    SaveVRootsToFile(storageFilePath_.c_str(), vRootMap_);
    return TsbAgentRc::OK;
}

TsbAgentRc TsbAgentImpl::RemoveVRoot(const std::string &uuid)
{
    vRootMap_ = LoadVRootsFromFile(storageFilePath_.c_str());
    if (vRootMap_.find(uuid) == vRootMap_.end()) {
        SPDLOG_ERROR("[MOCK-TSB-AGENT] uuid:{} not found", uuid);
        return TsbAgentRc::ERROR;
    }
    vRootMap_.erase(uuid);
    SaveVRootsToFile(storageFilePath_.c_str(), vRootMap_);
    return TsbAgentRc::OK;
}

TsbAgentRc TsbAgentImpl::UpdateMeasure(const std::string &uuid, MeasureInfo bios, MeasureInfo shim, MeasureInfo grub,
                                       MeasureInfo grubCfg, MeasureInfo kernel, MeasureInfo initrd)
{
    vRootMap_ = LoadVRootsFromFile(storageFilePath_.c_str());
    if (vRootMap_.find(uuid) == vRootMap_.end()) {
        SPDLOG_ERROR("[MOCK-TSB-AGENT] uuid:{} not found", uuid);
        return TsbAgentRc::ERROR;
    }
    // REVIEW
    SaveVRootsToFile(storageFilePath_.c_str(), vRootMap_);
    return TsbAgentRc::OK;
}

TsbAgentRc TsbAgentImpl::CheckMeasure(const std::string &uuid, MeasureInfo bios, MeasureInfo shim, MeasureInfo grub,
                                      MeasureInfo grubCfg, MeasureInfo kernel, MeasureInfo initrd)
{
    vRootMap_ = LoadVRootsFromFile(storageFilePath_.c_str());
    if (vRootMap_.find(uuid) == vRootMap_.end()) {
        SPDLOG_ERROR("[MOCK-TSB-AGENT] uuid:{} not found", uuid);
        return TsbAgentRc::ERROR;
    }
    // REVIEW
    SaveVRootsToFile(storageFilePath_.c_str(), vRootMap_);
    return TsbAgentRc::OK;
}

// Almost always return true with empty report
TsbAgentRc TsbAgentImpl::GetReport(const std::string &pUuid, const std::string &vUuid,
                                   struct trust_report_new *hostreport, struct trust_report_new *vmreport)
{
    (void)pUuid;
    (void)vUuid;
    (void)hostreport;
    (void)vmreport;
    return TsbAgentRc::OK;
}

// Almost always return true if report is not nullptr
TsbAgentRc TsbAgentImpl::VerifyReport(const std::string &pUuid, const std::string &vUuid,
                                      struct trust_report_new *hostreport, struct trust_report_new *vmreport)
{
    vRootMap_ = LoadVRootsFromFile(storageFilePath_.c_str());
    if (vRootMap_.find(vUuid) == vRootMap_.end()) {
        SPDLOG_ERROR("[MOCK-TSB-AGENT] vUuid:{} not found", vUuid);
        return TsbAgentRc::ERROR;
    }

    if (hostreport == nullptr || vmreport == nullptr) {
        SPDLOG_ERROR("[MOCK-TSB-AGENT] host report or vm report is nullptr!");
        return TsbAgentRc::ERROR;
    }

    SaveVRootsToFile(storageFilePath_.c_str(), vRootMap_);
    return TsbAgentRc::OK;
}

// Almost always return true with empty report
TsbAgentRc TsbAgentImpl::MigrationGetCert(const std::string &vUuid, std::vector<uint8_t> &cert,
                                          std::vector<uint8_t> &pubkey)
{
    return TsbAgentRc::OK;
}

} // namespace virtrust::mock
