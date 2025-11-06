/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <securec.h>

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "mock/tsb_agent_itf.h"

namespace virtrust::mock {

constexpr uint32_t VROOT_VM_NAME_MAX_LEN = 256; // with extra \0
constexpr uint32_t VROOT_VM_UUID_MAX_LEN = 37;  // with extra \0
constexpr uint32_t VROOT_SM3_OUTPUT_BYTES = 32;
constexpr uint32_t VROOT_VERSION_LEN = 64;

// the status of virtual root
enum class VRootStatus : uint32_t {
    OFF,
    RUNNING,
};

// the virtual root internal status
struct VRootData {
    std::array<char, VROOT_VM_UUID_MAX_LEN> uuid = {};     // uuid (string)
    VRootStatus status = VRootStatus::OFF;                 // status (string)
    std::array<char, VROOT_VERSION_LEN> version = {};      // version (string)
    std::array<char, VROOT_VM_NAME_MAX_LEN> name = {};     // name (string)
    std::array<char, VROOT_SM3_OUTPUT_BYTES> bios = {};    // sm3 (bytes)
    std::array<char, VROOT_SM3_OUTPUT_BYTES> shim = {};    // sm3 (bytes)
    std::array<char, VROOT_SM3_OUTPUT_BYTES> grub = {};    // sm3 (bytes)
    std::array<char, VROOT_SM3_OUTPUT_BYTES> grubCfg = {}; // sm3 (bytes)
    std::array<char, VROOT_SM3_OUTPUT_BYTES> kernel = {};  // sm3 (bytes)
    std::array<char, VROOT_SM3_OUTPUT_BYTES> initrd = {};  // sm3 (bytes)
};

// Virtual Root
class VRoot {
public:
    // Constructor and Destructor
    VRoot() = default;
    ~VRoot() = default;

    explicit VRoot(VRootData data) : data_(data)
    {}

    VRootData GetData() const
    {
        return data_;
    }

    VRootData &GetDataRef()
    {
        return data_;
    }

    Description GetDescription()
    {
        Description out;
        out.state = static_cast<int>(data_.status);
        memcpy_s(out.name, VROOT_VM_NAME_MAX_LEN, data_.name.data(), data_.name.size());
        memcpy_s(out.uuid, VROOT_VM_UUID_MAX_LEN, data_.uuid.data(), data_.uuid.size());
        return out;
    }

private:
    // NOTE Since this is a mock, no need for encapsulation
    VRootData data_;
};

} // namespace virtrust::mock
