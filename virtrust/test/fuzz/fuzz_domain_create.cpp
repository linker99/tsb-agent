// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

#include "fuzz_helper.h"

// ---------- libFuzzer main entry ----------
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 5) {
        return 0;
    }

    // Extract parameters from fuzz data
    std::vector<std::string> args = ExtractVirtArgs(data, size, 0);

    auto &conn = GetGlobalConn();
    if (!conn) {
        return 0;
    }

    // Test with extracted arguments
    if (args.size() > 1) { // Should have at least virt-install path
        (void)virtrust::DomainCreate(conn, args);
    }

    // Test edge cases
    std::vector<std::string> emptyArgs;
    (void)virtrust::DomainCreate(conn, emptyArgs);

    std::vector<std::string> onlyPathArgs;
    onlyPathArgs.push_back("/usr/bin/virt-install");
    (void)virtrust::DomainCreate(conn, onlyPathArgs);

    // Test with missing domain name
    std::vector<std::string> missingNameArgs = {
        "/usr/bin/virt-install",
        "--memory",
        "1024",
        "--vcpus",
        "1"
    };
    (void)virtrust::DomainCreate(conn, missingNameArgs);

    // Test nullptr connection
    (void)virtrust::DomainCreate(nullptr, args);

    return 0;
}