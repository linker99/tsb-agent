// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

#include "fuzz_helper.h"

// ---------- libFuzzer main entry ----------
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 10) {
        return 0;
    }

    // Extract parameters from fuzz data
    std::string domainName = ExtractDomainName(data, size, 0);
    std::string uuid = ExtractUUID(data, size, 5);
    unsigned int flags = ExtractFlags(data, size, 6);
    bool isOnlyTsb = ExtractBool(data, size, 10);

    auto &conn = GetGlobalConn();
    if (!conn) {
        return 0;
    }

    // Test different scenarios
    if (isOnlyTsb) {
        // Test with UUID (should be 36 chars for valid UUID)
        (void)virtrust::DomainDestroy(conn, uuid, virtrust::DomainDestroyFlags::DOMAIN_DESTROY_NONE, true);

        // Test with invalid UUID length
        (void)virtrust::DomainDestroy(conn, "invalid-uuid", virtrust::DomainDestroyFlags::DOMAIN_DESTROY_NONE, true);
    } else {
        // Test with domain name
        if (!domainName.empty()) {
            (void)virtrust::DomainDestroy(conn, domainName, flags, false);
        }

        // Test with empty domain name
        (void)virtrust::DomainDestroy(conn, "", flags, false);

        // Test with invalid flags (only DOMAIN_DESTROY_NONE is supported)
        (void)virtrust::DomainDestroy(conn, domainName, 0xFFFFFFFF, false);
    }

    // Test nullptr connection
    (void)virtrust::DomainDestroy(nullptr, domainName, virtrust::DomainDestroyFlags::DOMAIN_DESTROY_NONE, false);

    return 0;
}