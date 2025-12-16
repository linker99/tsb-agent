// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

#include "fuzz_helper.h"

// ---------- libFuzzer main entry ----------
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 15) {
        return 0;
    }

    // Extract parameters from fuzz data
    std::string domainName = ExtractDomainName(data, size, 0);
    std::string uuid = ExtractUUID(data, size, 5);
    unsigned int flags = ExtractFlags(data, size, 10);
    bool isOnlyTsb = ExtractBool(data, size, 14);

    auto &conn = GetGlobalConn();
    if (!conn) {
        return 0;
    }

    // Test different scenarios
    if (isOnlyTsb) {
        // Test with UUID (should be 36 chars for valid UUID)
        (void)virtrust::DomainStart(conn, uuid, virtrust::DomainStartFlags::DOMAIN_START_NONE, true);

        // Test with invalid UUID length
        (void)virtrust::DomainStart(conn, "invalid-uuid", virtrust::DomainStartFlags::DOMAIN_START_NONE, true);
    } else {
        // Test with domain name
        if (!domainName.empty()) {
            (void)virtrust::DomainStart(conn, domainName, flags, false);
        }

        // Test with empty domain name
        (void)virtrust::DomainStart(conn, "", flags, false);

        // Test with invalid flags (only DOMAIN_START_NONE is supported)
        (void)virtrust::DomainStart(conn, domainName, 0xFFFFFFFF, false);
    }

    // Test nullptr connection
    (void)virtrust::DomainStart(nullptr, domainName, virtrust::DomainStartFlags::DOMAIN_START_NONE, false);

    // Test with non-existent domain
    (void)virtrust::DomainStart(conn, "non-existent-domain", virtrust::DomainStartFlags::DOMAIN_START_NONE, false);

    return 0;
}