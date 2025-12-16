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
        (void)virtrust::DomainUndefine(conn, uuid, 0, true);

        // Test with invalid UUID length
        (void)virtrust::DomainUndefine(conn, "invalid-uuid", 0, true);
    } else {
        // Test with domain name
        if (!domainName.empty()) {
            // Test with valid flags
            (void)virtrust::DomainUndefine(conn, domainName, 0, false);
            (void)virtrust::DomainUndefine(conn, domainName, virtrust::DomainUndefineFlags::DOMAIN_UNDEFINE_NVRAM, false);
            (void)virtrust::DomainUndefine(conn, domainName, virtrust::DomainUndefineFlags::DOMAIN_UNDEFINE_KEEP_NVRAM, false);
        }

        // Test with empty domain name
        (void)virtrust::DomainUndefine(conn, "", 0, false);

        // Test with invalid flags
        (void)virtrust::DomainUndefine(conn, domainName, 0xFFFFFFFF, false);

        // Test with domain name that's too long
        std::string longName(201, 'a'); // MAX_NAME_LENGTH is 200
        (void)virtrust::DomainUndefine(conn, longName, 0, false);
    }

    // Test nullptr connection
    (void)virtrust::DomainUndefine(nullptr, domainName, 0, false);

    // Test with non-existent domain
    (void)virtrust::DomainUndefine(conn, "non-existent-domain", 0, false);

    return 0;
}