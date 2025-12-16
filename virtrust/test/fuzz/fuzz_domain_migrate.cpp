// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

#include "fuzz_helper.h"

// ---------- libFuzzer main entry ----------
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 20) {
        return 0;
    }

    // Extract parameters from fuzz data
    std::string domainName = ExtractDomainName(data, size, 0);
    std::string destUri = ExtractDestUri(data, size, 5);
    unsigned int flags = ExtractFlags(data, size, 10);

    auto &conn = GetGlobalConn();
    if (!conn) {
        return 0;
    }

    // Test valid migration scenarios
    if (!domainName.empty() && !destUri.empty()) {
        // Test with default flags (0)
        (void)virtrust::DomainMigrate(conn, domainName, destUri, 0);

        // Test with MIGRATE_UNDEFINE_SOURCE flag
        (void)virtrust::DomainMigrate(conn, domainName, destUri, virtrust::DomainMigrateFlags::MIGRATE_UNDEFINE_SOURCE);

        // Test with combined flags
        (void)virtrust::DomainMigrate(conn, domainName, destUri,
                                      virtrust::DomainMigrateFlags::MIGRATE_UNDEFINE_SOURCE |
                                          virtrust::DomainMigrateFlags::MIGRATE_UNDEFINE_SOURCE);

        // Test with invalid flags
        (void)virtrust::DomainMigrate(conn, domainName, destUri, 0xFFFFFFFF);
    }

    // Test edge cases
    if (!domainName.empty()) {
        // Test with empty destination URI
        (void)virtrust::DomainMigrate(conn, domainName, "", 0);

        // Test with invalid destination URI (not starting with qemu+tls://)
        (void)virtrust::DomainMigrate(conn, domainName, "invalid://uri", 0);

        // Test with non-existent domain
        (void)virtrust::DomainMigrate(conn, "non-existent-domain", destUri, 0);
    }

    // Test nullptr connection
    (void)virtrust::DomainMigrate(nullptr, domainName, destUri, 0);

    // Test with empty domain name
    (void)virtrust::DomainMigrate(conn, "", destUri, 0);

    return 0;
}