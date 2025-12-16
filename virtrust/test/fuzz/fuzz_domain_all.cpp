// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <unordered_map>

#include "fuzz_helper.h"

// Forward declarations for helper functions
void FuzzDomainCreate(const uint8_t* data, size_t size);
void FuzzDomainDestroy(const uint8_t* data, size_t size);
void FuzzDomainStart(const uint8_t* data, size_t size);
void FuzzDomainList(const uint8_t* data, size_t size);
void FuzzDomainUndefine(const uint8_t* data, size_t size);
void FuzzDomainMigrate(const uint8_t* data, size_t size);


// Common validation helper
static bool CheckMinSize(const uint8_t* data, size_t size, size_t min)
{
    return data != nullptr && size >= min;
}

// Helper function implementations (refactored from existing fuzzer files)

void FuzzDomainCreate(const uint8_t* data, size_t size)
{
    if (size < 1) return;

    // Extract parameters from fuzz data
    std::vector<std::string> args = ExtractVirtArgs(data, size, 0);

    auto &conn = GetGlobalConn();
    if (!conn) return;

    // Test with extracted arguments
    if (args.size() > 1) {
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
}

void FuzzDomainDestroy(const uint8_t* data, size_t size)
{
    if (size < 6) return;

    // Extract parameters from fuzz data
    std::string domainName;
    unsigned int flags;
    bool isOnlyTsb;
    ExtractDomainDestroyParams(data, size, domainName, flags, isOnlyTsb);

    auto &conn = GetGlobalConn();
    if (!conn) return;

    // Test with extracted parameters
    if (!domainName.empty()) {
        (void)virtrust::DomainDestroy(conn, domainName, flags, isOnlyTsb);
    }

    // Test edge cases
    (void)virtrust::DomainDestroy(conn, "", flags, isOnlyTsb);
    (void)virtrust::DomainDestroy(conn, "non-existent-domain", flags, isOnlyTsb);
    (void)virtrust::DomainDestroy(conn, domainName, 0xFFFFFFFF, !isOnlyTsb);

    // Test nullptr connection
    (void)virtrust::DomainDestroy(nullptr, domainName, 0, false);
}

void FuzzDomainStart(const uint8_t* data, size_t size)
{
    if (size < 6) return;

    // Extract parameters from fuzz data
    std::string domainName;
    unsigned int flags;
    bool isOnlyTsb;
    ExtractDomainDestroyParams(data, size, domainName, flags, isOnlyTsb);

    auto &conn = GetGlobalConn();
    if (!conn) return;

    // Test with extracted parameters
    if (!domainName.empty()) {
        (void)virtrust::DomainStart(conn, domainName, flags, isOnlyTsb);
    }

    // Test edge cases
    (void)virtrust::DomainStart(conn, "", flags, isOnlyTsb);
    (void)virtrust::DomainStart(conn, "non-existent-domain", flags, !isOnlyTsb);
    (void)virtrust::DomainStart(conn, domainName, 0xFFFFFFFF, false);

    // Test nullptr connection
    (void)virtrust::DomainStart(nullptr, domainName, 0, false);
}

void FuzzDomainList(const uint8_t* data, size_t size)
{
    if (size < 5) return;

    // Extract parameters from fuzz data
    unsigned int flags;
    bool printErrToCli;
    ExtractDomainListParams(data, size, flags, printErrToCli);

    auto &conn = GetGlobalConn();
    if (!conn) return;

    std::unordered_map<std::string, virtrust::DomainInfo> domainInfos;
    (void)virtrust::DomainList(conn, flags, domainInfos, printErrToCli);

    for (const auto& [uuid, info] : domainInfos) {
        AccessDomainInfo(info);
    }

    // Test edge cases
    std::unordered_map<std::string, virtrust::DomainInfo> emptyInfos;
    (void)virtrust::DomainList(conn, 0xFFFFFFFF, emptyInfos, !printErrToCli);

    // Test nullptr connection
    (void)virtrust::DomainList(nullptr, flags, domainInfos, printErrToCli);
}

void FuzzDomainUndefine(const uint8_t* data, size_t size)
{
    if (size < 6) return;

    // Extract parameters from fuzz data
    std::string domainName;
    unsigned int flags;
    bool isOnlyTsb;
    ExtractDomainDestroyParams(data, size, domainName, flags, isOnlyTsb);

    auto &conn = GetGlobalConn();
    if (!conn) return;

    // Test with extracted parameters
    if (!domainName.empty()) {
        (void)virtrust::DomainUndefine(conn, domainName, flags, isOnlyTsb);
    }

    // Test edge cases
    (void)virtrust::DomainUndefine(conn, "", flags, isOnlyTsb);
    (void)virtrust::DomainUndefine(conn, "non-existent-domain", flags, !isOnlyTsb);
    (void)virtrust::DomainUndefine(conn, domainName, 0xFFFFFFFF, false);

    // Test nullptr connection
    (void)virtrust::DomainUndefine(nullptr, domainName, 0, false);
}

void FuzzDomainMigrate(const uint8_t* data, size_t size)
{
    if (size < 6) return;

    // Extract parameters from fuzz data
    std::string domainName;
    std::string destUri;
    unsigned int flags;
    ExtractDomainMigrateParams(data, size, domainName, destUri, flags);

    auto &conn = GetGlobalConn();
    if (!conn) return;

    // Test with extracted parameters
    if (!domainName.empty()) {
        (void)virtrust::DomainMigrate(conn, domainName, destUri, flags);
    }

    // Test edge cases
    (void)virtrust::DomainMigrate(conn, "", destUri, flags);
    (void)virtrust::DomainMigrate(conn, domainName, "", flags);
    (void)virtrust::DomainMigrate(conn, domainName, destUri, 0xFFFFFFFF);

    // Test nullptr connection
    (void)virtrust::DomainMigrate(nullptr, domainName, destUri, 0);

    // Test with non-existent domain
    (void)virtrust::DomainMigrate(conn, "non-existent-domain", destUri, 0);
}

// ---------- libFuzzer main entry ----------
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size < 2) {
        // At least 1 byte op + 1 byte payload
        return 0;
    }

    uint8_t op = data[0];
    const uint8_t* payload = data + 1;
    size_t payload_size = size - 1;

    // Dispatch to appropriate operation
    switch (op % 6) { // Currently have 6 domain operations
        case 0:
            if (!CheckMinSize(payload, payload_size, 5)) return 0;
            FuzzDomainCreate(payload, payload_size);
            break;
        case 1:
            if (!CheckMinSize(payload, payload_size, 15)) return 0;
            FuzzDomainDestroy(payload, payload_size);
            break;
        case 2:
            if (!CheckMinSize(payload, payload_size, 15)) return 0;
            FuzzDomainStart(payload, payload_size);
            break;
        case 3:
            if (!CheckMinSize(payload, payload_size, 6)) return 0;
            FuzzDomainList(payload, payload_size);
            break;
        case 4:
            if (!CheckMinSize(payload, payload_size, 15)) return 0;
            FuzzDomainUndefine(payload, payload_size);
            break;
        case 5:
        default:
            if (!CheckMinSize(payload, payload_size, 25)) return 0;
            FuzzDomainMigrate(payload, payload_size);
            break;
    }

    return 0;
}