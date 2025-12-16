// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "virtrust/api/context.h"
#include "virtrust/api/defines.h"
#include "virtrust/api/domain.h"

inline std::unique_ptr<virtrust::ConnCtx> CreateConnCtx(const std::string &uri)
{
    auto conn = std::make_unique<virtrust::ConnCtx>();
    if (!conn || !conn->SetUri(uri)) {
        return nullptr;
    }
    conn->Connect();
    if (conn->Get() == nullptr) {
        return nullptr;
    }
    return conn;
}

inline const std::unique_ptr<virtrust::ConnCtx> &GetGlobalConn(const std::string &uri = "qemu:///system")
{
    static std::unique_ptr<virtrust::ConnCtx> globalConn;

    if (!globalConn) {
        globalConn = CreateConnCtx(uri);
    }
    return globalConn;
}

// Extract string from fuzz data safely
inline std::string ExtractString(const uint8_t* data, size_t size, size_t offset, size_t maxLen = 200)
{
    if (offset >= size) {
        return "";
    }

    // Find null terminator for NULL-terminated strings (from generate_seed_corpus.py)
    const char* strStart = reinterpret_cast<const char*>(data + offset);
    const char* strEnd = strStart;
    size_t remainingSize = size - offset;

    // Find null terminator or reach max length
    while (static_cast<size_t>(strEnd - strStart) < std::min(maxLen, remainingSize) && *strEnd != '\0') {
        strEnd++;
    }

    return std::string(strStart, strEnd - strStart);
}

// Extract domain name from fuzz data
inline std::string ExtractDomainName(const uint8_t* data, size_t size, size_t offset = 0)
{
    return ExtractString(data, size, offset, 199); // MAX_NAME_LENGTH is 200
}

// Extract UUID from fuzz data (36 chars for standard UUID format)
inline std::string ExtractUUID(const uint8_t* data, size_t size, size_t offset = 0)
{
    return ExtractString(data, size, offset, 36);
}

// Extract destination URI from fuzz data
inline std::string ExtractDestUri(const uint8_t* data, size_t size, size_t offset = 0)
{
    std::string uri = ExtractString(data, size, offset, 100);

    // If URI is empty, provide a default test URI
    if (uri.empty()) {
        return "qemu+tls://127.0.0.1:8080/system";
    }

    // Ensure it starts with qemu+tls:// for DomainMigrate
    if (uri.find("qemu+tls://") != 0) {
        return "qemu+tls://127.0.0.1:8080/system";
    }

    return uri;
}

// Extract flags from fuzz data
inline unsigned int ExtractFlags(const uint8_t* data, size_t size, size_t offset)
{
    if (offset + sizeof(unsigned int) > size) {
        return 0;
    }

    unsigned int flags = 0;
    std::memcpy(&flags, data + offset, sizeof(unsigned int));
    return flags;
}

// Extract boolean from fuzz data
inline bool ExtractBool(const uint8_t* data, size_t size, size_t offset)
{
    if (offset >= size) {
        return false;
    }

    return (data[offset] & 0x1) != 0;
}

// Extract virt-install arguments from fuzz data
inline std::vector<std::string> ExtractVirtArgs(const uint8_t* data, size_t size, size_t offset)
{
    std::vector<std::string> args;

    if (offset >= size) {
        return args;
    }

    // Parse number of arguments (first byte)
    uint8_t argCount = data[offset];
    const uint8_t* payload = data + offset + 1;
    size_t payloadSize = size - offset - 1;

    if (payloadSize == 0 || argCount == 0) {
        // Default case: add virt-install path
        args.push_back("/usr/bin/virt-install");
        return args;
    }

    // Parse each argument (null-terminated strings)
    size_t pos = 0;
    for (uint8_t i = 0; i < argCount && pos < payloadSize; i++) {
        if (payload[pos] == '\0') {
            // Empty argument - skip
            pos++;
            continue;
        }

        // Find the end of current argument
        size_t argStart = pos;
        while (pos < payloadSize && payload[pos] != '\0') {
            pos++;
        }

        // Extract argument
        if (pos < payloadSize) {
            std::string arg(reinterpret_cast<const char*>(payload + argStart), pos - argStart);
            args.push_back(arg);
        } else {
            // Last argument without null terminator
            std::string arg(reinterpret_cast<const char*>(payload + argStart), payloadSize - argStart);
            args.push_back(arg);
            break;
        }
        pos++; // Skip null terminator
    }

    // Ensure we have at least virt-install path
    if (args.empty()) {
        args.push_back("/usr/bin/virt-install");
    }

    return args;
}

// Extract DomainDestroy parameters from fuzz data
inline void ExtractDomainDestroyParams(const uint8_t* data, size_t size,
                                      std::string& domainName, unsigned int& flags, bool& isOnlyTsb)
{
    if (size < 12) return; // Minimum size for all parameters

    // Extract domain name (first part, variable length)
    domainName = ExtractDomainName(data, size, 0);

    // Extract flags (4 bytes at offset based on domain name length)
    size_t flagsOffset = domainName.length() + 1; // +1 for null terminator
    if (flagsOffset + sizeof(unsigned int) <= size) {
        flags = ExtractFlags(data, size, flagsOffset);
    } else {
        flags = 0;
    }

    // Extract isOnlyTsb (1 byte)
    size_t isOnlyTsbOffset = flagsOffset + sizeof(unsigned int);
    if (isOnlyTsbOffset < size) {
        isOnlyTsb = ExtractBool(data, size, isOnlyTsbOffset);
    } else {
        isOnlyTsb = false;
    }
}

// Extract DomainList parameters from fuzz data
inline void ExtractDomainListParams(const uint8_t* data, size_t size, unsigned int& flags, bool& printErrToCli)
{
    if (size < 5) return; // Minimum size for flags (4 bytes) + printErrToCli (1 byte)

    // Extract flags (4 bytes)
    flags = ExtractFlags(data, size, 0);

    // Extract printErrToCli (1 byte)
    if (size >= 5) {
        printErrToCli = ExtractBool(data, size, sizeof(unsigned int));
    } else {
        printErrToCli = false;
    }
}

// Extract DomainMigrate parameters from fuzz data
inline void ExtractDomainMigrateParams(const uint8_t* data, size_t size,
                                       std::string& domainName, std::string& destUri, unsigned int& flags)
{
    if (size < 10) return; // Minimum size for domainName + destUri separator + flags

    // Extract domain name (first part, variable length)
    domainName = ExtractDomainName(data, size, 0);

    // Find destUri start (after domainName + null terminator)
    size_t destUriOffset = domainName.length() + 1;
    if (destUriOffset >= size) {
        destUri = "qemu+tls://localhost:16509/system";
        flags = 0;
        return;
    }

    // Extract destUri (null-terminated)
    destUri = ExtractString(data, size, destUriOffset, 100);

    // Extract flags (4 bytes at the end)
    size_t flagsOffset = destUriOffset + destUri.length() + 1; // +1 for null terminator
    if (flagsOffset + sizeof(unsigned int) <= size) {
        flags = ExtractFlags(data, size, flagsOffset);
    } else {
        flags = 0;
    }
}

// Access domain info fields to prevent compiler optimization
inline void AccessDomainInfo(const virtrust::DomainInfo& info)
{
    volatile auto nameLen = info.domainName.length();
    volatile auto state = info.state;
    volatile auto maxMem = info.maxMem;
    volatile auto memory = info.memory;
    volatile auto nrVirtCpu = info.nrVirtCpu;
    volatile auto cpuTime = info.cpuTime;

    (void)nameLen;
    (void)state;
    (void)maxMem;
    (void)memory;
    (void)nrVirtCpu;
    (void)cpuTime;
}