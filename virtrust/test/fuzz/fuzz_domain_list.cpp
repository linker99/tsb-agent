// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <memory>

#include "fuzz_helper.h"

// ---------- libFuzzer main entry ----------
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 6) {
        return 0;
    }

    unsigned int rawFlags = 0;
    std::memcpy(&rawFlags, data + 1, sizeof(unsigned int));

    bool printErrToCli = (data[5] & 0x1) != 0;

    unsigned int flags = 0;
    switch (rawFlags % 5) {
        case 0:
            flags = 0;
            break;
        case 1:
            flags = virtrust::DomainListFlags::LIST_DOMAINS_ACTIVE;
            break;
        case 2:
            flags = virtrust::DomainListFlags::LIST_DOMAINS_INACTIVE;
            break;
        case 3:
            flags = virtrust::DomainListFlags::LIST_DOMAINS_ACTIVE |
                    virtrust::DomainListFlags::LIST_DOMAINS_INACTIVE;
            break;
        default:
            flags = 0xFFFFFFFFu;
            break;
    }

    auto &conn = GetGlobalConn();
    if (!conn) {
        return 0;
    }

    std::unordered_map<std::string, virtrust::DomainInfo> domainInfos;
    (void)virtrust::DomainList(conn, flags, domainInfos, printErrToCli);    

    for (const auto& [uuid, info] : domainInfos) {
        AccessDomainInfo(info);
    }

    return 0;
}
