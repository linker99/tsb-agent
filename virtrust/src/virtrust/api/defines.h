// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace virtrust {

constexpr std::string_view VIRTRUST_DEFAULT_URI = "qemu:///session";

enum class VirtrustRc : uint32_t {
  OK = 0,
  ERROR = 1,
  CHECK_FAILED = 2,
  INCONSISTENT_RESOURCE = 3
};

enum DomainUndefineFlags {
  DOMAIN_UNDEFINE_NVRAM = (1 << 2),
  DOMAIN_UNDEFINE_KEEP_NVRAM = (1 << 3),
};

// 可组合 如LIST_DOMAINS_ACTIVE|LIST_DOMAINS_INACTIVE
enum DomainListFlags {
  LIST_DOMAINS_ACTIVE = (1 << 0),
  LIST_DOMAINS_INACTIVE = (1 << 1),
};

enum DomainStartFlags {
  DOMAIN_START_NONE = 0,
};

enum DomainDestroyFlags {
  DOMAIN_DESTROY_NONE = 0,
};

struct DomainInfo {
  std::string domainName;
  unsigned char state;        //  the running state, one of virDomainState
  unsigned long maxMem;       //  the maximum memory in KBytes allowed
  unsigned long memory;       //   the memory in KBytes used by the domain
  unsigned short nrVirtCpu;   //   the number of virtual CPUs for the domain
  unsigned long long cpuTime; //  the CPU time used in nanoseconds
};
} // namespace virtrust
