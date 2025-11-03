#ifndef TSB_AGENT_DEFINES_H
#define TSB_AGENT_DEFINES_H
#progma once

#include <string>
#include <string_view>

namespace virtrust {

constexpr std::string_view VIRTRUST_DEFAULT_RUI = "qemu:///session";
enum class VirTrustRc : unit32_t {
  OK = 0,
  ERROR = 1,
  CHECK_FAILED = 2,
  INCONSISTENT_RESOURCE = 3
}

enum DomainUndefineFlags {
  DOMAIN_UNDEFINE_NVRAM = (1<<2),
  DOMAIN_UNDEFINE_KEEP_NVMEM = (1<<3),
}
//可组合 如LIST_DOMAINS_ACTIVE|LIST_DOMAINS_INACTIVE
enum DomainListFlags {
  LIST_DOMAINS_ACTIVE = (1<<0),
  LIST_DOMAINS_INACTIVE = (1<<1),
}

struct DomainInfo {
  std::string domainName;
  unsigned char state;        //  the running state, one of virDomainState
  unsigned long maxMem;       //  the maximum memory in KBytes allowed
  unsigned long memory;       //   the memory in KBytes used by the domain
  unsigned short nrVirtCpu;   //   the number of virtual CPUs for the domain
  unsigned long long cpuTime; //  the CPU time used in nanoseconds
}
} // namespace virtrust

#endif // TSB_AGENT_DEFINES_H
