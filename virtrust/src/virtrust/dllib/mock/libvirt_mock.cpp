/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#ifdef VIRTRUST_MOCK

#include "virtrust/dllib/mock/libvirt_mock.h"

#include <securec.h>
#include <vector>
#include <cstring>

#include "tsb_agent/tsb_agent.h"
#include "tsb_agent/mock/mock_vm_infos.h"

namespace virtrust {
namespace {
int DOMAIN_POINT[16] = {};
}

// Mock domain information structure
struct MockDomainInfo {
    virDomainPtr ptr;           // Domain pointer
    char name[64];              // Domain name (with null terminator)
    char uuid[37];              // Domain UUID (with null terminator)
    virDomainState state;       // Domain state
    unsigned long maxMem;       // Maximum memory (KB)
    unsigned long memory;       // Current memory (KB)
    unsigned short nrVirtCpu;   // Number of virtual CPUs
    unsigned long long cpuTime; // CPU time (nanoseconds)
};

// Helper function to convert VM state from mock_vm_infos.h to libvirt state
inline virDomainState ConvertVmStateToLibvirtState(int vmState)
{
    return (vmState == VM_RUNNING) ? VIR_DOMAIN_RUNNING : VIR_DOMAIN_SHUTOFF;
}

// Mock domain data - using data from mock_vm_infos.h
static MockDomainInfo LIBVIRT_MOCK_DOMAINS[] = {
    {
        .ptr = &DOMAIN_POINT[0],
        .name = {},  // Will be initialized from MOCK_DOMAINS[0]
        .uuid = {}, // Will be initialized from MOCK_DOMAINS[0]
        .state = VIR_DOMAIN_SHUTOFF,    // Will be updated from MOCK_DOMAINS[0]
        .maxMem = 1024 * 1024,         // 1GB
        .memory = 0,
        .nrVirtCpu = 1,
        .cpuTime = 0
    },
    {
        .ptr = &DOMAIN_POINT[1],
        .name = {},  // Will be initialized from MOCK_DOMAINS[1]
        .uuid = {}, // Will be initialized from MOCK_DOMAINS[1]
        .state = VIR_DOMAIN_SHUTOFF,    // Will be updated from MOCK_DOMAINS[1]
        .maxMem = 2048 * 1024,         // 2GB
        .memory = 0,
        .nrVirtCpu = 2,
        .cpuTime = 0
    },
    {
        .ptr = &DOMAIN_POINT[2],
        .name = {},  // Will be initialized from MOCK_DOMAINS[2]
        .uuid = {}, // Will be initialized from MOCK_DOMAINS[2]
        .state = VIR_DOMAIN_RUNNING,    // Will be updated from MOCK_DOMAINS[2]
        .maxMem = 512 * 1024,          // 512MB
        .memory = 256 * 1024,          // 256MB
        .nrVirtCpu = 1,
        .cpuTime = 5000000
    },
    {
        .ptr = &DOMAIN_POINT[3],
        .name = {},  // Will be initialized from MOCK_DOMAINS[3]
        .uuid = {}, // Will be initialized from MOCK_DOMAINS[3]
        .state = VIR_DOMAIN_SHUTOFF,    // Will be updated from MOCK_DOMAINS[3]
        .maxMem = 4096 * 1024,         // 4GB
        .memory = 0,
        .nrVirtCpu = 4,
        .cpuTime = 0
    }
};

constexpr int LIBVIRT_MOCK_DOMAIN_COUNT = sizeof(LIBVIRT_MOCK_DOMAINS) / sizeof(LIBVIRT_MOCK_DOMAINS[0]);

// Helper function to find domain info by pointer
const MockDomainInfo* FindMockDomainByPtr(virDomainPtr ptr)
{
    for (int i = 0; i < LIBVIRT_MOCK_DOMAIN_COUNT; ++i) {
        if (LIBVIRT_MOCK_DOMAINS[i].ptr == ptr) {
            return &LIBVIRT_MOCK_DOMAINS[i];
        }
    }
    return nullptr;
}

// Helper function to find domain info by name
const MockDomainInfo* FindMockDomainByName(const char* name)
{
    for (int i = 0; i < LIBVIRT_MOCK_DOMAIN_COUNT; ++i) {
        if (strcmp(LIBVIRT_MOCK_DOMAINS[i].name, name) == 0) {
            return &LIBVIRT_MOCK_DOMAINS[i];
        }
    }
    return nullptr;
}

// Initialize MockDomainInfo arrays with proper null-terminated strings
static void InitializeMockDomainData()
{
    for (int i = 0; i < LIBVIRT_MOCK_DOMAIN_COUNT && i < MOCK_DOMAIN_COUNT; ++i) {
        // Initialize name with null terminator from MOCK_DOMAINS
        if (strncpy_s(LIBVIRT_MOCK_DOMAINS[i].name, sizeof(LIBVIRT_MOCK_DOMAINS[i].name),
                      MOCK_DOMAINS[i].name, strlen(MOCK_DOMAINS[i].name)) != EOK) {
            // If copy fails, fallback to empty string
            memset_s(LIBVIRT_MOCK_DOMAINS[i].name, sizeof(LIBVIRT_MOCK_DOMAINS[i].name), 0, sizeof(LIBVIRT_MOCK_DOMAINS[i].name));
        }
        LIBVIRT_MOCK_DOMAINS[i].name[sizeof(LIBVIRT_MOCK_DOMAINS[i].name) - 1] = '\0';

        // Initialize uuid with null terminator from MOCK_DOMAINS
        if (strncpy_s(LIBVIRT_MOCK_DOMAINS[i].uuid, sizeof(LIBVIRT_MOCK_DOMAINS[i].uuid),
                      MOCK_DOMAINS[i].uuid, strlen(MOCK_DOMAINS[i].uuid)) != EOK) {
            // If copy fails, fallback to empty string
            memset_s(LIBVIRT_MOCK_DOMAINS[i].uuid, sizeof(LIBVIRT_MOCK_DOMAINS[i].uuid), 0, sizeof(LIBVIRT_MOCK_DOMAINS[i].uuid));
        }
        LIBVIRT_MOCK_DOMAINS[i].uuid[sizeof(LIBVIRT_MOCK_DOMAINS[i].uuid) - 1] = '\0';

        // Convert VM state from mock_vm_infos.h to libvirt state
        LIBVIRT_MOCK_DOMAINS[i].state = ConvertVmStateToLibvirtState(MOCK_DOMAINS[i].state);
    }
}

DllibRc LibvirtMock::CheckOk() const
{
    return DllibRc::OK;
}

void LibvirtMock::InitializeMockFunctions()
{
    // Initialize mock domain data
    InitializeMockDomainData();

    // Mock连接管理
    virConnectOpen = DlFun<virConnectPtr, const char *>("virConnectOpen",
        [](const char* uri) -> virConnectPtr {
            return &DOMAIN_POINT[0]; // Mock连接指针
        });

    virConnectClose = DlFun<int, virConnectPtr>("virConnectClose",
        [](virConnectPtr conn) -> int {
            return 0; // 总是成功关闭
        });

    virSetErrorFunc = DlFun<void, void *, virErrorFunc>("virSetErrorFunc",
        [](void* userData, virErrorFunc handler) -> void {
            // Mock实现，不做任何操作
        });

    // Mock域查询
    virConnectListAllDomains = DlFun<int, virConnectPtr, virDomainPtr **, unsigned int>("virConnectListAllDomains",
        [](virConnectPtr conn, virDomainPtr **domains, unsigned int flags) -> int {
            std::vector<virDomainPtr> domainPtrs;

            // 根据flags筛选域
            for (int i = 0; i < LIBVIRT_MOCK_DOMAIN_COUNT; ++i) {
                bool includeDomain = false;
                // LIST_DOMAINS_ACTIVE - 只包含running的域
                if (flags == LIST_DOMAINS_ACTIVE && LIBVIRT_MOCK_DOMAINS[i].state == VIR_DOMAIN_RUNNING) {
                    includeDomain = true;
                } else if (flags == LIST_DOMAINS_INACTIVE && LIBVIRT_MOCK_DOMAINS[i].state == VIR_DOMAIN_SHUTOFF) {
                    // LIST_DOMAINS_INACTIVE - 只包含shut off的域
                    includeDomain = true;
                } else { // LIST_DOMAINS_ACTIVE | LIST_DOMAINS_INACTIVE - 包含所有域
                    includeDomain = true;
                }

                if (includeDomain) {
                    domainPtrs.push_back(LIBVIRT_MOCK_DOMAINS[i].ptr);
                }
            }

            int count = static_cast<int>(domainPtrs.size());

            if (domains == nullptr) {
                return count; // 只返回数量
            }

            // 分配并填充域指针数组
            *domains = static_cast<virDomainPtr*>(calloc(count + 1, sizeof(virDomainPtr)));
            if (*domains == nullptr) {
                return -1;
            }

            for (int i = 0; i < count; ++i) {
                (*domains)[i] = domainPtrs[i];
            }
            return count;
        });

    // Mock域操作
    virDomainLookupByName = DlFun<virDomainPtr, virConnectPtr, const char *>("virDomainLookupByName",
        [](virConnectPtr conn, const char* name) -> virDomainPtr {
            // Always succeed for stable unit testing - removed random failure logic
            const MockDomainInfo* domainInfo = FindMockDomainByName(name);
            return domainInfo ? domainInfo->ptr : nullptr;
        });

    virDomainGetName = DlFun<const char *, virDomainPtr>("virDomainGetName",
        [](virDomainPtr domain) -> const char* {
            const MockDomainInfo* domainInfo = FindMockDomainByPtr(domain);
            return domainInfo ? domainInfo->name : "unknown-domain";
        });

    virDomainGetUUIDString = DlFun<int, virDomainPtr, char *>("virDomainGetUUIDString",
        [](virDomainPtr domain, char* uuid) -> int {
            // Always succeed for stable unit testing - removed random failure logic
            const MockDomainInfo* domainInfo = FindMockDomainByPtr(domain);
            if (domainInfo) {
                if (strncpy_s(uuid, 37, domainInfo->uuid, strlen(domainInfo->uuid)) != EOK) {
                    return -1; // 内存拷贝失败
                }
                uuid[36] = '\0'; // 确保字符串终止
                return 0;
            }
            if (strncpy_s(uuid, 37, "12345678-1234-1234-1234-123456789999", 36) != EOK) {
                return -1; // 内存拷贝失败
            }
            uuid[36] = '\0'; // 确保字符串终止
            return 0;
        });

    virDomainGetInfo = DlFun<int, virDomainPtr, virDomainInfo *>("virDomainGetInfo",
        [](virDomainPtr domain, virDomainInfo* info) -> int {
            // Always succeed for stable unit testing - removed random failure logic
            // 初始化结构体
            memset_s(info, sizeof(*info), 0, sizeof(*info));

            const MockDomainInfo* domainInfo = FindMockDomainByPtr(domain);
            if (domainInfo) {
                // 从结构体数据填充virDomainInfo
                info->state = domainInfo->state;
                info->maxMem = domainInfo->maxMem;
                info->memory = domainInfo->memory;
                info->nrVirtCpu = domainInfo->nrVirtCpu;
                info->cpuTime = domainInfo->cpuTime;
                return 0;
            }

            // 默认值（未知域）
            info->state = VIR_DOMAIN_SHUTOFF;
            info->maxMem = 1024 * 1024;
            info->memory = 0;
            info->nrVirtCpu = 1;
            info->cpuTime = 0;
            return 0;
        });

    // Mock域生命周期管理
    virDomainCreateWithFlags = DlFun<int, virDomainPtr, unsigned int>("virDomainCreateWithFlags",
        [](virDomainPtr domain, unsigned int flags) -> int {
            // Always succeed for stable unit testing - removed random failure logic
            return 0; // 成功
        });

    virDomainDestroyFlags = DlFun<int, virDomainPtr, unsigned int>("virDomainDestroyFlags",
        [](virDomainPtr domain, unsigned int flags) -> int {
            // Always succeed for stable unit testing - removed random failure logic
            return 0; // 成功
        });

    virDomainUndefineFlags = DlFun<int, virDomainPtr, unsigned int>("virDomainUndefineFlags",
        [](virDomainPtr domain, unsigned int flags) -> int {
            // Always succeed for stable unit testing - removed random failure logic
            return 0; // 成功
        });

    // Mock域清理
    virDomainFree = DlFun<int, virDomainPtr>("virDomainFree",
        [](virDomainPtr domain) -> int {
            return 0; // 总是成功
        });

    // Mock其他函数
    virDomainShutdownFlags = DlFun<int, virDomainPtr, unsigned int>("virDomainShutdownFlags",
        [](virDomainPtr domain, unsigned int flags) -> int {
            return 0; // 总是成功
        });

    virConnectNumOfDomains = DlFun<int, virConnectPtr>("virConnectNumOfDomains",
        [](virConnectPtr conn) -> int {
            return 3; // Mock域数量
        });

    virDomainGetID = DlFun<unsigned int, virDomainPtr>("virDomainGetID",
        [](virDomainPtr domain) -> unsigned int {
            // 根据域指针返回对应的ID
            const MockDomainInfo* domainInfo = FindMockDomainByPtr(domain);
            if (domainInfo) {
                // 使用指针的低字节作为ID，保持一致性
                return static_cast<unsigned int>(reinterpret_cast<uint64_t>(domainInfo->ptr) & 0xFF);
            }
            return 0; // 默认ID
        });

    // Mock迁移相关函数
    virDomainMigrate3 = DlFun<virDomainPtr, virDomainPtr, virConnectPtr, virTypedParameterPtr, unsigned int, unsigned int>("virDomainMigrate3",
        [](virDomainPtr domain, virConnectPtr dconn, virTypedParameterPtr params, unsigned int nparams, unsigned int flags) -> virDomainPtr {
            // Always succeed for stable unit testing - removed random failure logic
            return reinterpret_cast<virDomainPtr>(0x98765432); // Mock迁移后的域指针
        });
}

} // namespace virtrust

#endif // VIRTRUST_MOCK