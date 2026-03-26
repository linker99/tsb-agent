/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#ifdef VIRTRUST_MOCK

#include <cstring>
#include <cstdlib>
#include <string_view>

#include "virtrust/dllib/common.h"
#include "virtrust/dllib/libvirt_defines.h"

namespace virtrust {

// libvirt Mock implementation for fuzzing
class LibvirtMock : public DlLibBase {
public:
    ~LibvirtMock() = default;
    LibvirtMock(const LibvirtMock &) = delete;
    void operator=(const LibvirtMock &) = delete;

    // Singleton instance
    static LibvirtMock &GetInstance()
    {
        static LibvirtMock instance;
        return instance;
    }

    // Reload all functions (Mock implementation)
    DllibRc Reload()
    {
        // Mock implementation always succeeds
        return DllibRc::OK;
    }

    // Set log level (Mock implementation)
    DllibRc SetErrorFunction(virErrorFunc func)
    {
        // Mock implementation
        return DllibRc::OK;
    }

    // Declare all functions that you need
    DlFun<virConnectPtr, const char *> virConnectOpen;
    DlFun<virDomainPtr, virConnectPtr, const char *> virDomainLookupByName;
    DlFun<int, virDomainPtr, unsigned int> virDomainCreateWithFlags;
    DlFun<int, virConnectPtr> virConnectClose;
    DlFun<int, virDomainPtr> virDomainFree;
    DlFun<int, virDomainPtr, unsigned int> virDomainShutdownFlags;
    DlFun<int, virConnectPtr> virConnectNumOfDomains;
    DlFun<int, virConnectPtr, virDomainPtr **, unsigned int> virConnectListAllDomains;
    DlFun<unsigned int, virDomainPtr> virDomainGetID;
    DlFun<const char *, virDomainPtr> virDomainGetName;
    DlFun<int, virDomainPtr, virDomainInfo *> virDomainGetInfo;
    DlFun<int, virDomainPtr, unsigned int> virDomainDestroyFlags;
    DlFun<int, virDomainPtr, unsigned int> virDomainUndefineFlags;
    DlFun<void, void *, virErrorFunc> virSetErrorFunc;
    DlFun<int, virDomainPtr, char *> virDomainGetUUIDString;
    DlFun<virDomainPtr, virDomainPtr, virConnectPtr, virTypedParameterPtr, unsigned int, unsigned int>
        virDomainMigrate3;

    DllibRc CheckOk() const;
private:
    void InitializeMockFunctions();

    LibvirtMock() : DlLibBase("libvirt.so")
    {
        InitializeMockFunctions();
    }
};

} // namespace virtrust

#endif // VIRTRUST_MOCK