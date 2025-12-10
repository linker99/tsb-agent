/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <dlfcn.h>

#include <string_view>

#include "virtrust/dllib/common.h"
#include "virtrust/dllib/libvirt_defines.h"

namespace virtrust {

// libvirt api
class Libvirt : public DlLibBase {
public:
    ~Libvirt() = default;
    Libvirt(const Libvirt &) = delete;
    void operator=(const Libvirt &) = delete;

    // Singleton instance
    static Libvirt &GetInstance()
    {
        static Libvirt instance;
        return instance;
    }

    // Reload all functions
    DllibRc Reload()
    {
        SelfDlClose();
        LoadAll();
        return CheckOk();
    }

    // Set log level
    DllibRc SetErrorFunction(virErrorFunc func)
    {
        auto ret = GetInstance().CheckOk();
        if (ret != DllibRc::OK) {
            return ret;
        }
        virSetErrorFunc(nullptr, func);
        return DllibRc::OK;
    }

    // Declare all functions that you need
    // NOTE Please make sure the class instance is inited before calling those
    // functions
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

private:
    DllibRc LoadAll()
    {
        // NOTE explicitly dlopen shared library
        auto ret = SelfDlOpen();
        if (ret != DllibRc::OK) {
            return ret;
        }
        if (DLLIB_SELF_DLSYM(virConnectOpen) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(virDomainLookupByName) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(virDomainCreateWithFlags) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(virConnectClose) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(virDomainFree) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(virDomainShutdownFlags) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(virConnectNumOfDomains) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(virConnectListAllDomains) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(virDomainGetID) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(virDomainGetName) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(virDomainGetInfo) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(virDomainDestroyFlags) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(virDomainUndefineFlags) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(virSetErrorFunc) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(virDomainGetUUIDString) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(virDomainMigrate3) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        return DllibRc::OK;
    }

    Libvirt() : DlLibBase(LIB_NAME)
    {
        LoadAll();
    }

    static constexpr std::string_view LIB_NAME = "libvirt.so";
};

} // namespace virtrust