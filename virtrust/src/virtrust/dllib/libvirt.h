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
  static Libvirt &GetInstance() {
    static Libvirt instance;
    return instance;
  }

  // Reload all functions
  DllibRc Reload() {
    SelfDlClose();
    LoadAll();
    return CheckOk();
  }

  // Set log level
  DllibRc SetErrorFunction(virErrorFunc func) {
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
  DlFun<int, virConnectPtr, virDomainPtr **, unsigned int>
      virConnectListAllDomains;
  DlFun<unsigned int, virDomainPtr> virDomainGetID;
  DlFun<const char *, virDomainPtr> virDomainGetName;
  DlFun<int, virDomainPtr, virDomainInfo *> virDomainGetInfo;
  DlFun<int, virDomainPtr, unsigned int> virDomainDestroyFlags;
  DlFun<int, virDomainPtr, unsigned int> virDomainUndefineFlags;
  DlFun<void, void *, virErrorFunc> virSetErrorFunc;
  DlFun<int, virDomainPtr, char *> virDomainGetUUIDString;
  DlFun<virDomainPtr, virDomainPtr, virConnectPtr, virTypedParameterPtr,
        unsigned int, unsigned int>
      virDomainMigrate3;

private:
  void LoadAll() {
    // NOTE explicitly dlopen shared library
    auto ret = SelfDlOpen();
    if (ret != DllibRc::OK) {
      return;
    }
    DLLIB_SELF_DLSYM(virConnectOpen);
    DLLIB_SELF_DLSYM(virDomainLookupByName);
    DLLIB_SELF_DLSYM(virDomainCreateWithFlags);
    DLLIB_SELF_DLSYM(virConnectClose);
    DLLIB_SELF_DLSYM(virDomainFree);
    DLLIB_SELF_DLSYM(virDomainShutdownFlags);
    DLLIB_SELF_DLSYM(virConnectNumOfDomains);
    DLLIB_SELF_DLSYM(virConnectListAllDomains);
    DLLIB_SELF_DLSYM(virDomainGetID);
    DLLIB_SELF_DLSYM(virDomainGetName);
    DLLIB_SELF_DLSYM(virDomainGetInfo);
    DLLIB_SELF_DLSYM(virDomainDestroyFlags);
    DLLIB_SELF_DLSYM(virDomainUndefineFlags);
    DLLIB_SELF_DLSYM(virSetErrorFunc);
    DLLIB_SELF_DLSYM(virDomainGetUUIDString);
    DLLIB_SELF_DLSYM(virDomainMigrate3);
  }

  Libvirt() : DlLibBase(LIB_NAME) { LoadAll(); }

  static constexpr std::string_view LIB_NAME = "libvirt.so";
};

} // namespace virtrust