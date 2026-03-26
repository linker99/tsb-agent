/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <dlfcn.h>

#include <string_view>

#include "virtrust/dllib/common.h"
#include "virtrust/dllib/libxml2_defines.h"

namespace virtrust {

// libxml2 api
class Libxml2 : public DlLibBase {
public:
    ~Libxml2() = default;
    Libxml2(const Libxml2 &) = delete;
    void operator=(const Libxml2 &) = delete;

    // Singleton instance
    static Libxml2 &GetInstance()
    {
        static Libxml2 instance;
        return instance;
    }

    // Reload all functions
    DllibRc Reload()
    {
        SelfDlClose();
        LoadAll();
        return CheckOk();
    }

    // Declare all functions that you need
    // NOTE Please make sure the class instance is inited before calling those
    // functions
    DlFun<xmlDoc *, const char *> xmlParseFile;
    DlFun<void, xmlDoc *> xmlFreeDoc;
    DlFun<xmlNode *, const xmlDoc *> xmlDocGetRootElement;
    DlFun<xmlChar *, const xmlNode *, const xmlChar *> xmlGetProp;
    DlFun<void, void *> xmlFree;

private:
    DllibRc LoadAll()
    {
        // NOTE explicitly dlopen shared library
        auto ret = SelfDlOpen();
        if (ret != DllibRc::OK) {
            return ret;
        }
        if (DLLIB_SELF_DLSYM(xmlParseFile) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(xmlFreeDoc) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(xmlDocGetRootElement) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(xmlGetProp) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(xmlFree) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        return DllibRc::OK;
    }

    Libxml2() : DlLibBase(LIB_NAME)
    {
        LoadAll();
    }

    static constexpr std::string_view LIB_NAME = "libxml2.so";
};

} // namespace virtrust