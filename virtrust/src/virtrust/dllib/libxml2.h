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
    void LoadAll()
    {
        // NOTE explicitly dlopen shared library
        SelfDlOpen();
        DLLIB_SELF_DLSYM(xmlParseFile);
        DLLIB_SELF_DLSYM(xmlFreeDoc);
        DLLIB_SELF_DLSYM(xmlDocGetRootElement);
        DLLIB_SELF_DLSYM(xmlGetProp);
        DLLIB_SELF_DLSYM(xmlFree);
    }

    Libxml2() : DlLibBase(LIB_NAME)
    {
        LoadAll();
    }

    static constexpr std::string_view LIB_NAME = "libxml2.so";
};

} // namespace virtrust