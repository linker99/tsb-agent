/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <dlfcn.h>

#include <cstdint>
#include <functional>
#include <string_view>

#include "virtrust/dllib/common.h"
#include "virtrust/dllib/openssl_defines.h"

namespace virtrust {

// openssl api
class Openssl : public DlLibBase {
public:
    ~Openssl() = default;
    Openssl(const Openssl &) = delete;
    void operator=(const Openssl &) = delete;

    // Singleton instance
    static Openssl &GetInstance()
    {
        static Openssl instance;
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

    // Fetch openssl message digest context
    DlFun<EVP_MD *, OSSL_LIB_CTX *, const char *, const char *> EVP_MD_fetch;

    // Get the output size of the message digest algorithm (e.g. SM3), this
    // function is the same as EVP_MD_size
    DlFun<int, const EVP_MD *> EVP_MD_get_size;

    // Create new message digest context
    DlFun<EVP_MD_CTX *> EVP_MD_CTX_new;

    // Reset md context
    DlFun<int, EVP_MD_CTX *> EVP_MD_CTX_reset;

    // Copy md context
    DlFun<int, EVP_MD_CTX *, const EVP_MD_CTX *> EVP_MD_CTX_copy_ex;

    // Init
    DlFun<int, EVP_MD_CTX *, EVP_MD *> EVP_DigestInit;

    // Update
    DlFun<int, EVP_MD_CTX *, const void *, size_t> EVP_DigestUpdate;

    // Final
    DlFun<int, EVP_MD_CTX *, unsigned char *, unsigned int *> EVP_DigestFinal_ex;

    // Free
    DlFun<void, EVP_MD *> EVP_MD_free;
    DlFun<void, EVP_MD_CTX *> EVP_MD_CTX_free;

private:
    void LoadAll()
    {
        // NOTE explicitly dlopen shared library
        SelfDlOpen();
        DLLIB_SELF_DLSYM(EVP_MD_fetch);
        DLLIB_SELF_DLSYM(EVP_MD_get_size);
        DLLIB_SELF_DLSYM(EVP_MD_CTX_new);
        DLLIB_SELF_DLSYM(EVP_MD_CTX_reset);
        DLLIB_SELF_DLSYM(EVP_MD_CTX_copy_ex);
        DLLIB_SELF_DLSYM(EVP_DigestInit);
        DLLIB_SELF_DLSYM(EVP_DigestUpdate);
        DLLIB_SELF_DLSYM(EVP_DigestFinal_ex);
        DLLIB_SELF_DLSYM(EVP_MD_free);
        DLLIB_SELF_DLSYM(EVP_MD_CTX_free);
    }

    Openssl() : DlLibBase(LIB_NAME)
    {
        LoadAll();
    }

    static constexpr std::string_view LIB_NAME = "libcrypto.so";
};

} // namespace virtrust
