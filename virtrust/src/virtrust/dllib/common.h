/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <dlfcn.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <numeric>
#include <stdexcept>
#include <string_view>

#include "virtrust/base/exception.h"
#include "virtrust/base/str_utils.h"

namespace virtrust {

// Dllib Return Code
enum class DllibRc : uint32_t {
    OK = 0,
    ERROR = 1,
};

template <class R, class... Args> class DlFun {
public:
    using FunTy = R (*)(Args...);

    DlFun() = default;

    DlFun(std::string_view name, FunTy funptr)
        : funName_(name), funptr_(funptr ? std::function<R(Args...)>(funptr) : std::function<R(Args...)>(nullptr))
    {}

    std::function<R(Args...)> Get() const
    {
        return funptr_;
    }

    std::string GetName() const
    {
        return funName_;
    }

    R operator()(Args... args) const
    {
        if (!funptr_) {
            throw std::runtime_error(std::string("[") + __FILE__ + ":" + std::to_string(__LINE__) +
                                     "] Fatal Error: function " + funName_ +
                                     " is nullptr, maybe previous dlsym failed.");
        }
        return funptr_(std::forward<Args>(args)...);
    }

private:
    std::string funName_ = "unknown";
    std::function<R(Args...)> funptr_ = nullptr;
};

class DlLibBase {
public:
    // Check whether dlopen and dlsym has succeed
    DllibRc CheckOk() const
    {
        return libptr_ != nullptr ? DllibRc::OK : DllibRc::ERROR;
    }

    size_t Size() const
    {
        return size_;
    }

protected:
    explicit DlLibBase(std::string_view lib) : libName_(lib)
    {}

    virtual ~DlLibBase()
    {
        SelfDlClose();
    }

    void SelfDlClose()
    {
        // the stored pointer
        if (libptr_ != nullptr) {
            dlclose(libptr_);
            libptr_ = nullptr;
        }

        // reset to default
        size_ = 0;
    }

    void SelfDlOpen()
    {
        libptr_ = dlopen(libName_.data(), RTLD_NOW | RTLD_GLOBAL);
        VIRTRUST_ENFORCE(libptr_ != nullptr, std::string(dlerror()));
    }

    template <class R, class... Args> void SelfDlSym(std::string_view funName, DlFun<R, Args...> &outFun)
    {
        VIRTRUST_ENFORCE(libptr_ != nullptr && !funName.empty(), "funName:", funName,"  is empty or libprt is nullptr");
        void *funPtr = dlsym(libptr_, funName.data());
        size_++; // always add up internal size counter
        outFun = DlFun<R, Args...>(funName, reinterpret_cast<R (*)(Args...)>(funPtr));
    }

private:
    void *libptr_ = nullptr;
    const std::string libName_ = "unknown";

    // funCache_ stores all dlsym function raw pointers
    // WARNING: DO NOT manually manipulate those pointers
    std::vector<void *> funCache_; // cache DO NOT own pointers, those pointers should read only
    size_t size_ = 0;
};

// The second argument is the templateHelper which helps template deduction
#define DLLIB_SELF_DLSYM(NAME) SelfDlSym(#NAME, NAME)

} // namespace virtrust