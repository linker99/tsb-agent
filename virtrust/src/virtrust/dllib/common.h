#pragma once

#include <dlfcn.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <numeric>
#include <stdexcept>
#include <string_view>

#include "virtrust/base/str_utils.h"

namespace virtrust {

// Dllib Return Code
enum class DllibRc : uint32_t {
    OK = 0,
    ERROR = 1,
};

template <class R, class... Args> class DlFun {
public:
    using FunTy = R (*) (Args...);

    DlFun() = default;

    DlFun(std::string_view name, FunTy funcptr)
        : funcName_(name), funcptr_(funcptr ? std::function<R (Args...)>(funcptr) : std::function<R (Args...)>(nullptr))
    {}

    std::function<R (Args...)> Get() const
    {
        return funcptr_;
    }

    R operator()(Args... args) const
    {
        if (!funcptr_) {
            throw std::runtime_error(std::string("[") + __FILE__ + ":" + std::to_string(__LINE__) +
                                     "]: Fatal Error: function " + funcName_ +
                                     " is nullptr, maybe previous dlsym failed.");
        }
        return funcptr_(args...);
    }


private:
    std::string funcName_ = "unknown";
    std::function<R (Args...)> funcptr_ = nullptr;
};

class DlLibBase {
public:
    // Check weather dlopen and dlsym has succeed
    DllibRc CheckOk() const
    {
        return ok_ ? DllibRc::OK : DllibRc::ERROR;
    }

    size_t Size() const
    {
        return size_;
    }

protected:
    explicit DlLibBase(std::string_view lib) : libname_(lib)
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
        ok_ = true;
    }

    DllibRc SelfDlOpen()
    {
        libptr_ = dlopen(libname_.data(), RTLD_NOW | RTLD_GLOBAL);
        return libptr_ != nullptr ? DllibRc::OK : DllibRc::ERROR;
    }

    template <class R, class... Args> void SelfDlSym(std::string_view funName, DlFun<R, Args...> &outFun)
    {
        if (libptr_ == nullptr || funName.empty()) {
            return;
        }

        void *funPtr = dlsym(libptr_, funName.data());
        if (funPtr == nullptr) {
            ok_ = false;
        }
        size_++; // always add up internal size counter
        outFun = DlFun<R, Args...>(funName, reinterpret_cast<R (*)(Args...)>(funPtr));
    }

private:
    void *libptr_ = nullptr;
    const std::string libname_ = "unknown";

    // duncCache_ store all dlsym function raw pointers
    // WARNING: DO NOT manually manipulate those pointers
    std::vector<void *> funcCache_; // cache DO NOT own pointers, those pointers should read only
    size_t size_ = 0;
    bool ok_ = true;
};

// The second argument is the templateHelper which helps template deduction
#define DLLIB_SELF_DLSYM(NAME) SelfDlSym(#NAME, NAME)

} // namespace virtrust