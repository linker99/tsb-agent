// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

#pragma once

#include <memory>
#include <string>

namespace virtrust {

class ConnCtx {
public:
    // HACK redefine this type as it in libvirt
    using virConnectPtr = int *;

    ConnCtx();
    explicit ConnCtx(virConnectPtr conn) : conn_(conn)
    {}
    bool Connect();

    ConnCtx(const ConnCtx &) = delete;
    ConnCtx &operator=(const ConnCtx &) = delete;
    ~ConnCtx();
    bool SetUri(std::string uri);

    std::string GetUri() const;

    bool CheckOk()
    {
        return conn_ != nullptr;
    }

    // Get the raw pointer (NOTE you may receive a nullptr)
    virConnectPtr Get()
    {
        return conn_;
    }

private:
    virConnectPtr conn_ = nullptr;
    std::string uri_;
};

class DomainCtx {
public:
    using virDomainPtr = int *;
    DomainCtx() = default;
    explicit DomainCtx(virDomainPtr domain) : domain_(domain)
    {}
    explicit DomainCtx(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName);

    ~DomainCtx();
    DomainCtx(const DomainCtx &) = delete;
    DomainCtx &operator=(const DomainCtx &) = delete;

    bool CheckOk()
    {
        return domain_ != nullptr;
    }
    virDomainPtr Get()
    {
        return domain_;
    }

private:
    virDomainPtr domain_ = nullptr;
};
} // namespace virtrust
