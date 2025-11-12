// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

#include "virtrust/api/context.h"

#include "virtrust/api/define_private.h"
#include "virtrust/api/defines.h"
#include "virtrust/base/logger.h"
#include "virtrust/dllib/libvirt.h"

namespace virtrust {

ConnCtx::ConnCtx() : uri_(VIRTRUST_DEFAULT_URI)
{}

ConnCtx::~ConnCtx()
{
    if (conn_ != nullptr) {

        Libvirt::GetInstance().virConnectClose(conn_);
        conn_ = nullptr;
    }
}

bool ConnCtx::Connect()
{
    conn_ = Libvirt::GetInstance().virConnectOpen(uri_.data());
    if (conn_ == nullptr) {
        VIRTRUST_LOG_ERROR("virConnectOpen of uri failed, a nullptr ConnCtx has been created.");
        return false;
    }
    return true;
}

bool ConnCtx::SetUri(std::string uri)
{
    if (uri_.empty() || uri.size() > URI_MAX_LENGTH) {
        return false;
    }
    uri_ = uri;
    return true;
}

DomainCtx::DomainCtx(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName)
{
    if (conn->Get() != nullptr) {
        domain_ = Libvirt::GetInstance().virDomainLookupByName(conn->Get(), domainName.data());
        if (domain_ == nullptr) {
            VIRTRUST_LOG_ERROR("ConnCtx is nullptr, virDomainLookupByName is not "
                               "called, a nullprt DomainCtx has been created.");
        }
    }
}

DomainCtx::~DomainCtx()
{

    if (domain_ != nullptr) {
        Libvirt::GetInstance().virDomainFree(domain_);
        domain_ = nullptr;
    }
}
} // namespace virtrust
