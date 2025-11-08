/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include "virtrust/crypto/sm3.h"

#include <securec.h>

#include <vector>

#include "virtrust/base/logger.h"
#include "virtrust/dllib/openssl.h"

namespace virtrust {

Sm3::Sm3()
    : md_(SmartEVP_MD(Openssl::GetInstance().EVP_MD_fetch(nullptr, "sm3", nullptr))),
      context_(SmartEVP_MD_CTX(Openssl::GetInstance().EVP_MD_CTX_new()))
{
    Reset();
}

Sm3Rc Sm3::Reset()
{
    if (context_.Get() == nullptr || md_.Get() == nullptr) {
        VIRTRUST_LOG_ERROR("Sm3::Reset() Failed, context_ or md_ is nullptr");
        return Sm3Rc::ERROR;
    }

    auto ret = Openssl::GetInstance().EVP_MD_CTX_reset(context_.Get());
    if (ret != OPENSSL_OK) {
        VIRTRUST_LOG_ERROR("Sm3::Reset() Failed, EVP_MD_CTX_reset return:{}", ret);
        return Sm3Rc::ERROR;
    }

    // NOTE we do not need to reset md_-
    ret = Openssl::GetInstance().EVP_DigestInit(context_.Get(), md_.Get());
    if (ret != OPENSSL_OK) {
        VIRTRUST_LOG_ERROR("Sm3::Reset() Failed, EVP_DigestInit return:{}", ret);
        return Sm3Rc::ERROR;
    }

    return Sm3Rc::OK;
}

Sm3Rc Sm3::Update(std::string_view data)
{
    if (data.size() > UPDATE_SIZE_LIMIT) {
        VIRTRUST_LOG_ERROR("Sm3::Update() Failed, input data size:{}, exceeds limit:{}", data.size(),
                           UPDATE_SIZE_LIMIT);
        return Sm3Rc::ERROR;
    }

    if (context_.Get() == nullptr) {
        VIRTRUST_LOG_ERROR("Sm3::Update() Failed, context is nullptr");
        return Sm3Rc::ERROR;
    }

    auto ret = Openssl::GetInstance().EVP_DigestUpdate(context_.Get(), data.data(), data.size());
    if (ret != OPENSSL_OK) {
        VIRTRUST_LOG_ERROR("Sm3::Update() Failed, EVP_DigestUpdate  returns: {}", ret);
        return Sm3Rc::ERROR;
    }

    return Sm3Rc::OK;
}

std::vector<uint8_t> Sm3::CumulativeHash() const
{
    if (context_.Get() == nullptr || md_.Get() == nullptr) {
        VIRTRUST_LOG_ERROR("Sm3::CumulativeHash() Failed, context_ or md_ is nullptr");
        return {};
    }

    unsigned int out_len = 0;
    std::vector<uint8_t> out(DigestSize());

    auto ctx_snapshot = SmartEVP_MD_CTX(Openssl::GetInstance().EVP_MD_CTX_new());
    if (ctx_snapshot.Get() == nullptr) {
        VIRTRUST_LOG_ERROR("Sm3::CumulativeHash() Failed, EVP_MD_CTX_new returns nullptr");
        return {};
    }

    auto ret = Openssl::GetInstance().EVP_MD_CTX_copy_ex(ctx_snapshot.Get(), context_.Get());
    if (ret != OPENSSL_OK) {
        VIRTRUST_LOG_ERROR("Sm3::CumulativeHash() Failed, EVP_MD_CTX_copy_ex returns:{}", ret);
        return {};
    }

    ret = Openssl::GetInstance().EVP_DigestFinal_ex(ctx_snapshot.Get(), out.data(), &out_len);
    if (ret != OPENSSL_OK) {
        VIRTRUST_LOG_ERROR("Sm3::CumulativeHash() Failed, EVP_DigestFinal_ex returns:{}", ret);
        return {};
    }

    if (out_len != DigestSize()) {
        VIRTRUST_LOG_ERROR("Sm3::CumulativeHash() Failed, EVP_DigestFinal_ex "
                           "output len incorrect:{}",
                           out_len);
        return {};
    }

    return out;
}

std::array<uint8_t, Sm3::DigestSize()> DoSm3(std::string_view data)
{
    auto sm3 = Sm3();
    if (sm3.Update(data) != Sm3Rc::OK) { // data.size limit will be captured here
        VIRTRUST_LOG_ERROR("DoSm3() Failed, Update error");
        return {};
    }

    auto buf = sm3.CumulativeHash();
    if (buf.size() < Sm3::DigestSize()) {
        VIRTRUST_LOG_ERROR("DoSm3() Failed, CumulativeHash output len incorrent:{}", buf.size());
        return {};
    }

    std::array<uint8_t, Sm3::DigestSize()> out{};
    auto ret = memcpy_s(out.data(), out.size(), buf.data(), buf.size());
    if (ret != EOK) {
        VIRTRUST_LOG_ERROR("DoSm3() Failed, memcpy_s error. ret is: {}", ret);
        return {};
    }

    return out;
}

Sm3Rc DoSm3(std::string_view data, std::vector<uint8_t> &out)
{
    auto sm3 = Sm3();
    if (sm3.Update(data) != Sm3Rc::OK) { // data.size limit will be captured here
        VIRTRUST_LOG_ERROR("DoSm3() Failed, update error");
        return Sm3Rc::ERROR;
    }

    auto buf = sm3.CumulativeHash();
    if (buf.size() < Sm3::DigestSize()) {
        VIRTRUST_LOG_ERROR("DoSm3() Failed, CumulativeHash output len incorrent:{}", buf.size());
        return Sm3Rc::ERROR;
    }

    auto ret = memcpy_s(out.data(), out.size(), buf.data(), buf.size());
    if (ret != EOK) {
        VIRTRUST_LOG_ERROR("DoSm3() Failed, memcpy_s error. ret is: {}", ret);
        return Sm3Rc::ERROR;
    }

    return Sm3Rc::OK;
}

} // namespace virtrust
