/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "virtrust/dllib/openssl.h"
#include "virtrust/dllib/openssl_defines.h"
#include "virtrust/utils/smart_deleter.h"

namespace virtrust {

VIRTRUST_MAKE_SMART(EVP_MD_CTX, Openssl::GetInstance().EVP_MD_CTX_free);
VIRTRUST_MAKE_SMART(EVP_MD, Openssl::GetInstance().EVP_MD_free);

enum class Sm3Rc : uint32_t {
    OK = 0,
    ERROR = 1
};

class Sm3 {
public:
    Sm3();
    Sm3Rc Reset();
    Sm3Rc Update(std::string_view data);
    std::vector<uint8_t> CumulativeHash() const;

    static constexpr size_t DigestSize()
    {
        return DIGEST_SIZE;
    }

private:
    SmartEVP_MD md_;
    SmartEVP_MD_CTX context_;
    static constexpr size_t DIGEST_SIZE = 32;
    static constexpr size_t UPDATE_SIZE_LIMIT = 1024 * 1024 * 1024; // 1G
};

std::array<uint8_t, Sm3::DigestSize()> DoSm3(std::string_view data);
Sm3Rc DoSm3(std::string_view data, std::vector<uint8_t> &out);

} // namespace virtrust