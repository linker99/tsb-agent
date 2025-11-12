/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <string>
#include <utility>

#include "virtrust/api/context.h"

namespace virtrust {

class MigrateHelper {
public:
    explicit MigrateHelper() = default;
    ~MigrateHelper() = default;

    explicit MigrateHelper(std::string destUri) : destUri_(std::move(destUri))
    {}

    void SetDstUri(const std::string &destUri)
    {
        destUri_ = destUri;
    }

    std::string GetDstUri()
    {
        return destUri_;
    }

    // step 1: get report that the hardware is okay
    void GetReport();

    // step 2: get the private shared key pair
    void GetKey();

    // step 3: key exchange to get a shared key
    void ExchangeKey();

private:
    ConnCtx conn_;
    std::string destUri_;
};

} // namespace virtrust