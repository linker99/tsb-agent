#pragma once

#include <string>
#include <utility>

#include "virtrust/api/context.h"

namespace virtrust {

class MigrateHelper {
public:
    explicit MigrateHelper() = default;
    ~MigrateHelper() = default;

    explicit MigrateHelper(std::string destUri) : destUri_(destUri)
    {}

    void SetDstUri(const std::string &destUri)
    {
        destUri_ = destUri;
    }

    std::string GetDestUri()
    {
        return destUri_;
    }

    // step 1: get report that the hardware is okay
    void GetReport();

    // step 2: get the private shared key pair
    void GetKet();

    // step 3: key exchange to get a shared key
    void ExchangeKey();


private:
    ConnCtx conn_;
    std::string destUri_;
};

} // namespace virtrust