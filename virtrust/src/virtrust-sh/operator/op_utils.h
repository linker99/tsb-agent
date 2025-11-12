// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#pragma once

#include "virtrust-sh/defines.h"
#include "virtrust-sh/operator/op_itf.h"

namespace virtrust {

inline OpRc ParseCmdStr(char *argv, std::string &out)
{
    if (strlen(argv) >= VIRTRUST_SH_CMD_STR_MAX_LEN) {
        return OpRc::ERROR;
    }
    out = argv;
    return OpRc::OK;
}

inline OpRc ParseVirtrustRc(VirtrustRc rc)
{
    switch (rc) {
        case VirtrustRc::OK:
            return OpRc::OK;
        case VirtrustRc::ERROR:
            return OpRc::ERROR;
        default:
            VIRTRUST_LOG_ERROR("Unknown virtrust return code: {}", static_cast<int>(rc));
            return OpRc::ERROR;
    }
}

} // namespace virtrust
