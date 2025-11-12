/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "virtrust/base/str_utils.h"

#include <sstream>
#include <string>
#include <vector>

namespace virtrust {

void StrSplit(std::string_view src, std::string_view sep, std::vector<std::string> &out)
{

    if (src.empty() || sep.empty()) {
        return;
    }
    std::string::size_type pos1 = 0;
    std::string::size_type pos2 = src.find(sep);
    while (pos2 != std::string::npos) {
        out.emplace_back(src.substr(pos1, pos2 - pos1));
        pos1 = pos2 + sep.size();
        pos2 = src.find(sep, pos1);
    }
    if (pos1 != src.size())
        out.emplace_back(src.substr(pos1));
}

} // namespace virtrust
