// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#pragma once

#include "virtrust-sh/operator/op_itf.h"

#include <string>
#include <vector>

namespace virtrust {

class OpList : public OpItf {
public:
  explicit OpList() : OpItf(OpTy::LIST) {}
  ~OpList() override = default;

  OpRc Exec() override;

  // Parse the args from command line
  OpRc ParseArgv(int argc, char **argv) override;

  // Print the usage of this operator
  OpRc PrintUsage() override;

private:
  unsigned int flags_ LIST_DOMAINS_ACTIVE; // default show only active
};

} // namespace virtrust
