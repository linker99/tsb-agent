// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#pragma once

#include "virtrust-sh/operator/op_itf.h"

#include <string>
#include <vector>

namespace virtrust {

class OpCreate : public OpItf {
public:
  explicit OpCreate() : OpItf(OpTy::CREATE) {}
  ~OpCreate() override = default;

  OpRc Exec() override;

  // Parse the args from command line
  OpRc ParseArgv(int argc, char **argv) override;

  // Print the usage of this operator
  void PrintUsage() override;

private:
  std::vector<std::string> virtInstallArgs_;
};

} // namespace virtrust
