// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#pragma once

#include "virtrust-sh/operator/op_itf.h"

#include <string>
#include <vector>

namespace virtrust {

class OpMigrate : public OpItf {
public:
  explicit OpMigrate() : OpItf(OpTy::MIGRATE) {}
  ~OpMigrate() override = default;

  OpRc Exec() override;

  // Parse the args from command line
  OpRc ParseArgv(int argc, char **argv) override;

  // Print the usage of this operator
  OpRc PrintUsage() override;

private:
  std::string domainName_ = "unknown";
  std::string destUri_;
};

} // namespace virtrust
