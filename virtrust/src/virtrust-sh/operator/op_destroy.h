// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#pragma once

#include "virtrust-sh/operator/op_itf.h"

#include <string>
#include <vector>

namespace virtrust {

class OpDestroy : public OpItf {
public:
  explicit OpDestroy() : OpItf(OpTy::DESTROY) {}
  ~OpDestroy() override = default;

  OpRc Exec() override;

  // Parse the args from command line
  OpRc ParseArgv(int argc, char **argv) override;

  // Print the usage of this operator
  void PrintUsage() override;

private:
  std::string domainName_ = "unknown";
  unsigned int flags_ = DOMAIN_DESTROY_NONE;
  bool onlyTsb_ = false;
};

} // namespace virtrust
