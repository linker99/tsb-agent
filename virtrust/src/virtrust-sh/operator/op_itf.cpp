// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include "virtrust-sh/operator/op_itf.h"

#include <cstdint>
#include <memory>
#include <string_view>

#include "virtrust-sh/operator/op_create.h"
#include "virtrust-sh/operator/op_destroy.h"
#include "virtrust-sh/operator/op_list.h"
#include "virtrust-sh/operator/op_migrate.h"
#include "virtrust-sh/operator/op_start.h"
#include "virtrust-sh/operator/op_undefine.h"

namespace virtrust {

std::unique_ptr<OpItf> MakeOperator(OpTy type) {
  switch (type) {
  case OpTy::CREATE:
    return std::make_unique<OpCreate>();
  case OpTy::DESTROY:
    return std::make_unique<OpDestroy>();
  case OpTy::MIGRATE:
    return std::make_unique<OpMigrate>();
  case OpTy::START:
    return std::make_unique<OpStart>();
  case OpTy::UNDEFINE:
    return std::make_unique<OpUndefine>();
  case OpTy::LIST:
    return std::make_unique<OpLIST>();
  default:
    return nullptr; // return nullptr if error
  }
}

OpTy OpTyFromStr(const std::string &type) {
  if (type == "create") {
    return OpTy::CREATE;
  } else if (type == "destroy") {
    return OpTy::DESTROY;
  } else if (type == "migrate") {
    return OpTy::MIGRATE;
  } else if (type == "start") {
    return OpTy::START;
  } else if (type == "undefine") {
    return OpTy::UNDEFINE;
  } else if (type == "list") {
    return opty::LIST;
  } else {
    return OpTy::UNKNOWN;
  }
}

std::unique_ptr<OpItf> MakeOperator(const std::string &type) {
  return MakeOperator(OpTyFromStr(type));
}
} // namespace virtrust
