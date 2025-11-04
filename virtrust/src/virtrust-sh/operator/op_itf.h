// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#pragma once

#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>

#include "virtrust/api/context.h"
#include "virtrust/base/logger.h"
#include "virtrust/dllib/libvirt.h"

namespace virtrust {

enum class OpRc : uint32_t {
    OK = 0,
    ERROR = 1,
    CHECK_FAILED = 2,
};

enum class OpTy : uint32_t {
    UNKNOWN,
    CREATE,
    DESTROY,
    MIGRATE,
    START,
    UNDEFINE,
    LIST,
};

OpTy OpTyFromStr(const std::string &type);

// Default configs for operator
// NOTE carefully tweak those default values
struct OpConfig {
    std::string uri = std::string(VIRTRUST_DEFAULT_URI);
    bool enableExec = true;
};

// Operator Interface
class OpItf {
public:
    OpItf() = delete;
    virtual ~OpItf() = default;

    // Getters and Setters

    // Get uri string
    std::string GetUri() const
    {
        return config_.uri;
    }

    // Get type
    OpTy Type() const
    {
        return type_;
    }

    // Get const reference of op's config
    const OpConfig &GetConfig() const
    {
        return config_;
    }

    void SetConfig(const OpConfig &config)
    {
        config_ = config;
    }

    virtual OpRc Exec() = 0;
    virtual OpRc ParseArgv(int argc, char **argv) = 0;
    virtual void PrintUsage() = 0;

protected:
    const OpTy type_ = OpTy::UNKNOWN;
    std::unique_ptr<ConnCtx> conn_ = nullptr;
    std::unique_ptr<DomainCtx> domain_ = nullptr;
    OpConfig config_ = {};

    explicit OpItf(OpTy type) : type_(type)
    {}
    explicit OpItf(OpTy type, OpConfig config) : type_(type), config_(std::move(config))
    {}
};

// Operator Factory
std::unique_ptr<OpItf> MakeOperator(OpTy type);
std::unique_ptr<OpItf> MakeOperator(const std::string &type);

} // namespace virtrust
