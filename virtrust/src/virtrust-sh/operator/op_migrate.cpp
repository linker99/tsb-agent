// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include "virtrust-sh/operator/op_migrate.h"

#include <getopt.h>

#include <string>
#include <vector>

#include "virtrust-sh/operator/op_itf.h"
#include "virtrust-sh/operator/op_utils.h"
#include "virtrust/api/domain.h"

namespace virtrust {
namespace {
constexpr int OP_MIGRATE_EXTRA_CMD_NUM = 2;
}

OpRc OpMigrate::Exec()
{
    // make connection
    conn_.reset();
    conn_ = std::make_unique<ConnCtx>();
    if (!conn_->SetUri(config_.uri)) {
        VIRTRUST_LOG_ERROR("Failed to set uri: {}", config_.uri);
        return OpRc::ERROR;
    }
    conn_->Connect();
    if (conn_->Get() == nullptr) {
        VIRTRUST_LOG_ERROR("Failed to establish connection to: {}", config_.uri);
        return OpRc::ERROR;
    }
    return ParseVirtrustRc(DomainMigrate(conn_, domainName_, destUri_, flags_));
}

// Parse the args from command line
OpRc OpMigrate::ParseArgv(int argc, char **argv)
{
    int arg = -1;
    int longindex = -1;
    optind = 1; // reset

    std::vector<option> opt = {
        {"help", no_argument, nullptr, 'h'}, {"undefinesource", no_argument, nullptr, 0}, {nullptr, 0, nullptr, 0}};

    // The leading + means no re-ordering, see man page of getopt_long
    while ((arg = getopt_long(argc, argv, "+h", opt.data(), &longindex)) != -1) {
        switch (arg) {
            case 'h':
                config_.enableExec = false;
                PrintUsage();
                optind = argc; // stop parsing
                return OpRc::OK;
            case 0:
                if (flags_ & MIGRATE_UNDEFINE_SOURCE) {
                    fmt::print("\nOption --undefinesource is already set.\n");
                    return OpRc::ERROR;
                }
                flags_ |= MIGRATE_UNDEFINE_SOURCE;
                break;
            default:
                config_.enableExec = false;
                PrintUsage();
                optind = argc; // stop parsing
                return OpRc::ERROR;
        }
    }

    if (argc - optind != OP_MIGRATE_EXTRA_CMD_NUM) {
        fmt::print("\nInvalid number of arguments, expect: {}, got: {}\n", OP_MIGRATE_EXTRA_CMD_NUM, argc - optind);
        PrintUsage();
        return OpRc::ERROR;
    }

    if (strlen(argv[optind]) != 0) {
        domainName_ = argv[optind];
    } else {
        VIRTRUST_LOG_ERROR("Invalid empty domain name");
        return OpRc::ERROR;
    }

    if (strlen(argv[optind + 1]) != 0) {
        destUri_ = argv[optind + 1];
    } else {
        VIRTRUST_LOG_ERROR("Invalid empty domain name");
        return OpRc::ERROR;
    }
    return OpRc::OK;
}

// Print the usage of this operator
void OpMigrate::PrintUsage()
{
    fmt::print("\n"
               "  NAME:\n"
               "    migrate - migrate domain to another host\n"
               "\n"
               "  SYNOPSIS:\n"
               "    migrate [options] <domain> <desturi>\n"
               "\n"
               "  OPTIONS:\n"
               "    -h | --help                    this help\n"
               "    --undefinesource               undefine VM on source\n"
               "\n");
}

} // namespace virtrust
