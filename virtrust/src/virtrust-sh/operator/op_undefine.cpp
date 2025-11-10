// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include "virtrust-sh/operator/op_undefine.h"

#include <getopt.h>

#include <string>
#include <vector>

#include "virtrust-sh/operator/op_itf.h"
#include "virtrust-sh/operator/op_utils.h"
#include "virtrust/api/domain.h"

namespace virtrust {
namespace {
constexpr int OP_UNDEFINE_EXTRA_CMD_NUM = 1;
}

OpRc OpUndefine::Exec()
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
    return ParseVirtrustRc(DomainUndefine(conn_, domainName_, flags_, isOnlyTsb_));
}

OpRc OpUndefine::CheckOptions(int longindex) {
    if (longindex == 0) {
        if (flags_ == DOMAIN_UNDEFINE_KEEP_NVRAM) { // --nvram
            fmt::print("Options --nvram and --keep-nvram are mutually exclusive.\n");
            return OpRc::ERROR;
        }
        flags_ = DOMAIN_UNDEFINE_NVRAM;
    } else if (longindex == 1) {
        if (flags_ == DOMAIN_UNDEFINE_NVRAM) { // --keep-nvram
            fmt::print("Options --nvram and --keep-nvram are mutually exclusive.\n");
            return OpRc::ERROR;
        }
        flags_ = DOMAIN_UNDEFINE_KEEP_NVRAM;
    } else if (longindex == 2) { // --only-tsb
        isOnlyTsb_ = true;
    } else {
        fmt::print("Invalid option index: {}\n", longindex);
        PrintUsage();
        return OpRc::ERROR;
    }
    return OpRc::OK;
}
// Parse the args from command line
OpRc OpUndefine::ParseArgv(int argc, char **argv)
{
    int arg = -1;
    int longindex = -1;
    optind = 1;                   // reset
    std::vector<option> opt = {
        {"nvram", no_argument, nullptr, 0},
        {"keep-nvram", no_argument, nullptr, 0},
        {"only-tsb", no_argument, nullptr, 0},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}};

    opterr = 0;
    // The leading + means no re-ordering, see man page of getopt_long
    while ((arg = getopt_long(argc, argv, "+h", opt.data(), &longindex)) != -1) {
        switch (arg) {
            case 'h':
                config_.enableExec = false;
                PrintUsage();
                optind = argc; // stop parsing
                return OpRc::OK;
            case 0:
                if (CheckOptions(longindex) != OpRc::OK) {
                    return OpRc::ERROR;
                }
                break;
            default:
                config_.enableExec = false;
                PrintUsage();
                optind = argc; // stop parsing
                return OpRc::ERROR;
        }
    }

    if (argc - optind != OP_UNDEFINE_EXTRA_CMD_NUM) {
        fmt::print("\nInvalid number of arguments, expect: {}, got: {}\n", OP_UNDEFINE_EXTRA_CMD_NUM, argc - optind);
        PrintUsage();
        return OpRc::ERROR;
    }

    if (strlen(argv[optind]) != 0) {
        domainName_ = argv[optind];
        return OpRc::OK;
    } else {
        VIRTRUST_LOG_ERROR("Invalid empty domain name");
        return OpRc::ERROR;
    }
}

// Print the usage of this operator
void OpUndefine::PrintUsage()
{
    fmt::print("\n"
               "  NAME:\n"
               "    undefine - undefine a domain\n"
               "\n"
               "  SYNOPSIS:\n"
               "    destroy [options] <domain>\n"
               "\n"
               "  OPTIONS:\n"
               "    -h | --help                    this help\n"
               "    --nvram                        remove nvram file\n"
               "    --keep-nvram                   keep nvram file\n"
               "    --only-tsb                     only remove tsb resources, <domain> need uuid\n"
               "\n");
}

} // namespace virtrust
