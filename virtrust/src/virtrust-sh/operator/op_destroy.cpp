// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include "virtrust-sh/operator/op_destroy.h"

#include <getopt.h>

#include <string>
#include <vector>

#include "virtrust-sh/operator/op_itf.h"
#include "virtrust-sh/operator/op_utils.h"
#include "virtrust/api/domain.h"

namespace virtrust {
namespace {
constexpr int OP_DESTROY_EXTRA_CMD_NUM = 1;
}

OpRc OpDestroy::Exec()
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
    return ParseVirtrustRc(DomainDestroy(conn_, domainName_, flags_, onlyTsb_));
}

// Parse the args from command line
OpRc OpDestroy::ParseArgv(int argc, char **argv)
{
    int arg = -1;
    int longindex = -1;
    optind = 1;                   // reset
    const int onlyTsbVal = 0x100; // REVIEW why?
    std::vector<option> opt = {
        {"help", no_argument, nullptr, 'h'}, {"only-tsb", no_argument, nullptr, onlyTsbVal}, {nullptr, 0, nullptr, 0}};

    // The leading + means no re-ordering, see man page of getopt_long
    while ((arg = getopt_long(argc, argv, "+c:dhv", opt.data(), &longindex)) != -1) {
        switch (arg) {
            case 'h':
                config_.enableExec = false;
                PrintUsage();
                optind = argc; // stop parsing
                return OpRc::OK;
            case onlyTsbVal:
                onlyTsb_ = true;
                continue;
            default:
                config_.enableExec = false;
                PrintUsage();
                optind = argc; // stop parsing
                return OpRc::ERROR;
        }
    }

    if (argc - optind != OP_DESTROY_EXTRA_CMD_NUM) {
        fmt::print("\nInvalid number of arguments, expect: {}, got: {}\n", OP_DESTROY_EXTRA_CMD_NUM, argc - optind);
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
void OpDestroy::PrintUsage()
{
    fmt::print("\n"
               "  NAME:\n"
               "    destroy - destroy (stop) a domain\n"
               "\n"
               "  SYNOPSIS:\n"
               "    destroy [options] <domain>\n"
               "\n"
               "  OPTIONS:\n"
               "    -h | --help                    this help\n"
               "    --onlyTsb                      only update tsb resource, "
               "<domain> should be replaced with uuid if --onlyTsb enabled\n"
               "\n");
}

} // namespace virtrust
