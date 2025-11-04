// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include "virtrust-sh/operator/op_create.h"

#include <getopt.h>

#include <string>
#include <vector>

#include "virtrust-sh/operator/op_itf.h"
#include "virtrust-sh/operator/op_utils.h"
#include "virtrust/api/domain.h"

namespace virtrust {

OpRc OpCreate::Exec()
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
    return ParseVirtrustRc(DomainCreate(conn_, virtInstallArgs_));
}

// Parse the args from command line
OpRc OpCreate::ParseArgv(int argc, char **argv)
{
    int arg = -1;
    int longindex = -1;
    optind = 1; // reset
    bool hasNameArg = false;

    std::vector<option> opt = {{"help", no_argument, nullptr, 'h'},
                               {"name", required_argument, nullptr, 'n'},
                               {"allow-store-measurements", no_argument, nullptr, 1},
                               {nullptr, 0, nullptr, 0}};

    opterr = 0;
    // The leading + means no re-ordering, see man page of getopt_long
    while ((arg = getopt_long(argc, argv, "+c:dhv", opt.data(), &longindex)) != -1) {
        switch (arg) {
            case 'h':
                config_.enableExec = false;
                PrintUsage();
                optind = 1;
                return OpRc::OK;
            case 'n':
                hasNameArg = true;
                break;
            default:
                continue; // do nothing;
        }
    }

    opterr = 1;
    if (!hasNameArg) {
        fmt::print("\n--name/-n not set.\n");
        return OpRc::ERROR;
    }

    virtInstallArgs_.clear();

    // all args should be parse to virt-install, so nothing need to be done here
    virtInstallArgs_.emplace_back(VIRTRUST_SH_VIRT_INSTALL_PATH);
    for (auto i = 1; i < argc; ++i) {
        virtInstallArgs_.emplace_back(argv[i]);
    }
    return OpRc::OK;
}

// Print the usage of this operator
void OpCreate::PrintUsage()
{
    fmt::print("\n"
               "  NAME:\n"
               "    create - create a new virtual machine\n"
               "\n"
               "  SYNOPSIS:\n"
               "    create [options] <args>\n"
               "\n"
               "  OPTIONS:\n"
               "    -h | --help                    this help\n"
               "    --allow-store-measurements     allow store measurements\n"
               "                                   (NOTE when using this option, "
               "--name must be provided)\n"
               "\n"
               "  ARGS:\n"
               "    virt-install args, see all supported args with `virt-install "
               "--help`.\n"
               "\n");
}

} // namespace virtrust
