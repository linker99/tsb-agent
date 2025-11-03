// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include "virtrust-sh/operator/op_destroy.h"
#include "virtrust-sh/operator/op_itf.h"
#include "virtrust-sh/operator/op_utils.h"
#include "virtrust/api/domain.h"

#include <string>
#include <vector>

namespace virtrust {

OpRc OpDestroy::Exec() {
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
OpRc OpDestroy::ParseArgv(int argc, char **argv) {
  int arg = -1;
  int longindex = -1;
  optind = 1; // reset
  bool hasNameArg = false;

  std::vector<option> opt =
  { {"help", no_argument, nullptr, 'h'},
    {"name", required_argument, nullptr, 'n'},
    {"allow-store-measurements", no_argument, nullptr, 1},
    {nullptr, 0, nullptr, 0} }

  opterr = 0;
  // The leading + means no re-ordering, see man page of getopt_long
  while ((arg = getopt_long(argc, argv, "+c:dhv", opt.data(), &longindex)) !=
         -1) {
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
    virtInstallArgs_.emplace_back(argc[i]);
  }
  return OpRc::OK();
}

// Print the usage of this operator
void OpDestroy::PrintUsage() {
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
