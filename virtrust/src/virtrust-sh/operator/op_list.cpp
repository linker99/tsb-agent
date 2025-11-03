// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include "virtrust-sh/operator/op_list.h"
#include "virtrust-sh/operator/op_itf.h"
#include "virtrust-sh/operator/op_utils.h"
#include "virtrust/api/domain.h"

#include <getopt.h>
#include <string>
#include <vector>

namespace virtrust {

namespace {
constexpr int OP_LIST_EXTRA_CMD_NUM = 0;
constexpr int KB_TO_MD = 1024;
inline std::string GetIdStr(const std::unique_ptr<ConnCtx> &conn,
                            const std::string &name) {
  auto &libvirt = Libvirt::GetInstance();
  auto *domain = libvirt.virDomainLookupByName(conn->Get(), name.data());
  if (domain == nullptr) {
    return "-";
  }
  auto id = libvirt.virDomainGetID(domain);
  libvirt.virDomainFree(domain);
  return id == std::numeric_limits<unsigned int>::max() ? "-"
                                                        : std::to_string(id);
}

inline std::string GetStateStr(int state) {
  switch (state) {
  case VIR_DOMAIN_RUNNING:
    return "running";
  case VIR_DOMAIN_PAUSED:
    return "paused";
  case VIR_DOMAIN_SHUTDOWN:
    return "shut down";
  case VIR_DOMAIN_SHUTOFF:
    return "shut off";
  case VIR_DOMAIN_CRASHED:
    return "crashed";
  default:
    return "unknown";
  }
}
} // namespace

OpRc OpList::Exec() {
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

  std::unordered_map<std::string, DomainInfo> domainInfos = {};
  auto rc = DomainList(conn_, flags_, domainInfos, true);
  if (rc != VirtrustRc::OK) {
    return ParseVirtrustRc(rc);
  }

  fmt::print("\n{:5} {:15} {:<10}\n", "ID", "NAME", "STATE");
  fmt::print("------------------------------\n");
  for (const auto &domain : domainInfos) {
    fmt::print("\n{:5} {:15} {:<10}\n",
               GetIdStr(conn_, domain.second.domainName),
               domain.second.domainName, GetStateStr(domain.second.state));
  }

  return OpRc::OK;
}

// Parse the args from command line
OpRc OpList::ParseArgv(int argc, char **argv) {
  int arg = -1;
  int longindex = -1;
  optind = 1; // reset

  std::vector<option> opt = {{"help", no_argument, nullptr, 'h'},
                             {"all", required_argument, nullptr, 'a'},
                             {nullptr, 0, nullptr, 0}};

  opterr = 0;
  // The leading + means no re-ordering, see man page of getopt_long
  while ((arg = getopt_long(argc, argv, "+ah", opt.data(), &longindex)) != -1) {
    switch (arg) {
    case 'h':
      config_.enableExec = false;
      PrintUsage();
      optind = argc; // stop parsing
      return OpRc::OK;
    case 'a':
      // see: libvirt/tools/virsh-domain-monitor.c, line 1890
      flags_ = LIST_DOMAINS_ACTIVE | LIST_DOMAINS_INACTIVE;
      break;
    default:
      config_.enableExec = false;
      PrintUsage();
      optind = argc; // stop parsing
      return OpRc::ERROR;
    }
  }

  if (argc - optind != OP_LIST_EXTRA_CMD_NUM) {
    fmt::print("\nInvalid number of arguments, expect: {}, got: {}\n",
               OP_LIST_EXTRA_CMD_NUM, argc - optind);
    PrintUsage();
    return OpRc::ERROR;
  }
  return OpRc::OK;
}

// Print the usage of this operator
void OpList::PrintUsage() {
  fmt::print("\n"
             "  NAME:\n"
             "    list - list domains\n"
             "\n"
             "  SYNOPSIS:\n"
             "    list [options]\n"
             "\n"
             "  OPTIONS:\n"
             "    -h | --help                    this help\n"
             "    -a | --all                     list all domains\n"
             "\n");
}

} // namespace virtrust
