// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include "virtrust-sh/operator/op_list.h"

#include <getopt.h>

#include <string>
#include <vector>

#include "virtrust-sh/operator/op_itf.h"
#include "virtrust-sh/operator/op_utils.h"
#include "virtrust/api/domain.h"

namespace virtrust {

namespace {
constexpr int OP_LIST_EXTRA_CMD_NUM = 0;
constexpr int KB_TO_MD = 1024;
inline std::string GetIdStr(const std::unique_ptr<ConnCtx> &conn, const std::string &name)
{
    auto &libvirt = Libvirt::GetInstance();
    auto *domain = libvirt.virDomainLookupByName(conn->Get(), name.data());
    if (domain == nullptr) {
        return "-";
    }
    auto id = libvirt.virDomainGetID(domain);
    libvirt.virDomainFree(domain);
    return id == std::numeric_limits<unsigned int>::max() ? "-" : std::to_string(id);
}

inline unsigned int GetIdInt(const std::unique_ptr<ConnCtx> &conn, const std::string &name)
{
    auto &libvirt = Libvirt::GetInstance();
    auto *domain = libvirt.virDomainLookupByName(conn->Get(), name.data());
    if (domain == nullptr) {
        return std::numeric_limits<unsigned int>::max();
    }
    auto id = libvirt.virDomainGetID(domain);
    libvirt.virDomainFree(domain);
    return id;
}

inline std::string GetStateStr(int state)
{
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

struct DomainInfoForSort {
    unsigned int id;
    DomainInfo domainInfo;
};

std::vector<DomainInfoForSort> GetSortedDomainInfos(const std::unique_ptr<ConnCtx> &conn,
                                                    const std::unordered_map<std::string, DomainInfo> &domainInfos,
                                                    size_t &maxNameLen)

{
    std::vector<DomainInfoForSort> sortedInfos;
    sortedInfos.reserve(domainInfos.size());
    for (const auto &[key, info] : domainInfos) {
        DomainInfoForSort item;
        item.id = GetIdInt(conn, info.domainName);
        item.domainInfo = info;
        sortedInfos.push_back(item);
        maxNameLen = std::max(maxNameLen, info.domainName.length());
    }
    // 自定义排序
    std::sort(sortedInfos.begin(), sortedInfos.end(), [](const DomainInfoForSort &lhs, const DomainInfoForSort &rhs) {
        if (lhs.id != rhs.id) {
            return lhs.id < rhs.id;
        } else if (lhs.domainInfo.state != rhs.domainInfo.state) {
            return lhs.domainInfo.state < rhs.domainInfo.state;

        } else {
            return lhs.domainInfo.domainName < rhs.domainInfo.domainName;
        }
    });
    return sortedInfos;
}

} // namespace

OpRc OpList::Exec()
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

    std::unordered_map<std::string, DomainInfo> domainInfos = {};
    auto rc = DomainList(conn_, flags_, domainInfos, true);
    if (rc != VirtrustRc::OK) {
        return ParseVirtrustRc(rc);
    }

    size_t maxNameLen = 5;
    std::vector<DomainInfoForSort> sortedInfos = GetSortedDomainInfos(conn_, domainInfos, maxNameLen);

    fmt::print("\n{:5} {:{}} {:<10}\n", "Id", "Name", maxNameLen + 2, "State");
    std::string separator(maxNameLen + 19, '-');

    fmt::print("{}\n", separator);
    for (const auto &item : sortedInfos) {
        fmt::print("\n{:5} {:{}} {:<10}\n",
                   item.id == std::numeric_limits<unsigned int>::max() ? "-" : std::to_string(item.id),
                   item.domainInfo.domainName, maxNameLen + 2, GetStateStr(item.domainInfo.state));
    }

    return OpRc::OK;
}

// Parse the args from command line
OpRc OpList::ParseArgv(int argc, char **argv)
{
    int arg = -1;
    int longindex = -1;
    optind = 1; // reset

    std::vector<option> opt = {
        {"help", no_argument, nullptr, 'h'}, {"all", no_argument, nullptr, 'a'}, {nullptr, 0, nullptr, 0}};

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
        fmt::print("\nInvalid number of arguments, expect: {}, got: {}\n", OP_LIST_EXTRA_CMD_NUM, argc - optind);
        PrintUsage();
        return OpRc::ERROR;
    }
    return OpRc::OK;
}

// Print the usage of this operator
void OpList::PrintUsage()
{
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
