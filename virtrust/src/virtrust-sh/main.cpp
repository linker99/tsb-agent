// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include <getopt.h>
#include <unistd.h>

#include <array>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>

#include "spdlog/fmt/fmt.h"

#include "virtrust-sh/defines.h"
#include "virtrust-sh/operator/op_itf.h"
#include "virtrust/base/custom_logger.h"
#include "virtrust/base/logger.h"

namespace {

std::string GetLogPath()
{
    return std::filesystem::current_path() / virtrust::VIRTRUST_SH_LOGFILE_NAME;
}

void PrintVersion(std::string_view progname)
{
    fmt::print("{} version: {}\n", progname, virtrust::VIRTRUST_SH_VERSION);
}

void PrintUsage(std::string_view progname)
{
    fmt::print("\n"
               "  USAGE:\n"
               "    {} [options]... [<command_string>]\n"
               "    {} [options]... <command> [args...]\n"
               "\n"
               "  OPTIONS:\n"
               "    -c | --connect=URI             hypervisor connection URI, "
               "default to {}\n"
               "    -d | --debug                   run in debug mode\n"
               "    -h | --help                    print this help\n"
               "    -v | --version                 show verion\n"
               "\n"
               "  COMMANDS:\n"
               "    create                         create virtual machine instance\n"
               "    destroy                        destroy (stop) a domain\n"
               "    list                           list domain information\n"
               "    migrate                        migrate domain to another host\n"
               "    start                          start a (previously define) inactive "
               "domain\n"
               "    undefine                       undefine a domain\n"
               "\n",
               progname, progname, virtrust::VIRTRUST_DEFAULT_URI);
}

int ProcessOp(int argc, char **argv, const virtrust::OpConfig &config)
{
    auto op = virtrust::MakeOperator(virtrust::OpTyFromStr(argv[optind]));
    if (op == nullptr) {
        fmt::print(":\nInvalid command: {}\n", argv[optind]);
        PrintUsage(argv[0]);
        return 1;
    }

    // Setup config
    op->SetConfig(config);

    // Parse subcommand
    auto rc = op->ParseArgv(argc - optind, &argv[optind]);
    if (rc != virtrust::OpRc::OK) {
        return 1;
    }

    // Execute subcommand, if enabled
    if (op->GetConfig().enableExec) {
        rc = op->Exec();
        if (rc != virtrust::OpRc::OK) {
            fmt::print("\nCommand execution failed.\nSee log at: {}\n", GetLogPath());
            return 1;
        }
    }
    fmt::print("\nCommand execution succeed.\nSee log at: {}\n", GetLogPath());
    return 0;
}

int ProcessArgs(int argc, char **argv)
{
    int arg = -1;
    int longindex = -1;
    std::vector<option> opt = {{"connect", required_argument, nullptr, 'c'},
                               {"debug", no_argument, nullptr, 'd'},
                               {"help", no_argument, nullptr, 'h'},
                               {"version", no_argument, nullptr, 'v'},
                               {nullptr, 0, nullptr, 0}};

    virtrust::OpConfig op_config = {}; // default init

    // The leading + means no re-ordering, see man page of getopt_long
    while ((arg = getopt_long(argc, argv, "+c:dhv", opt.data(), &longindex)) != -1) {
        switch (arg) {
            case 'c':
                op_config.uri = optarg;
                break;
            case 'd':
                virtrust::Logger::Instance()->SetDisplayLogLevel(virtrust::LogLevel::DEBUG);
                break;
            case 'v':
                PrintVersion(argv[0]);
                optind = argc; // stop parsing
                return 0;      // success
            case 'h':
                PrintUsage(argv[0]);
                optind = argc; // stop parsing
                return 0;      // success
            case '?':
                PrintUsage(argv[0]);
                optind = argc; // stop parsing
                return 1;      // fail
            default:
                PrintUsage(argv[0]);
                return 1; // fail
        }
    }

    if (argc == optind) {
        PrintUsage(argv[0]);
        return 1; // fail
    } else {
        return ProcessOp(argc, argv, op_config);
    }
}

} // namespace

int main(int argc, char *argv[])
{
    // Check input parameters
    if (argv[0] == nullptr || strlen(argv[0]) > PATH_MAX) {
        fmt::print("Invalid program name length, exit with failure\n");
        return 1;
    }

    // Init log file for virtrust
    auto ret = virtrust::Logger::Instance()->InitLog(static_cast<int>(virtrust::LogLevel::INFO), GetLogPath().data());
    if (ret != virtrust::VirtrustRc::OK) {
        fmt::print("\nInit log failed!\n");
        return 1;
    }

    // Let libvirt print its err to virtrust
    virtrust::Libvirt::GetInstance().SetErrorFunction([]([[maybe_unused]] void *userData, virtrust::virErrorPtr error) {
        auto logLevel = virtrust::virErrorLevelToLogLevel(error->level);
        // domain: see
        // https://libvirt.org/html/libvirt-virterror.html#virErrorDomain
        // code: see
        // https://libvirt.org/html/libvirt-virterror.html#virErrorNumber
        auto logMsg = fmt::format("[LIBVIRT domain: {}, code: {}] {}", error->domain, error->code, error->message);
        virtrust::Logger::Instance()->Log(logLevel, logMsg);
    });

    // Run virtrust based on args
    return ProcessArgs(argc, argv);
}
