/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <getopt.h>
#include <unistd.h>

#include <csignal>
#include <iostream>
#include <thread>

#include "libvirtrustd/defines.h"
#include "libvirtrustd/utils.h"
#include "spdlog/fmt/bundled/core.h"

#include "virtrust/api/defines.h"
#include "virtrust/base/logger.h"
#include "virtrust/link/grpc_server.h"

namespace virtrust {
namespace {
volatile sig_atomic_t g_stopFlag = 0;

void SignalHandler(int signum)
{
    VIRTRUST_LOG_INFO("Received signal: {}", signum);
    if (signum == SIGPIPE) {
        VIRTRUST_LOG_INFO("SIGPIPE signal received, ignored.");

        return;
    }
    g_stopFlag = 1;
}

void PrintVersion(std::string_view progname)
{
    fmt::print("{} version: {}\n", progname, LIBVIRTRUSTD_VERSION);
}

void PrintUsage(std::string_view progname)
{
    fmt::print("\n"
               "  USAGE:\n"
               "    {} <args> [options]\n"
               "\n"
               "  REQUIRED ARGS:\n"
               "    --config           path to config file\n"
               "\n"
               "  OPTIONS:\n"
               "    --help             print this help\n"
               "    --version          show version\n"
               "\n",
               progname);
}

int ProcessArgs(int argc, char **argv)
{
    int arg = -1;
    int longindex = -1;
    std::vector<option> opt = {
        {"config", required_argument, nullptr, 'c'},
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'v'},
        {nullptr, 0, nullptr, 0},
    };

    std::string configPath;
    // The leading + means no re-ordering, see man page of getopt_long
    // The ":" after "c" means it has long arguments from cli, and is parsed to
    // optarg
    while ((arg = getopt_long(argc, argv, "+c:hv", opt.data(), &longindex)) != -1) {
        switch (arg) {
            case 'c':
                configPath = std::string(optarg);
                break;
            case 'v':
                PrintVersion(argv[0]);
                return 0; // return with success
            case 'h':
                PrintUsage(argv[0]);
                return 0; // return with success
            case '?':
            default:
                PrintUsage(argv[0]);
                return 1; // return with failure
        }
    }

    if (configPath.empty()) {
        fmt::print("\n"
                   "  ERROR: Missing requried config files\n");
        PrintUsage(argv[0]);
        return 1; // return with success
    }

    auto ret = MakeLinkConfigFromJsonFile(configPath);
    if (ret.has_value()) {
        GrpcServer sever(ret.value());
        fmt::print("start link config. Exiting...{}, {}\n", ret.value().udsPath, ret.value().caPath);
        LinkRc linkRc = sever.Start();
        if (linkRc != LinkRc::OK) {
            fmt::print("Failed to start link config. Exiting...\n");
            return 1;
        }

        while (g_stopFlag == 0) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        sever.Stop();
    } else {
        // make link config failed
        return 1;
    }
    return 0;
}
} // namespace
} // namespace virtrust

int main(int argc, char **argv)
{
    // register signal handler
    signal(SIGINT, virtrust::SignalHandler);
    signal(SIGTERM, virtrust::SignalHandler);
    signal(SIGPIPE, virtrust::SignalHandler);

    auto ret = virtrust::Logger::Instance()->InitLog(static_cast<int>(virtrust::LogLevel::INFO),
                                                     virtrust::VIRTRUSTD_LOGFILE_NAME);
    if (ret != virtrust::VirtrustRc::OK) {
        fmt::print("\nInitLog failed\n");
        return 1;
    }

    return virtrust::ProcessArgs(argc, argv);
}
