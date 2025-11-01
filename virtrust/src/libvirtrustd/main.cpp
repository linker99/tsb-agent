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

#include "virtrust/base/logger.h"
#include "virtrust/link/link_server.h"

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

void PrintVersion()
{
    fmt::print("{} version: {}\n", progname, LIBVIRTRUST_VERSION);
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
    // The ":" after "c" means it has long arguments from cli, and is parsed to optarg
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
        auto server = virtrust::LinkServer(ret.value());
        server.Start();
        // REVIEW

        // hold server until receives stop signal
        while (g_stopFlag == 0) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
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

    // Set custom logger function for virtrust
    virtrust::Logger::Instance()->SetCustomLogFuntion([](virtrust::LogLevel level, std::string_view msg) {
        fmt::print("[{}] {}\n", virtrust::LogLevelToStr(level), msg);
    });

    return virtrust::ProcessArgs(argc, argv);
}
