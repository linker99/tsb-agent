// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include <string>
#include <getopt.h>
#include <memory>
#include <vector>

// 在fuzzing模式下禁用外部效果
#ifdef VIRTRUST_MOCK
#define VIRTRUST_FUZZING_CLI_MODE
#endif

static std::vector<std::string> g_args;
static std::vector<char*>       g_argv;

extern int FuzzVirtrustCliMain(int argc, char *argv[]);

// 从fuzz数据中提取CLI参数
static std::vector<std::string> ExtractCliArgs(const uint8_t* data, size_t size)
{
    std::vector<std::string> args;

    if (size < 2) {
        return args; // 至少需要2字节存储argc
    }

    // 提取argc (2字节，小端序)
    uint16_t argc = 0;
    argc = static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);

    const uint8_t* payload = data + 2;
    size_t payloadSize = size - 2;

    if (argc == 0 || payloadSize == 0) {
        return args;
    }

    // 限制最大参数数量，防止内存问题
    if (argc > 64) {
        argc = 64;
    }

    // 提取每个参数
    for (uint16_t i = 0; i < argc && payloadSize > 0; i++) {
        if (payloadSize < 1) {
            break; // 需要至少1字节存储长度
        }

        uint8_t argLen = payload[0];
        payload++;
        payloadSize--;

        if (argLen == 0) {
            args.push_back(""); // 空参数
            continue;
        }

        if (payloadSize < argLen) {
            // 数据不完整，使用剩余数据
            args.emplace_back(reinterpret_cast<const char*>(payload), payloadSize);
            break;
        }

        // 提取参数字符串
        args.emplace_back(reinterpret_cast<const char*>(payload), argLen);
        payload += argLen;
        payloadSize -= argLen;
    }

    return args;
}

// 将vector<string>转换为char*数组，供main函数使用
static std::unique_ptr<char*[]> ConvertToArgv(const std::vector<std::string>& args)
{
    if (args.empty()) {
        return nullptr;
    }

    auto argv = std::make_unique<char*[]>(args.size() + 1); // +1 for nullptr terminator

    for (size_t i = 0; i < args.size(); i++) {
        argv[i] = const_cast<char*>(args[i].c_str());
    }
    argv[args.size()] = nullptr; // nullptr终止

    return argv;
}

// libFuzzer主入口
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size < 4) {
        return 0;
    }

    std::vector<std::string> tmpArgs = ExtractCliArgs(data, size);
    if (tmpArgs.empty()) {
        return 0;
    }

    // 至少要有 "程序名 + 命令" 两个参数，否则不跑
    if (tmpArgs.size() < 2) {
        return 0;
    }

    // 确保 argv[0] 是程序名
    if (tmpArgs[0].empty() || tmpArgs[0].find("virtrust") == std::string::npos) {
        tmpArgs[0] = "virtrust-sh";
    }

    // 把内容 move 到全局 g_args 中，转移 buffer 所有权
    g_args.clear();
    g_args.reserve(tmpArgs.size());
    for (auto &s : tmpArgs) {
        g_args.push_back(std::move(s));
    }

    // 构造全局 argv 指针数组
    g_argv.clear();
    g_argv.reserve(g_args.size() + 1);
    for (auto &s : g_args) {
        // c_str() 在 string 生命周期内绝不会是 nullptr
        g_argv.push_back(const_cast<char*>(s.c_str()));
    }
    g_argv.push_back(nullptr); // sentinel

    int argc = static_cast<int>(g_args.size());
    if (argc <= 0) {
        return 0;
    }

    // **防御性检查：argv[0..argc-1] 必须都是非空指针**
    for (int i = 0; i < argc; ++i) {
        if (g_argv[i] == nullptr) {
            return 0;  // 这一轮输入直接丢弃
        }
    }
    // 可选：确保 argv[argc] 为 nullptr
    g_argv[argc] = nullptr;

    // reset getopt 全局状态
#ifdef __GLIBC__
    optind = 0;
    optopt = 0;
#else
    optind = 1;
#endif
    opterr = 0;
    optarg = nullptr;

    (void)FuzzVirtrustCliMain(argc, g_argv.data());
    return 0;
}
