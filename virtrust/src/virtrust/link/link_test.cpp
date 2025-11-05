/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include <filesystem>
#include <future>

#include "gtest/gtest.h"
#include "spdlog/fmt/bundled/core.h"

#include "virtrust/link/link_client.h"
#include "virtrust/link/link_config_builder.h"
#include "virtrust/link/link_server.h"

namespace virtrust {

namespace {
constexpr std::string_view TEST_CA_CERT_FILENAME = "ca/cert.pem";
constexpr std::string_view TEST_SERVER_CERT_FILENAME = "server/cert.pem";
constexpr std::string_view TEST_SERVER_SK_FILENAME = "server/sk.pem";
constexpr std::string_view TEST_CLIENT_CERT_FILENAME = "client/cert.pem";
constexpr std::string_view TEST_CLIENT_SK_FILENAME = "client/sk.pem";

constexpr std::string_view TEST_ADDR = "127.0.0.1";
constexpr std::string_view TEST_ADDR_MASK = "127.0.0.0/128";
constexpr uint16_t TEST_SERVER_PORT = "10086";
constexpr uint16_t TEST_CLIENT_PORT = "10087";

inline std::filesystem::path GetTestDir()
{
    // GET the project root path (which is the directory)
    auto filePath = std::filesystem::path(__FILE__);
    return (filePath / ".." / ".." / ".." / ".." / "test").lexically_normal();
}

#define GET_PATH(ROLE, TYPE) (GetTestDir() / TEST_##ROLE##_##TYPE##_FILENAME).lexically_normal().string()

} // namespace

TEST(LinkTest, SimpleDemo)
{
    auto s = std::async([]() {
        LinkServer link(LinkConfigBuilder()
                            .caPath(GET_PATH(CA, CERT))
                            .certPath(GET_PATH(SERVER, CERT))
                            .skPath(GET_PATH(SERVER, SK))
                            .ip(std::string(TEST_ADDR))
                            .ipMask(std::string(TEST_ADDR_MASK))
                            .port(TEST_SERVER_PORT)
                            .Build());
        return link.Start();
    });
    auto c = std::async([]() {
        LinkClient link(LinkConfigBuilder()
                            .caPath(GET_PATH(CA, CERT))
                            .certPath(GET_PATH(CLIENT, CERT))
                            .skPath(GET_PATH(CLIENT, SK))
                            .ip(std::string(TEST_ADDR))
                            .ipMask(std::string(TEST_ADDR_MASK))
                            .port(TEST_CLIENT_PORT)
                            .Build());
        auto ret = link.Start();
        if (ret != LinkRc::OK) {
            return ret;
        };
        return link.Connect(TEST_ADDR, TEST_SERVER_PORT);
    });
    EXPECT_EQ(s.get(), LinkRc::OK);
    EXPECT_EQ(c.get(), LinkRc::OK);
}
} // namespace virtrust