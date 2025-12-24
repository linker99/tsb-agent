/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include "virtrust/api/context.h"
#include "virtrust/api/defines.h"
#include "virtrust/api/domain.h"
#include "virtrust/dllib/libvirt.h"

namespace virtrust {

namespace {

// Helper function to create connection context (similar to fuzz_helper.h)
inline std::unique_ptr<ConnCtx> CreateConnCtx(const std::string &uri)
{
    auto conn = std::make_unique<ConnCtx>();
    if (!conn || !conn->SetUri(uri)) {
        return nullptr;
    }
    conn->Connect();
    if (conn->Get() == nullptr) {
        return nullptr;
    }
    return conn;
}

inline const std::unique_ptr<ConnCtx> &GetGlobalConn(const std::string &uri = "qemu:///system")
{
    static std::unique_ptr<ConnCtx> globalConn;

    if (!globalConn) {
        globalConn = CreateConnCtx(uri);
    }
    return globalConn;
}
}

// DomainCreate Test Cases
TEST(DomainTest, DomainCreate)
{
    // Test with null connection
    std::vector<std::string> args;
    VirtrustRc rc = DomainCreate(nullptr, args);
    EXPECT_EQ(rc, VirtrustRc::ERROR); // Should fail with null connection

    // Test with valid connection but empty args
    auto &conn = GetGlobalConn();
    args.clear();
    rc = DomainCreate(conn, args);
    EXPECT_EQ(rc, VirtrustRc::ERROR); // Should fail with empty args

    // Test with valid connection and proper args
    args = {"/usr/bin/virt-install", "--name", "test-vm", "--ram", "1024", "--import"};
    rc = DomainCreate(conn, args);
    // Note: Actual success depends on test environment, but function should not crash
    EXPECT_EQ(rc, VirtrustRc::ERROR);
}

// DomainDestroy Test Cases
TEST(DomainTest, DomainDestroy)
{
    // Test with null connection

    VirtrustRc rc = DomainDestroy(nullptr, "test-domain-1", DomainDestroyFlags::DOMAIN_DESTROY_NONE, false);
    EXPECT_EQ(rc, VirtrustRc::ERROR);

    auto &conn = GetGlobalConn();

    // Test with empty domain name
    rc = DomainDestroy(conn, "", DomainDestroyFlags::DOMAIN_DESTROY_NONE, false);
    EXPECT_EQ(VirtrustRc::ERROR, rc);

    // Test with valid domain name, VM state is shut up
    rc = DomainDestroy(conn, "test-domain-1", DomainDestroyFlags::DOMAIN_DESTROY_NONE, false);
    EXPECT_EQ(VirtrustRc::ERROR, rc); 

    // Test with isOnlyTsb=true, domainName should be valid uuid
    rc = DomainDestroy(conn, "12345678-1234-1234-1234-123456789001", DomainDestroyFlags::DOMAIN_DESTROY_NONE, true);
    EXPECT_EQ(VirtrustRc::ERROR, rc); 
}

TEST(DomainTest, DomainDestroyEdgeCases)
{
    auto &conn = GetGlobalConn();

    // Test with mock name when isOnlyTsb=false
    VirtrustRc rc = DomainDestroy(conn, "test-domain-1",
                                 DomainDestroyFlags::DOMAIN_DESTROY_NONE, false);
    EXPECT_EQ(VirtrustRc::ERROR, rc); 

    // Test shut up VM with isOnlyTsb=true and UUID
    rc = DomainDestroy(conn, "12345678-1234-1234-1234-123456789002",
                      DomainDestroyFlags::DOMAIN_DESTROY_NONE, true);
    EXPECT_EQ(VirtrustRc::ERROR, rc); 

    // Test running VM with isOnlyTsb=true and running domain UUID
    rc = DomainDestroy(conn, "12345678-1234-1234-1234-123456789003",
                      DomainDestroyFlags::DOMAIN_DESTROY_NONE, true);
    EXPECT_EQ(VirtrustRc::OK, rc); 

    // Test with another-shut-off-domain name when isOnlyTsb=false
    rc = DomainDestroy(conn, "another-shut-off-domain",
                      DomainDestroyFlags::DOMAIN_DESTROY_NONE, false);
    EXPECT_EQ(VirtrustRc::ERROR, rc); 

    // Test with isOnlyTsb=true using UUID from another-shut-off-domain
    rc = DomainDestroy(conn, "12345678-1234-1234-1234-123456789004",
                      DomainDestroyFlags::DOMAIN_DESTROY_NONE, true);
    EXPECT_EQ(VirtrustRc::ERROR, rc); 

    // Test with non-existent domain
    rc = DomainDestroy(conn, "non-existent-domain", DomainDestroyFlags::DOMAIN_DESTROY_NONE, false);
    EXPECT_EQ(VirtrustRc::ERROR, rc); 
}

// DomainMigrate Test Cases
TEST(DomainTest, DomainMigrate)
{
    auto &conn = GetGlobalConn();

    // Test with empty domain name
    VirtrustRc rc = DomainMigrate(conn, "", "qemu+tls://dest:16509/system", MIGRATE_UNDEFINE_SOURCE);
    EXPECT_EQ(VirtrustRc::ERROR, rc);

    // Test with empty destination URI
    rc = DomainMigrate(conn, "test-domain", "", MIGRATE_UNDEFINE_SOURCE);
    EXPECT_EQ(VirtrustRc::ERROR, rc);

    // Test with invalid flag
    rc = DomainMigrate(conn, "test-domain-1", "qemu+tls://dest:16509/system", 0);
    EXPECT_EQ(VirtrustRc::ERROR, rc); 

    // Test with running domain (should fail to migrate)
    rc = DomainMigrate(conn, "running-domain", "qemu+tls://dest:16509/system", MIGRATE_UNDEFINE_SOURCE);
    EXPECT_EQ(VirtrustRc::ERROR, rc);     
    
    // Test with valid domain name and valid flag
    rc = DomainMigrate(conn, "test-domain-2", "qemu+tls://dest:16509/system", MIGRATE_UNDEFINE_SOURCE);
    EXPECT_EQ(VirtrustRc::OK, rc);
}

// DomainStart Test Cases
TEST(DomainTest, DomainStart)
{
    auto &conn = GetGlobalConn();

    // Test with empty domain name
    VirtrustRc rc = DomainStart(conn, "", DOMAIN_START_NONE, false);
    EXPECT_EQ(VirtrustRc::ERROR, rc);

    // Test with valid domain name
    rc = DomainStart(conn, "test-domain-1", DOMAIN_START_NONE, false);
    EXPECT_EQ(VirtrustRc::ERROR, rc);

    // Test with isOnlyTsb=true
    rc = DomainStart(conn, "test-domain-2", DOMAIN_START_NONE, true);
    EXPECT_EQ(VirtrustRc::ERROR, rc); 
}

TEST(DomainTest, DomainStartEdgeCases)
{
    auto &conn = GetGlobalConn();

    // Test with UUID (mock domain)
    VirtrustRc rc = DomainStart(conn, "12345678-1234-1234-1234-123456789001",
                               DOMAIN_START_NONE, false);
    EXPECT_EQ(VirtrustRc::ERROR, rc); 

    // Test with isOnlyTsb=true and UUID (flags should be ignored)
    rc = DomainStart(conn, "12345678-1234-1234-1234-123456789002",
                    DOMAIN_START_NONE, true);
    EXPECT_EQ(VirtrustRc::OK, rc);

    // Test with non-existent domain
    rc = DomainStart(conn, "non-existent-domain", DOMAIN_START_NONE, false);
    EXPECT_EQ(VirtrustRc::ERROR, rc); 
}

// DomainUndefine Test Cases
TEST(DomainTest, DomainUndefine)
{
    auto &conn = GetGlobalConn();

    // Test with empty domain name
    VirtrustRc rc = DomainUndefine(conn, "", 0, false);
    EXPECT_EQ(VirtrustRc::ERROR, rc);

    // Test with valid domain name
    rc = DomainUndefine(conn, "test-domain-1", 0, false);
    EXPECT_EQ(VirtrustRc::OK, rc); 

    // Test with isOnlyTsb=true
    rc = DomainUndefine(conn, "test-domain-2", 0, true);
    EXPECT_EQ(VirtrustRc::ERROR, rc); 

    // Test with nvram flags
    rc = DomainUndefine(conn, "another-shut-off-domain", DOMAIN_UNDEFINE_NVRAM, false);
    EXPECT_EQ(VirtrustRc::OK, rc); 

    rc = DomainUndefine(conn, "test-domain-1", DOMAIN_UNDEFINE_KEEP_NVRAM, false);
    EXPECT_EQ(VirtrustRc::OK, rc); 
}

TEST(DomainTest, DomainUndefineEdgeCases)
{
    auto &conn = GetGlobalConn();

    // Test with UUID (mock domain)
    VirtrustRc rc = DomainUndefine(conn, "12345678-1234-1234-1234-123456789001", 0, false);
    EXPECT_EQ(VirtrustRc::ERROR, rc); 

    // Test with isOnlyTsb=true and UUID, ignore flag
    rc = DomainUndefine(conn, "12345678-1234-1234-1234-123456789002", 666, true);
    EXPECT_EQ(VirtrustRc::OK, rc);

    // Test with multiple nvram flags (should not be used together, but function should handle)
    rc = DomainUndefine(conn, "test-domain-1", DOMAIN_UNDEFINE_NVRAM , false);
    EXPECT_EQ(VirtrustRc::OK, rc);

    rc = DomainUndefine(conn, "test-domain-2", DOMAIN_UNDEFINE_KEEP_NVRAM , false);
    EXPECT_EQ(VirtrustRc::OK, rc);

    rc = DomainUndefine(conn, "test-domain-2", DOMAIN_UNDEFINE_NVRAM|DOMAIN_UNDEFINE_KEEP_NVRAM , false);
    EXPECT_EQ(VirtrustRc::ERROR, rc);
}

// DomainList Test Cases
TEST(DomainTest, DomainList)
{
    std::unordered_map<std::string, DomainInfo> domainInfos;

    // Test with null connection
    VirtrustRc rc = DomainList(nullptr, DomainListFlags::LIST_DOMAINS_ACTIVE, domainInfos, false);
    EXPECT_EQ(VirtrustRc::ERROR, rc);

    auto &conn = GetGlobalConn();

    // Test with LIST_DOMAINS_ACTIVE
    domainInfos.clear();
    rc = DomainList(conn, DomainListFlags::LIST_DOMAINS_ACTIVE, domainInfos, false);
    EXPECT_EQ(VirtrustRc::OK, rc); 

    // Test with LIST_DOMAINS_INACTIVE
    domainInfos.clear();
    rc = DomainList(conn, DomainListFlags::LIST_DOMAINS_INACTIVE, domainInfos, false);
    EXPECT_EQ(VirtrustRc::OK, rc); 

    // Test with both flags
    domainInfos.clear();
    rc = DomainList(conn, DomainListFlags::LIST_DOMAINS_ACTIVE | DomainListFlags::LIST_DOMAINS_INACTIVE,
                   domainInfos, false);
    EXPECT_EQ(VirtrustRc::OK, rc); 
}

TEST(DomainTest, DomainListDetailed)
{
    auto &conn = GetGlobalConn();
    std::unordered_map<std::string, DomainInfo> domainInfos;

    // Test with printErrToCli=true
    VirtrustRc rc = DomainList(conn, DomainListFlags::LIST_DOMAINS_ACTIVE, domainInfos, true);
    EXPECT_EQ(VirtrustRc::OK, rc); 

    // Verify DomainInfo structure if any domains are returned
    if (!domainInfos.empty()) {
        for (const auto& [name, info] : domainInfos) {
            EXPECT_EQ(false, name.empty());
            // Verify DomainInfo fields are accessible - just access them to ensure they exist
            unsigned char testState = info.state;
            unsigned long testMaxMem = info.maxMem;
            unsigned long testMemory = info.memory;
            unsigned short testNrVirtCpu = info.nrVirtCpu;
            unsigned long long testCpuTime = info.cpuTime;
            (void)testState; (void)testMaxMem; (void)testMemory; (void)testNrVirtCpu; (void)testCpuTime; // Suppress unused warnings

            // Check if domain name matches our mock domains
            bool isMockDomain = (name == "test-domain-1" || name == "test-domain-2" ||
                                name == "running-domain" || name == "another-shut-off-domain");
            if (isMockDomain) {
                // Verify mock domain data consistency
                EXPECT_TRUE(info.maxMem >= 512 * 1024);  // At least 512MB
                EXPECT_TRUE(info.maxMem <= 4096 * 1024); // At most 4GB
            }
        }
    }
}

TEST(DomainTest, DomainListEdgeCases)
{
    auto &conn = GetGlobalConn();
    std::unordered_map<std::string, DomainInfo> domainInfos;

    // Test with no flags
    VirtrustRc rc = DomainList(conn,  0, domainInfos, false);
    EXPECT_EQ(VirtrustRc::ERROR, rc);

    // List active vm
    rc = DomainList(conn,  LIST_DOMAINS_ACTIVE, domainInfos, false);
    EXPECT_EQ(VirtrustRc::OK, rc);

    // List inactive vm
    rc = DomainList(conn,  LIST_DOMAINS_INACTIVE, domainInfos, false);
    EXPECT_EQ(VirtrustRc::OK, rc);

    // List all vm
    rc = DomainList(conn,  LIST_DOMAINS_ACTIVE | LIST_DOMAINS_INACTIVE, domainInfos, false);
    EXPECT_EQ(VirtrustRc::OK, rc);
}

// ConnCtx Test Cases
TEST(DomainTest, ConnCtxBasicFunctionality)
{
    // Test ConnCtx construction
    auto &conn = GetGlobalConn();
    EXPECT_TRUE(conn->CheckOk());

    EXPECT_FALSE(conn->GetUri().empty());

    // Test SetUri with valid URIs
    EXPECT_EQ(true, conn->SetUri("qemu:///system"));
    EXPECT_EQ(conn->GetUri(), "qemu:///system");

    EXPECT_EQ(true, conn->SetUri("qemu:///session"));
    EXPECT_EQ(conn->GetUri(), "qemu:///session");
}

TEST(DomainTest, ConnCtxEdgeCases)
{
    auto &conn = GetGlobalConn();

    // Test with various URI formats
    std::vector<std::string> testUris = {
        "qemu+tls://host/system",
        "qemu+ssh://user@host/system",
        "qemu+tcp://host:16509/system",
        "xen:///",
        "test:///default"
    };

    for (const auto& uri : testUris) {
        EXPECT_EQ(true, conn->SetUri(uri)) << "Failed to set URI: " << uri;
        EXPECT_EQ(conn->GetUri(), uri);
    }

    // Test with empty URI
    EXPECT_EQ(true, conn->SetUri(""));
    EXPECT_EQ(conn->GetUri(), "");
}

// Constants and Flags Test Cases
TEST(DomainTest, ConstantsVerification)
{
    // Verify enum values are as expected
    EXPECT_EQ(0, static_cast<int>(VirtrustRc::OK));
    EXPECT_EQ(1, static_cast<int>(VirtrustRc::ERROR));
    EXPECT_EQ(2, static_cast<int>(VirtrustRc::CHECK_FAILED));
    EXPECT_EQ(3, static_cast<int>(VirtrustRc::INCONSISTENT_RESOURCE));

    EXPECT_EQ(1 << 0, DomainListFlags::LIST_DOMAINS_ACTIVE);
    EXPECT_EQ(1 << 1, DomainListFlags::LIST_DOMAINS_INACTIVE);

    EXPECT_EQ(0, DOMAIN_START_NONE);
    EXPECT_EQ(0, DomainDestroyFlags::DOMAIN_DESTROY_NONE);

    EXPECT_EQ(1 << 2, DOMAIN_UNDEFINE_NVRAM);
    EXPECT_EQ(1 << 3, DOMAIN_UNDEFINE_KEEP_NVRAM);

    EXPECT_EQ(1 << 4, DomainMigrateFlags::MIGRATE_UNDEFINE_SOURCE);
}

TEST(DomainTest, DefaultValues)
{
    // Verify default values
    EXPECT_EQ(VIRTRUST_DEFAULT_URI, "qemu:///session");
    EXPECT_EQ(UDS_PATH, "/tmp/grpc.sock");
}

} // namespace virtrust
