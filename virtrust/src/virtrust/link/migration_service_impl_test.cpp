/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <memory>

#include "gtest/gtest.h"

#include "virtrust/link/migration_service_impl.h"
#include "virtrust/link/migration_session.h"

namespace virtrust {

class MigrationServiceImplTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        service_ = std::make_unique<MigrationServiceImpl>();
        
        testUuid_ = "test-uuid-12345";
        testDomainName_ = "test-domain";
        testDestUri_ = "qemu+tcp://192.168.1.100/system";
        testLocalUri_ = "qemu+tcp://192.168.1.50/system";
        testFlags_ = 0;
    }

    void TearDown() override
    {
        // Clean up any sessions created during tests
        SessionManager::GetInstance().RemoveSession(testUuid_);
    }

    std::unique_ptr<MigrationServiceImpl> service_;
    std::string testUuid_;
    std::string testDomainName_;
    std::string testDestUri_;
    std::string testLocalUri_;
    unsigned int testFlags_;
};

TEST_F(MigrationServiceImplTest, Constructor)
{
    // Test that MigrationServiceImpl can be constructed
    ASSERT_NE(service_, nullptr);
    SUCCEED();
}

TEST_F(MigrationServiceImplTest, PrepareMigrationNewSession)
{
    // Create request
    protos::PrepareMigRequest request;
    protos::PrepareMigReply response;
    
    request.set_uuid(testUuid_);
    request.set_domainname(testDomainName_);
    request.set_desturi(testDestUri_);
    request.set_localuri(testLocalUri_);
    request.set_flags(testFlags_);
    
    // Call PrepareMigration
    grpc::Status status = service_->PrepareMigration(nullptr, &request, &response);
    
    // Should succeed
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(response.result(), 0);
    
    // Session should be created
    MigrationSession* session = SessionManager::GetInstance().GetSession(testUuid_);
    EXPECT_NE(session, nullptr);
    EXPECT_EQ(session->Id(), testUuid_);
}

TEST_F(MigrationServiceImplTest, PrepareMigrationDuplicateSession)
{
    // Create first request
    protos::PrepareMigRequest request1;
    protos::PrepareMigReply response1;
    
    request1.set_uuid(testUuid_);
    request1.set_domainname(testDomainName_);
    request1.set_desturi(testDestUri_);
    request1.set_localuri(testLocalUri_);
    request1.set_flags(testFlags_);
    
    // Call PrepareMigration first time
    grpc::Status status1 = service_->PrepareMigration(nullptr, &request1, &response1);
    EXPECT_TRUE(status1.ok());
    EXPECT_EQ(response1.result(), 0);
    
    // Create second request with same UUID
    protos::PrepareMigRequest request2;
    protos::PrepareMigReply response2;
    
    request2.set_uuid(testUuid_);
    request2.set_domainname(testDomainName_);
    request2.set_desturi(testDestUri_);
    request2.set_localuri(testLocalUri_);
    request2.set_flags(testFlags_);
    
    // Call PrepareMigration second time (should fail due to duplicate)
    grpc::Status status2 = service_->PrepareMigration(nullptr, &request2, &response2);
    EXPECT_TRUE(status2.ok());
    EXPECT_EQ(response2.result(), 1);
}

TEST_F(MigrationServiceImplTest, PrepareMigrationWithEmptyUuid)
{
    protos::PrepareMigRequest request;
    protos::PrepareMigReply response;
    
    // Set empty UUID
    request.set_uuid("");
    request.set_domainname(testDomainName_);
    request.set_desturi(testDestUri_);
    request.set_localuri(testLocalUri_);
    request.set_flags(testFlags_);
    
    // Call PrepareMigration
    grpc::Status status = service_->PrepareMigration(nullptr, &request, &response);
    
    // Should handle empty UUID gracefully
    EXPECT_TRUE(status.ok());
}

TEST_F(MigrationServiceImplTest, PrepareMigrationWithEmptyDomainName)
{
    protos::PrepareMigRequest request;
    protos::PrepareMigReply response;
    
    request.set_uuid(testUuid_);
    request.set_domainname("");
    request.set_desturi(testDestUri_);
    request.set_localuri(testLocalUri_);
    request.set_flags(testFlags_);
    
    // Call PrepareMigration
    grpc::Status status = service_->PrepareMigration(nullptr, &request, &response);
    
    // Should handle empty domain name gracefully
    EXPECT_TRUE(status.ok());
}

TEST_F(MigrationServiceImplTest, ExchangePkAndReportWithValidSession)
{
    // First create a session
    protos::PrepareMigRequest prepareRequest;
    protos::PrepareMigReply prepareResponse;
    
    prepareRequest.set_uuid(testUuid_);
    prepareRequest.set_domainname(testDomainName_);
    prepareRequest.set_desturi(testDestUri_);
    prepareRequest.set_localuri(testLocalUri_);
    prepareRequest.set_flags(testFlags_);
    
    grpc::Status prepareStatus = service_->PrepareMigration(nullptr, &prepareRequest, &prepareResponse);
    EXPECT_TRUE(prepareStatus.ok());
    EXPECT_EQ(prepareResponse.result(), 0);
    
    // Now test ExchangePkAndReport
    protos::EXchangePkAndReportRequest request;
    protos::EXchangePkAndReportReply response;
    
    request.set_uuid(testUuid_);
    request.set_domainname(testDomainName_);
    request.set_cert("test-certificate-pem");
    request.set_pubkey("test-public-key");
    request.set_hostreport("test-host-report-data");
    request.set_vmreport("test-vm-report-data");
    
    grpc::Status status = service_->ExchangePkAndReport(nullptr, &request, &response);
    
    // Should handle the request
    EXPECT_TRUE(status.ok());
}

TEST_F(MigrationServiceImplTest, ExchangePkAndReportWithoutSession)
{
    protos::EXchangePkAndReportRequest request;
    protos::EXchangePkAndReportReply response;
    
    request.set_uuid("non-existent-uuid");
    request.set_domainname(testDomainName_);
    request.set_cert("test-certificate-pem");
    request.set_pubkey("test-public-key");
    request.set_hostreport("test-host-report-data");
    request.set_vmreport("test-vm-report-data");
    
    grpc::Status status = service_->ExchangePkAndReport(nullptr, &request, &response);
    
    // Should return error since session doesn't exist
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(response.result(), 1);
}

TEST_F(MigrationServiceImplTest, StartMigrationWithValidSession)
{
    // First create a session
    protos::PrepareMigRequest prepareRequest;
    protos::PrepareMigReply prepareResponse;
    
    prepareRequest.set_uuid(testUuid_);
    prepareRequest.set_domainname(testDomainName_);
    prepareRequest.set_desturi(testDestUri_);
    prepareRequest.set_localuri(testLocalUri_);
    prepareRequest.set_flags(testFlags_);
    
    grpc::Status prepareStatus = service_->PrepareMigration(nullptr, &prepareRequest, &prepareResponse);
    EXPECT_TRUE(prepareStatus.ok());
    EXPECT_EQ(prepareResponse.result(), 0);
    
    // Now test StartMigration
    protos::StartMigRequest request;
    protos::StartMigReply response;
    
    request.set_uuid(testUuid_);
    request.set_domainname(testDomainName_);
    
    grpc::Status status = service_->StartMigration(nullptr, &request, &response);
    
    // Should handle the request
    EXPECT_TRUE(status.ok());
}

TEST_F(MigrationServiceImplTest, StartMigrationWithoutSession)
{
    protos::StartMigRequest request;
    protos::StartMigReply response;
    
    request.set_uuid("non-existent-uuid");
    request.set_domainname(testDomainName_);
    
    grpc::Status status = service_->StartMigration(nullptr, &request, &response);
    
    // Should return error since session doesn't exist
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(response.result(), 1);
}

TEST_F(MigrationServiceImplTest, SendVRsourceDataWithValidSession)
{
    // First create a session
    protos::PrepareMigRequest prepareRequest;
    protos::PrepareMigReply prepareResponse;
    
    prepareRequest.set_uuid(testUuid_);
    prepareRequest.set_domainname(testDomainName_);
    prepareRequest.set_desturi(testDestUri_);
    prepareRequest.set_localuri(testLocalUri_);
    prepareRequest.set_flags(testFlags_);
    
    grpc::Status prepareStatus = service_->PrepareMigration(nullptr, &prepareRequest, &prepareResponse);
    EXPECT_TRUE(prepareStatus.ok());
    EXPECT_EQ(prepareResponse.result(), 0);
    
    // Now test SendVRsourceData
    protos::VRsourceInfoRequest request;
    protos::VRsourceInfoReply response;
    
    request.set_uuid(testUuid_);
    request.set_domainname(testDomainName_);
    request.set_vrdata("test-virtual-resource-data");
    
    grpc::Status status = service_->SendVRsourceData(nullptr, &request, &response);
    
    // Should handle the request
    EXPECT_TRUE(status.ok());
}

TEST_F(MigrationServiceImplTest, SendVRsourceDataWithoutSession)
{
    protos::VRsourceInfoRequest request;
    protos::VRsourceInfoReply response;
    
    request.set_uuid("non-existent-uuid");
    request.set_domainname(testDomainName_);
    request.set_vrdata("test-virtual-resource-data");
    
    grpc::Status status = service_->SendVRsourceData(nullptr, &request, &response);
    
    // Should return error since session doesn't exist
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(response.result(), 1);
}

TEST_F(MigrationServiceImplTest, NotifyVRMigrateResultWithValidSession)
{
    // First create a session
    protos::PrepareMigRequest prepareRequest;
    protos::PrepareMigReply prepareResponse;
    
    prepareRequest.set_uuid(testUuid_);
    prepareRequest.set_domainname(testDomainName_);
    prepareRequest.set_desturi(testDestUri_);
    prepareRequest.set_localuri(testLocalUri_);
    prepareRequest.set_flags(testFlags_);
    
    grpc::Status prepareStatus = service_->PrepareMigration(nullptr, &prepareRequest, &prepareResponse);
    EXPECT_TRUE(prepareStatus.ok());
    EXPECT_EQ(prepareResponse.result(), 0);
    
    // Now test NotifyVRMigrateResult
    protos::MigrateResultRequest request;
    protos::MigrateResultReply response;
    
    request.set_uuid(testUuid_);
    request.set_domainname(testDomainName_);
    request.set_success(true);
    request.set_message("Migration completed successfully");
    
    grpc::Status status = service_->NotifyVRMigrateResult(nullptr, &request, &response);
    
    // Should handle the request
    EXPECT_TRUE(status.ok());
}

TEST_F(MigrationServiceImplTest, NotifyVRMigrateResultWithoutSession)
{
    protos::MigrateResultRequest request;
    protos::MigrateResultReply response;
    
    request.set_uuid("non-existent-uuid");
    request.set_domainname(testDomainName_);
    request.set_success(false);
    request.set_message("Migration failed");
    
    grpc::Status status = service_->NotifyVRMigrateResult(nullptr, &request, &response);
    
    // Should return error since session doesn't exist
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(response.result(), 1);
}

TEST_F(MigrationServiceImplTest, DomainMigrateBasic)
{
    protos::DomainMigraterRequest request;
    protos::DomainMigraterReply response;
    
    request.set_domainname(testDomainName_);
    request.set_uuid(testUuid_);
    request.set_desturi(testDestUri_);
    request.set_localuri(testLocalUri_);
    request.set_flags(testFlags_);
    
    grpc::Status status = service_->DomainMigrate(nullptr, &request, &response);
    
    // Should handle the request (implementation may create a session)
    EXPECT_TRUE(status.ok());
}

TEST_F(MigrationServiceImplTest, DomainMigrateWithEmptyRequest)
{
    protos::DomainMigraterRequest request;
    protos::DomainMigraterReply response;
    
    // Don't set any fields
    grpc::Status status = service_->DomainMigrate(nullptr, &request, &response);
    
    // Should handle empty request gracefully
    EXPECT_TRUE(status.ok());
}

TEST_F(MigrationServiceImplTest, MultipleSessions)
{
    std::vector<std::string> uuids = {"uuid-1", "uuid-2", "uuid-3"};
    
    // Create multiple sessions
    for (const auto& uuid : uuids) {
        protos::PrepareMigRequest request;
        protos::PrepareMigReply response;
        
        request.set_uuid(uuid);
        request.set_domainname("domain-" + uuid);
        request.set_desturi(testDestUri_);
        request.set_localuri(testLocalUri_);
        request.set_flags(testFlags_);
        
        grpc::Status status = service_->PrepareMigration(nullptr, &request, &response);
        EXPECT_TRUE(status.ok());
        EXPECT_EQ(response.result(), 0);
        
        // Verify session exists
        MigrationSession* session = SessionManager::GetInstance().GetSession(uuid);
        EXPECT_NE(session, nullptr);
        EXPECT_EQ(session->Id(), uuid);
    }
    
    // Clean up
    for (const auto& uuid : uuids) {
        SessionManager::GetInstance().RemoveSession(uuid);
    }
}

TEST_F(MigrationServiceImplTest, SessionLifecycle)
{
    // Test complete session lifecycle
    std::string sessionId = "lifecycle-test";
    
    // 1. PrepareMigration
    protos::PrepareMigRequest prepareRequest;
    protos::PrepareMigReply prepareResponse;
    
    prepareRequest.set_uuid(sessionId);
    prepareRequest.set_domainname(testDomainName_);
    prepareRequest.set_desturi(testDestUri_);
    prepareRequest.set_localuri(testLocalUri_);
    prepareRequest.set_flags(testFlags_);
    
    grpc::Status prepareStatus = service_->PrepareMigration(nullptr, &prepareRequest, &prepareResponse);
    EXPECT_TRUE(prepareStatus.ok());
    EXPECT_EQ(prepareResponse.result(), 0);
    
    // 2. ExchangePkAndReport
    protos::EXchangePkAndReportRequest exchangeRequest;
    protos::EXchangePkAndReportReply exchangeResponse;
    
    exchangeRequest.set_uuid(sessionId);
    exchangeRequest.set_domainname(testDomainName_);
    exchangeRequest.set_cert("test-cert");
    exchangeRequest.set_pubkey("test-key");
    exchangeRequest.set_hostreport("test-host-report");
    exchangeRequest.set_vmreport("test-vm-report");
    
    grpc::Status exchangeStatus = service_->ExchangePkAndReport(nullptr, &exchangeRequest, &exchangeResponse);
    EXPECT_TRUE(exchangeStatus.ok());
    
    // 3. StartMigration
    protos::StartMigRequest startRequest;
    protos::StartMigReply startResponse;
    
    startRequest.set_uuid(sessionId);
    startRequest.set_domainname(testDomainName_);
    
    grpc::Status startStatus = service_->StartMigration(nullptr, &startRequest, &startResponse);
    EXPECT_TRUE(startStatus.ok());
    
    // 4. NotifyVRMigrateResult
    protos::MigrateResultRequest notifyRequest;
    protos::MigrateResultReply notifyResponse;
    
    notifyRequest.set_uuid(sessionId);
    notifyRequest.set_domainname(testDomainName_);
    notifyRequest.set_success(true);
    notifyRequest.set_message("Test completed");
    
    grpc::Status notifyStatus = service_->NotifyVRMigrateResult(nullptr, &notifyRequest, &notifyResponse);
    EXPECT_TRUE(notifyStatus.ok());
    
    // Clean up
    SessionManager::GetInstance().RemoveSession(sessionId);
}

} // namespace virtrust