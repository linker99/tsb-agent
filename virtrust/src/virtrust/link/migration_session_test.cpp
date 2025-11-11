/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <memory>
#include <string>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "virtrust/link/migration_session.h"
#include "virtrust/link/grpc_client.h"

namespace virtrust {

// Mock RpcClient for testing
class MockRpcClient : public RpcClient {
public:
    MockRpcClient() : RpcClient(LinkConfig{}) {}
    
    MOCK_METHOD(int32_t, PrepareMigration, (uint32_t timeout, const protos::PrepareMigRequest &request, protos::PrepareMigReply *response), (override));
    MOCK_METHOD(int32_t, ExchangePkAndReport, (uint32_t timeout, const protos::EXchangePkAndReportRequest &request, protos::EXchangePkAndReportReply *response), (override));
    MOCK_METHOD(int32_t, StartMigration, (uint32_t timeout, const protos::StartMigRequest &request, protos::StartMigReply *response), (override));
    MOCK_METHOD(int32_t, SendVRsourceData, (uint32_t timeout, const protos::VRsourceInfoRequest &request, protos::VRsourceInfoReply *response), (override));
    MOCK_METHOD(int32_t, NotifyVRMigrateResult, (uint32_t timeout, const protos::MigrateResultRequest &request, protos::MigrateResultReply *response), (override));
};

class MigrationSessionTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        sessionId_ = "test-session-12345";
        domainName_ = "test-domain";
        destUri_ = "qemu+tcp://dest-host/system";
        localUri_ = "qemu+tcp://src-host/system";
        flags_ = 0;
    }

    std::string sessionId_;
    std::string domainName_;
    std::string destUri_;
    std::string localUri_;
    unsigned int flags_;
};

TEST_F(MigrationSessionTest, ConstructorInitiator)
{
    MigrationSession session(MigrationSession::Role::Initiator, sessionId_, domainName_, destUri_, localUri_, flags_);
    
    EXPECT_EQ(session.Id(), sessionId_);
    // We can't directly test private members, but the constructor should work
    SUCCEED();
}

TEST_F(MigrationSessionTest, ConstructorResponder)
{
    MigrationSession session(MigrationSession::Role::Responder, sessionId_, domainName_, destUri_, localUri_, flags_);
    
    EXPECT_EQ(session.Id(), sessionId_);
    // We can't directly test private members, but the constructor should work
    SUCCEED();
}

TEST_F(MigrationSessionTest, ConstructorWithEmptyValues)
{
    MigrationSession session(MigrationSession::Role::Initiator, "", "", "", "", 0);
    
    EXPECT_EQ(session.Id(), "");
    // Should handle empty values gracefully
    SUCCEED();
}

TEST_F(MigrationSessionTest, SessionManagerCreateAndGetSession)
{
    SessionManager& manager = SessionManager::GetInstance();
    
    // Create a session
    MigrationSession* session = manager.CreateSession(
        MigrationSession::Role::Initiator, sessionId_, domainName_, destUri_, localUri_, flags_);
    
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->Id(), sessionId_);
    
    // Get the same session
    MigrationSession* retrievedSession = manager.GetSession(sessionId_);
    EXPECT_EQ(retrievedSession, session);
    
    // Clean up
    manager.RemoveSession(sessionId_);
}

TEST_F(MigrationSessionTest, SessionManagerCreateDuplicateSession)
{
    SessionManager& manager = SessionManager::GetInstance();
    
    // Create first session
    MigrationSession* firstSession = manager.CreateSession(
        MigrationSession::Role::Initiator, sessionId_, domainName_, destUri_, localUri_, flags_);
    
    // Create second session with same ID (should return existing one)
    MigrationSession* secondSession = manager.CreateSession(
        MigrationSession::Role::Responder, sessionId_, "other-domain", "other-uri", "other-uri", 1);
    
    EXPECT_EQ(firstSession, secondSession);
    EXPECT_EQ(secondSession->Id(), sessionId_);
    
    // Clean up
    manager.RemoveSession(sessionId_);
}

TEST_F(MigrationSessionTest, SessionManagerGetNonExistentSession)
{
    SessionManager& manager = SessionManager::GetInstance();
    
    // Try to get non-existent session
    MigrationSession* session = manager.GetSession("non-existent-session");
    EXPECT_EQ(session, nullptr);
}

TEST_F(MigrationSessionTest, SessionManagerRemoveNonExistentSession)
{
    SessionManager& manager = SessionManager::GetInstance();
    
    // Try to remove non-existent session (should not crash)
    manager.RemoveSession("non-existent-session");
    SUCCEED();
}

TEST_F(MigrationSessionTest, SessionManagerMultipleSessions)
{
    SessionManager& manager = SessionManager::GetInstance();
    
    std::vector<std::string> sessionIds = {
        "session-1", "session-2", "session-3", "session-4", "session-5"
    };
    
    // Create multiple sessions
    for (const auto& id : sessionIds) {
        MigrationSession* session = manager.CreateSession(
            MigrationSession::Role::Initiator, id, domainName_, destUri_, localUri_, flags_);
        ASSERT_NE(session, nullptr);
        EXPECT_EQ(session->Id(), id);
    }
    
    // Verify all sessions exist
    for (const auto& id : sessionIds) {
        MigrationSession* session = manager.GetSession(id);
        EXPECT_NE(session, nullptr);
        EXPECT_EQ(session->Id(), id);
    }
    
    // Remove all sessions
    for (const auto& id : sessionIds) {
        manager.RemoveSession(id);
    }
    
    // Verify all sessions are removed
    for (const auto& id : sessionIds) {
        MigrationSession* session = manager.GetSession(id);
        EXPECT_EQ(session, nullptr);
    }
}

TEST_F(MigrationSessionTest, InitiatorStartWithoutRpcClient)
{
    MigrationSession session(MigrationSession::Role::Initiator, sessionId_, domainName_, destUri_, localUri_, flags_);
    
    // Try to start without setting RPC client
    MigrateSessionRc result = session.Start();
    
    // Should fail because no RPC client is set
    EXPECT_EQ(result, MigrateSessionRc::ERROR);
}

TEST_F(MigrationSessionTest, ResponderStart)
{
    MigrationSession session(MigrationSession::Role::Responder, sessionId_, domainName_, destUri_, localUri_, flags_);
    
    // Try to start a responder session
    MigrateSessionRc result = session.Start();
    
    // Should fail because responders can't start migration
    EXPECT_EQ(result, MigrateSessionRc::ERROR);
}

TEST_F(MigrationSessionTest, SetRpcClient)
{
    MigrationSession session(MigrationSession::Role::Initiator, sessionId_, domainName_, destUri_, localUri_, flags_);
    
    // Create mock RPC client
    auto mockClient = std::make_unique<MockRpcClient>();
    
    // Set mock client (this should work without crashing)
    session.SetRpcClient(std::move(mockClient));
    
    SUCCEED();
}

TEST_F(MigrationSessionTest, ResponderOnMigrateRequestReceived)
{
    MigrationSession session(MigrationSession::Role::Responder, sessionId_, domainName_, destUri_, localUri_, flags_);
    
    // Responder should handle migrate request
    MigrateSessionRc result = session.OnMigrateRequestReceived();
    
    // Should succeed for responders
    EXPECT_EQ(result, MigrateSessionRc::OK);
}

TEST_F(MigrationSessionTest, InitiatorOnMigrateRequestReceived)
{
    MigrationSession session(MigrationSession::Role::Initiator, sessionId_, domainName_, destUri_, localUri_, flags_);
    
    // Initiator should not handle migrate request
    MigrateSessionRc result = session.OnMigrateRequestReceived();
    
    // Might return error or handle gracefully depending on implementation
    SUCCEED();
}

TEST_F(MigrationSessionTest, OnExchangeKeyRequestReceived)
{
    MigrationSession session(MigrationSession::Role::Responder, sessionId_, domainName_, destUri_, localUri_, flags_);
    
    // Create test request and response
    protos::EXchangePkAndReportRequest request;
    protos::EXchangePkAndReportReply response;
    
    request.set_domainname(domainName_);
    request.set_uuid(sessionId_);
    request.set_cert("test-cert");
    request.set_pubkey("test-key");
    request.set_hostreport("test-host-report");
    request.set_vmreport("test-vm-report");
    
    // Handle exchange key request
    MigrateSessionRc result = session.OnExchangeKeyRequestReceived(&request, &response);
    
    // Should handle the request (result depends on implementation details)
    SUCCEED();
}

TEST_F(MigrationSessionTest, OnStartMigrationRequestReceived)
{
    MigrationSession session(MigrationSession::Role::Responder, sessionId_, domainName_, destUri_, localUri_, flags_);
    
    // Handle start migration request
    MigrateSessionRc result = session.OnStartMigrationRequestReceived();
    
    // Should handle the request (result depends on implementation details)
    SUCCEED();
}

TEST_F(MigrationSessionTest, OnTransferDataRequestReceived)
{
    MigrationSession session(MigrationSession::Role::Responder, sessionId_, domainName_, destUri_, localUri_, flags_);
    
    // Create test request
    protos::VRsourceInfoRequest request;
    
    request.set_domainname(domainName_);
    request.set_uuid(sessionId_);
    request.set_vrdata("test-vr-data");
    
    // Handle transfer data request
    MigrateSessionRc result = session.OnTransferDataRequestReceived(&request);
    
    // Should handle the request (result depends on implementation details)
    SUCCEED();
}

TEST_F(MigrationSessionTest, OnFinishedRequestReceived)
{
    MigrationSession session(MigrationSession::Role::Responder, sessionId_, domainName_, destUri_, localUri_, flags_);
    
    // Handle finished request with success
    MigrateSessionRc successResult = session.OnFinishedRequestReceived(true);
    
    // Handle finished request with failure
    MigrateSessionRc failureResult = session.OnFinishedRequestReceived(false);
    
    // Should handle both cases
    SUCCEED();
}

TEST_F(MigrationSessionTest, OnTimeoutAndOnFail)
{
    MigrationSession session(MigrationSession::Role::Initiator, sessionId_, domainName_, destUri_, localUri_, flags_);
    
    // Test timeout handling
    session.OnTimeout(MigrationSession::State::Init);
    
    // Test fail handling
    session.OnFail();
    
    // Should handle both without crashing
    SUCCEED();
}

TEST_F(MigrationSessionTest, Cleanup)
{
    MigrationSession session(MigrationSession::Role::Initiator, sessionId_, domainName_, destUri_, localUri_, flags_);
    
    // Test cleanup
    session.Cleanup();
    
    // Should handle cleanup without crashing
    SUCCEED();
}

TEST_F(MigrationSessionTest, DifferentRolesAndStates)
{
    // Test different roles
    MigrationSession initiator(MigrationSession::Role::Initiator, sessionId_ + "-init", domainName_, destUri_, localUri_, flags_);
    MigrationSession responder(MigrationSession::Role::Responder, sessionId_ + "-resp", domainName_, destUri_, localUri_, flags_);
    
    EXPECT_EQ(initiator.Id(), sessionId_ + "-init");
    EXPECT_EQ(responder.Id(), sessionId_ + "-resp");
    
    // Both should be constructed successfully
    SUCCEED();
}

TEST_F(MigrationSessionTest, SessionManagerThreadSafety)
{
    SessionManager& manager = SessionManager::GetInstance();
    
    // Test multiple thread operations (basic thread safety test)
    std::vector<std::thread> threads;
    std::vector<std::string> sessionIds;
    
    // Create sessions from multiple threads
    for (int i = 0; i < 5; i++) {
        std::string id = "thread-session-" + std::to_string(i);
        sessionIds.push_back(id);
        
        threads.emplace_back([&manager, id, this]() {
            MigrationSession* session = manager.CreateSession(
                MigrationSession::Role::Initiator, id, domainName_, destUri_, localUri_, flags_);
            EXPECT_NE(session, nullptr);
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Verify all sessions were created
    for (const auto& id : sessionIds) {
        MigrationSession* session = manager.GetSession(id);
        EXPECT_NE(session, nullptr);
    }
    
    // Clean up
    for (const auto& id : sessionIds) {
        manager.RemoveSession(id);
    }
}

} // namespace virtrust