/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#ifdef VIRTRUST_MOCK

#include "virtrust/link/mock/grpc_client_mock.h"


#include "virtrust/link/migration_session.h"
#include "virtrust/link/migration_service_impl.h"

namespace virtrust {

namespace {
constexpr std::string_view MOCK_DEST_UUID = "12345678-1234-1234-1234-123456789010";
}

int32_t UdsClientMock::DomainMigrate(const MigrationConfig &config)
{
    // Create source migration session
    auto &mgr = SessionManager::GetInstance();
    MigrationSession *session = mgr.CreateSession(
        MigrationSession::Role::Initiator,
        config.uuid,
        config.domainName,
        config.destUri,
        config.localUri,
        config.flags
    );
    if (!session) {
        return 1; // Failed to create session
    }
    session->SetRpcClient(std::make_unique<RpcClientMock>(config_));

    // Start the migration session - this will cover migration_session.cpp
    auto ret = session->Start();
    session->Cleanup();
    // destSession->Cleanup();
    return (ret == MigrateSessionRc::OK) ? 0 : 1;
}

int32_t RpcClientMock::PrepareMigration(uint32_t timeout, const protos::PrepareMigRequest &request,
                                        protos::PrepareMigReply *response)
{
    (void)timeout;
    (void)request;

    // Always succeed for stable unit testing - removed random failure logic

    MigrationServiceImpl serviceImpl;
    grpc::ServerContext context;
    protos::PrepareMigRequest mockRequest = request;
    mockRequest.set_uuid(std::string(MOCK_DEST_UUID));
    serviceImpl.PrepareMigration(&context, &mockRequest, response);

    // Mock successful preparation
    if (response != nullptr) {
        response->set_result(0); // Success
    }

    return 0; // Success
}

int32_t RpcClientMock::ExchangePkAndReport(uint32_t timeout, const protos::EXchangePkAndReportRequest &request,
                                           protos::EXchangePkAndReportReply *response)
{
    (void)timeout;

    if (response == nullptr) {
        return -1; // Error
    }

    // Always succeed for stable unit testing - removed random failure logic

    MigrationServiceImpl serviceImpl;
    grpc::ServerContext context;
    protos::EXchangePkAndReportRequest mockRequest = request;
    mockRequest.set_uuid(std::string(MOCK_DEST_UUID));
    serviceImpl.ExchangePkAndReport(&context, &mockRequest, response);

    // Mock response with generated data
    response->set_result(0); // Success
    response->set_domainname(request.domainname());
    response->set_uuid(request.uuid());

    // Generate mock certificate
    response->set_cert("mock-certificate-data");

    // Generate mock public key
    std::string mockPublicKey = GenerateMockPublicKey();
    response->set_publickey(mockPublicKey);

    // Generate mock trust reports
    *response->mutable_hostreport() = GenerateMockTrustReport();
    *response->mutable_vmreport() = GenerateMockTrustReport();

    // Generate mock TCM2 key
    std::string mockTcm2Key = GenerateMockTcm2Key();
    response->set_tcm2key(mockTcm2Key);

    return 0; // Success
}

int32_t RpcClientMock::StartMigration(uint32_t timeout, const protos::StartMigRequest &request,
                                      protos::StartMigReply *response)
{
    (void)timeout; (void)request;

    // Always succeed for stable unit testing - removed random failure logic

    MigrationServiceImpl serviceImpl;
    grpc::ServerContext context;
    protos::StartMigRequest mockRequest = request;
    mockRequest.set_uuid(std::string(MOCK_DEST_UUID));
    serviceImpl.StartMigration(&context, &mockRequest, response);

    // Mock successful start
    if (response != nullptr) {
        response->set_result(0); // Success
    }

    return 0; // Success
}

int32_t RpcClientMock::SendVRsourceData(uint32_t timeout, const protos::VRsourceInfoRequest &request,
                                        protos::VRsourceInfoReply *response)
{
    (void)timeout; (void)request;

    // Always succeed for stable unit testing - removed random failure logic

    MigrationServiceImpl serviceImpl;
    grpc::ServerContext context;
    protos::VRsourceInfoRequest mockRequest = request;
    mockRequest.set_uuid(std::string(MOCK_DEST_UUID));
    serviceImpl.SendVRsourceData(&context, &mockRequest, response);

    // Mock successful data transfer
    if (response != nullptr) {
        response->set_result(0); // Success
    }

    return 0; // Success
}

int32_t RpcClientMock::NotifyVRMigrateResult(uint32_t timeout, const protos::MigrateResultRequest &request,
                                             protos::MigrateResultReply *response)
{
    (void)timeout; (void)request;

    // Always succeed for stable unit testing - removed random failure logic

    MigrationServiceImpl serviceImpl;
    grpc::ServerContext context;
    protos::MigrateResultRequest mockRequest = request;
    mockRequest.set_uuid(std::string(MOCK_DEST_UUID));
    serviceImpl.NotifyVRMigrateResult(&context, &mockRequest, response);

    // Mock successful result notification
    if (response != nullptr) {
        response->set_result(0); // Success
    }

    return 0; // Success
}

protos::TrustReportNew RpcClientMock::GenerateMockTrustReport()
{
    protos::TrustReportNew report;

    // Generate mock trust report content
    protos::TrustReportContentNew* content = report.mutable_content();
    content->set_be_host_report_time(1640995200); // Mock timestamp
    content->set_be_host_startup_time(1640995100);
    content->set_be_eval(1); // Success
    content->set_be_host_ip(0xC0A80101); // 192.168.1.1

    // Set mock IDs (32 bytes each)
    const char* mockHostId = "mock-host-id-1234567890123456789012";
    const char* mockTpcmId = "mock-tpcm-id-1234567890123456789012";

    content->set_host_id(mockHostId, 32);
    content->set_tpcm_id(mockTpcmId, 32);

    // Set mock PCR values (32 bytes each)
    const char* mockPcr = "mock-pcr-value-1234567890123456789012";
    content->set_bios_pcr(mockPcr, 32);
    content->set_boot_loader_pcr(mockPcr, 32);
    content->set_kernel_pcr(mockPcr, 32);
    content->set_tsb_pcr(mockPcr, 32);
    content->set_boot_pcr(mockPcr, 32);

    // Set mock log hash
    content->set_log_hash(mockPcr, 32);

    // Set mock nonce
    content->set_be_nonce(1234567890);

    // Set mock global control policy
    protos::GlobalControlPolicy* policy = content->mutable_global_control_policy();
    policy->set_be_size(1024);
    policy->set_be_boot_measure_on(1);
    policy->set_be_program_measure_on(1);
    policy->set_be_dynamic_measure_on(1);
    policy->set_be_boot_control(1);
    policy->set_be_program_control(1);

    // Set mock append data
    const char* mockAppendData = "mock-append-data-for-trust-report-testing";
    report.set_append_data(mockAppendData);

    return report;
}

std::string RpcClientMock::GenerateMockPublicKey()
{
    // Mock 256-byte public key
    std::string mockKey;
    mockKey.resize(256);

    // Fill with predictable pattern for testing
    for (int i = 0; i < 256; ++i) {
        mockKey[i] = static_cast<char>(i % 256);
    }

    return mockKey;
}

std::string RpcClientMock::GenerateMockTcm2Key()
{
    // Mock 128-byte TCM2 key
    std::string mockKey;
    mockKey.resize(128);

    // Fill with predictable pattern for testing
    for (int i = 0; i < 128; ++i) {
        mockKey[i] = static_cast<char>((i + 128) % 256);
    }

    return mockKey;
}

} // namespace virtrust

#endif // VIRTRUST_MOCK