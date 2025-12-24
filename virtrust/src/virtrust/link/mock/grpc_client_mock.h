/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#ifdef VIRTRUST_MOCK

#include <cstdint>
#include <string>

#include "virtrust/link/defines.h"
#include "virtrust/link/proto/migrate.grpc.pb.h"

#include <securec.h>

namespace virtrust {

// Forward declarations
class MigrationSession;
class SessionManager;

// gRPC Client Mock implementation for fuzzing
class UdsClientMock {
public:
    ~UdsClientMock() = default;
    UdsClientMock(const UdsClientMock &) = delete;
    void operator=(const UdsClientMock &) = delete;

    // Constructor
    explicit UdsClientMock(LinkConfig config) : config_(config) {}

    // Mock DomainMigrate function - migration entry point
    int32_t DomainMigrate(const MigrationConfig &config);

private:
    LinkConfig config_;
};

// gRPC Client Mock implementation for fuzzing
class RpcClientMock {
public:
    ~RpcClientMock() = default;
    RpcClientMock(const RpcClientMock &) = delete;
    void operator=(const RpcClientMock &) = delete;

    // Constructor
    explicit RpcClientMock(LinkConfig config) : config_(config) {}

    // Mock the 5 migration phase RPC calls

    // 1: Prepare migration
    int32_t PrepareMigration(uint32_t timeout, const protos::PrepareMigRequest &request,
                             protos::PrepareMigReply *response);

    // 2: Exchange public keys
    int32_t ExchangePkAndReport(uint32_t timeout, const protos::EXchangePkAndReportRequest &request,
                                protos::EXchangePkAndReportReply *response);

    // 3: Start migration
    int32_t StartMigration(uint32_t timeout, const protos::StartMigRequest &request,
                           protos::StartMigReply *response);

    // 4: Transfer VM resource data
    int32_t SendVRsourceData(uint32_t timeout, const protos::VRsourceInfoRequest &request,
                             protos::VRsourceInfoReply *response);

    // 5: Notify migration result
    int32_t NotifyVRMigrateResult(uint32_t timeout, const protos::MigrateResultRequest &request,
                                  protos::MigrateResultReply *response);

private:
    LinkConfig config_;

    // Helper function to generate mock trust report
    protos::TrustReportNew GenerateMockTrustReport();

    // Helper function to generate mock public key
    std::string GenerateMockPublicKey();

    // Helper function to generate mock TCM2 key
    std::string GenerateMockTcm2Key();
};

} // namespace virtrust

#endif // VIRTRUST_MOCK