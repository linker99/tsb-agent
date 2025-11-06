/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>

#include <memory>
#include <thread>

#include "virtrust/link/defines.h"

#include "virtrust/link/proto/migrate.grpc.pb.h"

namespace virtrust {
class MigrationServiceImpl final : public protos::MigrationService::Service {
public:
    grpc::Status PrepareMigration(grpc::ServerContext *context, const protos::PrepareMigRequest *request,
                                  protos::PrepareMigReply *response) override;

    // 2: 交换公钥
    grpc::Status ExchangePkAndReport(grpc::ServerContext *context, const protos::EXchangePkAndReportRequest *request,
                                     protos::EXchangePkAndReportReply *response) override;

    // 3: 开始迁移
    grpc::Status StartMigration(grpc::ServerContext *context, const protos::StartMigRequest *request,
                                protos::StartMigReply *response) override;

    // 4：迁移虚机密码资源
    grpc::Status SendVRsourceData(grpc::ServerContext *context, const protos::VRsourceInfoRequest *request,
                                  protos::VRsourceInfoReply *response) override;

    // 5: 通知迁移结果
    grpc::Status NotifyVRMigrateResult(grpc::ServerContext *context, const protos::MigrateResultRequest *request,
                                       protos::MigrateResultReply *response) override;

    // 6: 发起迁移任务
    grpc::Status DomainMigrate(grpc::ServerContext *context, const protos::DomainMigraterRequest *request,
                               protos::DomainMigraterReply *response) override;
};
} // namespace virtrust