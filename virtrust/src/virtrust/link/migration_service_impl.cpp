/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "migration_service_impl.h"

#include <getopt.h>
#include <unistd.h>

#include <csignal>
#include <iostream>
#include <thread>

#include "grpc_client.h"

#include "virtrust/base/logger.h"
#include "virtrust/link/defines.h"

namespace virtrust {
grpc::Status MigrationServiceImpl::PrepareMigration(grpc::ServerContext *context,
                                                    const protos::PrepareMigRequest *request,
                                                    protos::PrepareMigReply *response)
{
    return grpc::Status::OK;
}

// 2: 交换公钥
grpc::Status MigrationServiceImpl::ExchangePkAndReport(grpc::ServerContext *context,
                                                       const protos::EXchangePkAndReportRequest *request,
                                                       protos::EXchangePkAndReportReply *response)
{
    return grpc::Status::OK;
}

// 3: 开始迁移
grpc::Status MigrationServiceImpl::StartMigration(grpc::ServerContext *context, const protos::StartMigRequest *request,
                                                  protos::StartMigReply *response)
{
    return grpc::Status::OK;
}

// 4：迁移虚机密码资源
grpc::Status MigrationServiceImpl::SendVRsourceData(grpc::ServerContext *context,
                                                    const protos::VRsourceInfoRequest *request,
                                                    protos::VRsourceInfoReply *response)
{
    return grpc::Status::OK;
}

// 5: 通知迁移结果
grpc::Status MigrationServiceImpl::NotifyVRMigrateResult(grpc::ServerContext *context,
                                                         const protos::MigrateResultRequest *request,
                                                         protos::MigrateResultReply *response)
{
    return grpc::Status::OK;
}

// 6: 发起迁移任务, virsh-sh主动这个方法
grpc::Status MigrationServiceImpl::DomainMigrate(grpc::ServerContext *context,
                                                 const protos::DomainMigraterRequest *request,
                                                 protos::DomainMigraterReply *response)
{
    fmt::print("domain: {}\n", request->domainname());
    LinkConfig config;
    RpcClient client(config);

    uint32_t timeout = 5;
    protos::PrepareMigRequest prepareRequest;
    protos::PrepareMigReply prepareReply;
    client.PrepareMigration(timeout, prepareRequest, &prepareReply);
    return grpc::Status::OK;
}

} // namespace virtrust