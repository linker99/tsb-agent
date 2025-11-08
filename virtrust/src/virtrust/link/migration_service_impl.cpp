/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "virtrust/link/migration_service_impl.h"

#include <memory>
#include <thread>

#include "tsb_agent/tsb_agent.h"
#include "virtrust/base/logger.h"
#include "virtrust/link/defines.h"
#include "virtrust/link/grpc_client.h"
#include "virtrust/link/migration_session.h"

namespace virtrust {
grpc::Status MigrationServiceImpl::PrepareMigration(grpc::ServerContext *context,
                                                    const protos::PrepareMigRequest *request,
                                                    protos::PrepareMigReply *response)
{
    VIRTRUST_LOG_ERROR("|PrepareMigration|START||uuid:" + request->uuid() + "|domainName:" + request->domainname());

    auto &uuid = request->uuid();
    auto &mgr = SessionManager::GetInstance();

    // 已存在session，说明正在迁移
    if (mgr.GetSession(uuid) != nullptr) {
        VIRTRUST_LOG_ERROR("|PrepareMigration|END|returnF|uuid:" + uuid + "|Session already exists");
        response->set_result(1); // session already exists
        return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, "This VM is already migrating");
    }

    // 否则创建session
    MigrationSession *session = mgr.CreateSession(MigrationSession::Role::Responder, uuid, request->domainname(),
                                                  request->desturi(), request->localuri(), request->flags());
    MigrateSessionRc rc = session->OnMigrateRequestReceived();
    if (rc != MigrateSessionRc::OK) {
        return grpc::Status(grpc::StatusCode::ABORTED, "This VM is already migrating");
    }
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
    if (request == nullptr) {
        VIRTRUST_LOG_ERROR("|DomainMigrate|END|returnF|SendVRsourceData request is nullptr.");
        response->set_result(1);
        return grpc::Status::OK;
    }
    auto ret = MigrationImportVRootCipher(const_cast<char *>(request->data().c_str()),
                                          const_cast<char *>(request->uuid().c_str()));
    if (ret != 0) {
        VIRTRUST_LOG_ERROR("|DomainMigrate|END|returnF|MigrationImportVrootCipher failed.");
        response->set_result(1);
        return grpc::Status::OK;
    }
    response->set_result(0);
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
    LinkConfig config;
    RpcClient client(config);

    auto &mgr = SessionManager::GetInstance();
    MigrationSession *session =
        mgr.CreateSession(MigrationSession::Role::Initiator, request->uuid(), request->domainname(), request->desturi(),
                          request->localuri(), request->flags());
    if (!session) {
        response->set_result(1); // already exists or failed
        return grpc::Status::OK;
    }
    // 初始化会话内的 RPC 客户端
    session->SetRpcClient(std::make_unique<RpcClient>(config));
    // 启动状态机（内部会依次调用 Prepare/Exchange/Start）
    session->Start();
    response->set_result(0);
    return grpc::Status::OK;
}

} // namespace virtrust
