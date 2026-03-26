/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "virtrust/link/migration_service_impl.h"

#include <memory>
#include <regex>
#include <thread>
#include <vector>

#include "libvirtrustd/defines.h"
#include "tsb_agent/tsb_agent.h"

#include "virtrust/base/logger.h"
#include "virtrust/link/defines.h"
#include "virtrust/link/grpc_client.h"
#include "virtrust/link/migration_session.h"

namespace virtrust {
const std::regex IP_REGEX(R"((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))");

namespace {
std::string ExtractSingleIP(const std::string &str)
{
    std::vector<std::string> ips;
    std::sregex_iterator it(str.begin(), str.end(), IP_REGEX);
    std::sregex_iterator end;
    for (; it != end; ++it) {
        ips.push_back((*it)[1]);
    }

    if (ips.empty()) {
        VIRTRUST_LOG_ERROR("|ExtracSingleIP|END|returnF|No IP address found");
        return "";
    } else if (ips.size() > 1) {
        VIRTRUST_LOG_ERROR("|ExtracSingleIP|END|returnF|IP address is not in one or more");
        return "";
    }
    return ips[0];
}
} // namespace

grpc::Status MigrationServiceImpl::PrepareMigration(grpc::ServerContext *context,
                                                    const protos::PrepareMigRequest *request,
                                                    protos::PrepareMigReply *response)
{
    VIRTRUST_LOG_DEBUG("|PrepareMigration|START||start handle rpc request");
    auto &uuid = request->uuid();
    auto &domainName = request->domainname();
    auto &mgr = SessionManager::GetInstance();

    // 否则创建session
    MigrationSession *session = mgr.CreateSession(MigrationSession::Role::Responder, uuid, request->domainname(),
                                                  request->desturi(), request->localuri(), request->flags());
    if (session == nullptr) { // already exists or failed
        VIRTRUST_LOG_ERROR(
            "|PrepareMigration|END|returnF|domain name: {}|Session already exists, this VM is already migrating",
            domainName);
        response->set_result(1);
        return grpc::Status::OK;
    }

    MigrateSessionRc rc = session->OnMigrateRequestReceived();
    if (rc != MigrateSessionRc::OK) {
        response->set_result(1);
        return grpc::Status::OK;
    }
    response->set_result(0);
    return grpc::Status::OK;
}

// 2: 交换公钥和报告
grpc::Status MigrationServiceImpl::ExchangePkAndReport(grpc::ServerContext *context,
                                                       const protos::EXchangePkAndReportRequest *request,
                                                       protos::EXchangePkAndReportReply *response)
{
    VIRTRUST_LOG_DEBUG("|ExchangePkAndReport|START||start handle rpc request");
    auto &uuid = request->uuid();
    auto &domainName = request->domainname();
    MigrationSession *session = SessionManager::GetInstance().GetSession(uuid);
    if (session == nullptr) {
        VIRTRUST_LOG_ERROR("|ExchangePkAndReport|END|returnF|domain name: {}|Can't find session.", domainName);
        response->set_result(1);
        return grpc::Status::OK;
    }

    MigrateSessionRc rc = session->OnExchangeKeyRequestReceived(request, response);
    if (rc != MigrateSessionRc::OK) {
        response->set_result(1);
        return grpc::Status::OK;
    }

    response->set_result(0);
    return grpc::Status::OK;
}

// 3: 开始迁移通知
grpc::Status MigrationServiceImpl::StartMigration(grpc::ServerContext *context, const protos::StartMigRequest *request,
                                                  protos::StartMigReply *response)
{
    VIRTRUST_LOG_DEBUG("|StartMigration|START||start handle rpc request");
    auto &uuid = request->uuid();
    auto &domainName = request->domainname();
    MigrationSession *session = SessionManager::GetInstance().GetSession(uuid);
    if (session == nullptr) {
        VIRTRUST_LOG_ERROR("|StartMigration|END|returnF|domain name: {}|Can't find session.", domainName);
        response->set_result(1);
        return grpc::Status::OK;
    }

    MigrateSessionRc rc = session->OnStartMigrationRequestReceived();
    if (rc != MigrateSessionRc::OK) {
        response->set_result(1);
        return grpc::Status::OK;
    }

    response->set_result(0);
    return grpc::Status::OK;
}

// 4：迁移虚机密码资源
grpc::Status MigrationServiceImpl::SendVRsourceData(grpc::ServerContext *context,
                                                    const protos::VRsourceInfoRequest *request,
                                                    protos::VRsourceInfoReply *response)
{
    VIRTRUST_LOG_DEBUG("|SendVRsourceData|START||start handle rpc request");
    if (request == nullptr) {
        VIRTRUST_LOG_ERROR("|SendVRsourceData|END|returnF||request is nullptr.");
        response->set_result(1);
        return grpc::Status::OK;
    }
    auto &uuid = request->uuid();
    MigrationSession *session = SessionManager::GetInstance().GetSession(uuid);
    if (session == nullptr) {
        VIRTRUST_LOG_ERROR("|SendVRsourceData|END|returnF|uuid: {}|Can't find session.", uuid);
        response->set_result(1);
        return grpc::Status::OK;
    }
    // 服务端
    int32_t result = 0;
    MigrateSessionRc rc = session->OnTransferDataRequestReceived(request, result);
    if (rc != MigrateSessionRc::OK) {
        response->set_result(1);
        if (result != 0) {
            response->set_result(result);
        }
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
    VIRTRUST_LOG_DEBUG("|NotifyVRMigrateResult|START||start handle rpc request");
    if (request == nullptr) {
        VIRTRUST_LOG_ERROR("|DomainMigrate|END|returnF|NotifyVRMigrateResult request is nullptr.");
        response->set_result(1);
        return grpc::Status::OK;
    }
    auto &uuid = request->uuid();
    MigrationSession *session = SessionManager::GetInstance().GetSession(uuid);
    if (session == nullptr) {
        VIRTRUST_LOG_ERROR("|StartMigration|END|returnF|NotifyVRMigrateResult uuid: {}|Can't find session.", uuid);
        response->set_result(1);
        return grpc::Status::OK;
    }
    MigrateSessionRc rc = session->OnFinishedRequestReceived(request->result() == 0);
    if (rc != MigrateSessionRc::OK) {
        response->set_result(1);
        return grpc::Status::OK;
    }
    response->set_result(0);
    return grpc::Status::OK;
}

// 6: 发起迁移任务, virsh-sh主动这个方法
grpc::Status MigrationServiceImpl::DomainMigrate(grpc::ServerContext *context,
                                                 const protos::DomainMigraterRequest *request,
                                                 protos::DomainMigraterReply *response)
{
    VIRTRUST_LOG_DEBUG("|DomainMigrate|START||start handle uds request");
    std::string destIp = ExtractSingleIP(request->desturi());
    if (destIp.empty()) {
        VIRTRUST_LOG_ERROR("|MigrationServiceImpl DomainMigrate|END|returnF|invalid ip, destUri is: {}",
                           request->desturi());
        response->set_result(1);
        return grpc::Status::OK;
    }
    LinkConfig config = ConfigMgr::Instance().GetLinkConfig();
    config.ip = destIp;
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
    auto ret = session->Start();
    session->Cleanup();
    if (ret != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|MigrationServiceImpl DomainMigrate|END|returnF|domain : {} migrate failed.",
                           request->domainname());
        response->set_result(1);
        return grpc::Status::OK;
    }

    response->set_result(0);
    VIRTRUST_LOG_DEBUG("|DomainMigrate|END|returnS|");
    return grpc::Status::OK;
}

} // namespace virtrust
