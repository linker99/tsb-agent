/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "virtrust/link/migration_session.h"

#include <iostream>
#include <memory>
#include <mutex>

#include "virtrust/link/proto/migrate.pb.h"

namespace virtrust {

MigrationSession *SessionManager::CreateSession(MigrationSession::Role role, const std::string &sessionId,
                                                const std::string &domainName, const std::string &destUri)
{
    std::lock_guard<std::mutex> lock(mtx_);

    auto it = sessions_.find(sessionId);
    if (it != sessions_.end()) {
        return it->second.get();
    }

    auto session = std::make_unique<MigrationSession>(role, sessionId, domainName, destUri);
    MigrationSession *raw = session.get();
    sessions_[sessionId] = std::move(session);
    return raw;
}

MigrationSession *SessionManager::GetSession(const std::string &sessionId)
{
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = sessions_.find(sessionId);
    if (it == sessions_.end())
        return nullptr;
    return it->second.get();
}

void SessionManager::RemoveSession(const std::string &sessionId)
{
    std::lock_guard<std::mutex> lock(mtx_);
    sessions_.erase(sessionId);
}

MigrationSession::MigrationSession(Role role, const std::string &sessionId, const std::string &domainName,
                                   const std::string &destUri)
    : role_(role), state_(State::Init), sessionId_(sessionId), domainName_(domainName), destUri_(destUri)
{}

MigrateSessionRc MigrationSession::Start()
{
    if (role_ != Role::Initiator) {
        return MigrateSessionRc::ERROR;
    }
    EnterState(State::Init);
    return SendMigrateRequest();
}

MigrateSessionRc MigrationSession::SendMigrateRequest()
{
    if (!rpcClient_) {
        EnterState(State::Failed);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }

    protos::PrepareMigRequest req;
    req.set_uuid(sessionId_);
    req.set_domainname(sessionId_);

    protos::PrepareMigReply reply;

    int32_t rc = rpcClient_->PrepareMigration(5, req, &reply);
    bool ok = (rc == 0 && reply.result() == 0);
    return OnMigrateResponseReceived(ok);
}

MigrateSessionRc MigrationSession::OnMigrateResponseReceived(bool agree)
{
    if (!agree) {
        EnterState(State::Failed);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }
    EnterState(State::WaitingKey);
    return SendExchangeKey();
}

MigrateSessionRc MigrationSession::SendExchangeKey()
{
    if (!rpcClient_) {
        EnterState(State::Failed);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }
    // TODO: 生成远端可验证的报告，并获取/生成本端公钥
    myPubKey_ = "local_pub_key_bytes";
    protos::EXchangePkAndReportRequest req;
    req.set_domainname(sessionId_);
    req.set_uuid(sessionId_);
    req.set_report("mock_report");
    req.set_publickey(myPubKey_);
    protos::EXchangePkAndReportReply res;
    int32_t rc = rpcClient_->ExchangePkAndReport(5, req, &res);
    if (rc != 0) {
        return MigrateSessionRc::ERROR;
    }
    return OnExchangeKeyResponseReceived("", "");
}

MigrateSessionRc MigrationSession::OnExchangeKeyResponseReceived(const std::string &peerReport,
                                                                 const std::string &peerPubKey)
{
    if (peerPubKey.empty()) {
        EnterState(State::Failed);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }
    peerPubKey_ = peerPubKey;
    // 交换完成后发送开始迁移控制
    EnterState(State::WaitingKey);
    return SendStartMigration();
}

MigrateSessionRc MigrationSession::SendStartMigration()
{
    if (!rpcClient_) {
        EnterState(State::Failed);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }
    protos::StartMigRequest req;
    // TODO: 设置真实的 domainName
    req.set_domainname(sessionId_);
    // TODO: 设置真实的 uuid
    req.set_uuid(sessionId_);
    protos::StartMigReply res;
    int32_t rc = rpcClient_->StartMigration(5, req, &res);
    return OnStartMigrationResponseReceived(rc == 0);
}

MigrateSessionRc MigrationSession::OnStartMigrationResponseReceived(bool agree)
{
    if (!agree) {
        EnterState(State::Failed);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }
    // 进入传输阶段
    EnterState(State::Transferring);
    return SendTransferOnce();
}

MigrateSessionRc MigrationSession::SendTransferOnce()
{
    if (!rpcClient_) {
        EnterState(State::Failed);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }
    // TODO: 准备一次传输的数据块（敏感资源/迁移数据）
    protos::VRsourceInfoRequest req;
    req.set_uuid(sessionId_);
    // TODO: 设置真实数据内容
    req.set_data("vm_or_secret_chunk");
    protos::VRsourceInfoReply res;
    int32_t rc = rpcClient_->SendVRsourceData(5, req, &res);
    // TODO: 如果有分块传输，按返回状态决定是否继续
    bool finished = (rc == 0);
    return OnTransferResponseReceived(finished);
}

MigrateSessionRc MigrationSession::OnTransferResponseReceived(bool finished)
{
    if (!finished) {
        EnterState(State::Failed);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }
    // 数据传输完成后，进入完成阶段
    // TODO: do real migration

    return OnFinishedResponseReceived(true);
}

MigrateSessionRc MigrationSession::OnFinishedResponseReceived(bool finished)
{
    if (!finished) {
        EnterState(State::Failed);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }
    EnterState(State::Finished);
    Cleanup();
    return MigrateSessionRc::OK;
}

void MigrationSession::EnterState(State s)
{
    state_ = s;
    CancelTimer();

    // 终态不再开定时器
    if (s == State::Failed || s == State::Finished) {
        return;
    }

    StartTimerFor(s);
}

static std::chrono::seconds TimeoutForState(MigrationSession::State s)
{
    switch (s) {
        case MigrationSession::State::Init:
            return std::chrono::seconds(10);
        case MigrationSession::State::WaitingKey:
            return std::chrono::seconds(30);
        case MigrationSession::State::Transferring:
            return std::chrono::seconds(60);
        default:
            return std::chrono::seconds(60);
    }
}

void MigrationSession::StartTimerFor(State s)
{
    timerActive_.store(true);
    auto dur = TimeoutForState(s);
    timer_.Start(dur, [this, s] { this->OnTimeout(s); });
}

void MigrationSession::CancelTimer()
{
    timer_.Cancel();
    timerActive_.store(false);
}

void MigrationSession::OnTimeout(State stateWhenSet)
{
    if (!timerActive_.load() || state_ != stateWhenSet) {
        return;
    }
    EnterState(State::Failed);
    Cleanup();
}

void MigrationSession::Cleanup()
{
    CancelTimer();
    SessionManager::GetInstance().RemoveSession(sessionId_);
}

MigrateSessionRc MigrationSession::OnMigrateRequestReceived()
{
    // 1. 第一次收到 MigrateRequest，新建会话时调用
    if (state_ != State::Init) {
        VIRTRUST_LOG_ERROR("|OnMigrateRequestReceived|END|returnF|||Wrong state.");
        return MigrateSessionRc::ERROR;
    }
    EnterState(State::Init);

    // 2. 检查资源是否可用，生成报告
    // TODO
    bool ok = true;

    // 3. 返回响应
    //    通过 gRPC handler 写入 response->set_agree(ok);
    //    这里只更新状态
    if (!ok) {
        EnterState(State::Failed);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }

    EnterState(State::WaitingKey);
    // 启动60s，等待对端发 ExchangeKey

    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnExchangeKeyRequestReceived(const std::string &peerPubKey)
{
    if (role_ != Role::Responder) {
        return MigrateSessionRc::ERROR;
    }

    peerPubKey_ = peerPubKey;
    std::cout << "[Responder] Got peer public key" << std::endl;

    // TODO: 生成/加载响应方公钥，生成报告
    myPubKey_ = "responder_pub_key_bytes";

    // 2. 返回给对端（gRPC handler 内部写 response->set_pub_key(myPubKey_)）
    // TODO: 在 handler 中写入响应的 report/publicKey

    // 等待对端的 StartMigration
    EnterState(State::WaitingKey);

    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnStartMigrationRequestReceived(const std::string &domainName)
{
    if (role_ != Role::Responder) {
        return MigrateSessionRc::ERROR;
    }
    // TODO: 根据 domainName 做准备（挂载/预分配等）
    EnterState(State::Transferring);

    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnTransferDataRequestReceived(const std::string &data, bool finished)
{
    if (role_ != Role::Responder) {
        return MigrateSessionRc::ERROR;
    }
    // TODO: 校验并落盘 data（考虑分块/校验）
    if (finished) {
        // TODO: 定义并启动虚机
        EnterState(State::Finished);
        Cleanup();
    } else {
        EnterState(State::Transferring);
    }
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnFinishedRequestReceived(const std::string &vmData, bool finished)
{
    if (role_ != Role::Responder) {
        return MigrateSessionRc::ERROR;
    }
    // TODO: 收到结束通知后的收尾处理
    if (!finished) {
        EnterState(State::Failed);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }
    EnterState(State::Finished);
    Cleanup();
    return MigrateSessionRc::OK;
}
} // namespace virtrust
