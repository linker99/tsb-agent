/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "virtrust/link/migration_session.h"

#include <iostream>
#include <memory>
#include <mutex>


#include "virtrust/base/logger.h"
#include "virtrust/dllib/libvirt.h"
#include "virtrust/link/proto/proto_tools.h"
#include "virtrust/link/proto/migrate.pb.h"

namespace virtrust {

namespace {
unsigned int GetFlagCleard(const unsigned int &flags, const unsigned int &clear)
{
    return flags & ~clear;
}
}

MigrationSession *SessionManager::CreateSession(MigrationSession::Role role, const std::string &sessionId,
                                                const std::string &domainName, const std::string &destUri,
                                                const std::string &localUri, const unsigned int flags)
{
    std::lock_guard<std::mutex> lock(mtx_);

    auto it = sessions_.find(sessionId);
    if (it != sessions_.end()) {
        return it->second.get();
    }

    auto session = std::make_unique<MigrationSession>(role, sessionId, domainName, destUri, localUri, flags);
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
                                   const std::string &destUri, const std::string &localUri, const unsigned int flags)
    : role_(role),
      state_(State::Init),
      sessionId_(sessionId),
      domainName_(domainName),
      destUri_(destUri),
      localUri_(localUri),
      flags_(flags)
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
        VIRTRUST_LOG_ERROR("|SendMigrateRequest|END|returnF|uuid: {}|rpc client is nullptr.", sessionId_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    protos::PrepareMigRequest req;
    req.set_uuid(sessionId_);
    req.set_domainname(domainName_);

    protos::PrepareMigReply reply;

    int32_t rc = rpcClient_->PrepareMigration(5, req, &reply);
    bool ok = (rc == 0 && reply.result() == 0);

    if (!ok) {
        VIRTRUST_LOG_ERROR("|SendMigrateRequest|END|returnF|uuid: {}|send migrate request failed.", sessionId_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }
    return OnMigrateResponseReceived();
}

MigrateSessionRc MigrationSession::OnMigrateResponseReceived()
{
    EnterState(State::WaitingKey);
    return SendExchangeKey();
}

MigrateSessionRc MigrationSession::SendExchangeKey()
{
    protos::EXchangePkAndReportRequest req;
    MigrateSessionRc rc = GetExchangePkAndReport(&req, nullptr);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|SendExchangeKey|END|returnF|uuid: {}|Get local cert and report failed.", sessionId_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    protos::EXchangePkAndReportReply res;
    int32_t ret = rpcClient_->ExchangePkAndReport(5, req, &res);
    if (ret != 0 || res.result() != 0) {
        VIRTRUST_LOG_ERROR("|SendExchangeKey|END|returnF|uuid: {}|Exchange cert and report failed.", sessionId_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }
    return OnExchangeKeyResponseReceived(res);
}

MigrateSessionRc MigrationSession::OnExchangeKeyResponseReceived(protos::EXchangePkAndReportReply &res)
{
    // 校验证书和报告
    EnterState(State::CertVerify);

    // 1. 校验对端证书
    MigrateSessionRc rc = VerifyCertificate(res.uuid(), res.cert(), res.publickey());
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyResponseReceived|END|returnF|uuid: {}|Verify peer cert failed.", sessionId_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    // 2.校验对端报告
    rc = VerifyHostAndVmReport(res.hostreport(), res.vmreport());
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyResponseReceived|END|returnF|uuid: {}|Verify peer report failed.",
                           sessionId_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    return SendStartMigration();
}

MigrateSessionRc MigrationSession::SendStartMigration()
{
    protos::StartMigRequest req;
    req.set_domainname(domainName_);
    req.set_uuid(sessionId_);

    protos::StartMigReply res;
    int32_t ret = rpcClient_->StartMigration(5, req, &res);
    if (ret != 0) {
        VIRTRUST_LOG_ERROR("|SendStartMigration|END|returnF|uuid: {}|Send start migration signal failed.", sessionId_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }
    if (res.result() != 0) {
        VIRTRUST_LOG_ERROR("|SendStartMigration|END|returnF|uuid: {}|Start migration failed.", sessionId_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    return OnStartMigrationResponseReceived();
}

MigrateSessionRc MigrationSession::OnStartMigrationResponseReceived()
{
    char *cipher = nullptr;
    //收集密码资源
    auto ret = MigrationGetVRootCipher(const_cast<char *>(sessionId_.c_str()), &cipher);
    if (ret != 0) {
        VIRTRUST_LOG_ERROR("|OnStartMigrationResponseReceived|END|returnF|uuid:{}|MigrationGetVRootCipher failed.", sessionId_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }
    // 进入传输阶段
    EnterState(State::Transferring);
    return SendTransferOnce(cipher);
}

MigrateSessionRc MigrationSession::SendTransferOnce(char *cipher)
{
    if (cipher == nullptr) {
        VIRTRUST_LOG_ERROR("|SendTransferOnce|END|returnF||cipher is null.");
        OnFail();
        return OnTransferResponseReceived(false);
    }

    // 1.调用libvirt命令进行迁移
    MigrateSessionRc rc = MigrateByLibvirt();
    if (rc != MigrateSessionRc::ERROR) {
        VIRTRUST_LOG_ERROR("|SendTransferOnce|END|returnF||migrate by libvirt failed.");
        OnFail();
        return rc;
    }

    // 2.传输数据
    protos::VRsourceInfoRequest req;
    req.set_uuid(sessionId_);
    std::string cipherString(cipher);
    req.set_data(cipherString);
    free(cipher);
    protos::VRsourceInfoReply res;
    int32_t ret = rpcClient_->SendVRsourceData(5, req, &res);
    // 传输数据失败
    if (ret != 0) {
        VIRTRUST_LOG_ERROR("|SendTransferOnce|END|returnF||failed to tansfer data for: {}", domainName_);
        UndoMigration();
        return MigrateSessionRc::ERROR;
    }

    return OnTransferResponseReceived(res.result() == 0);
}

MigrateSessionRc MigrationSession::OnTransferResponseReceived(bool transferRet)
{
    // 对端校验数据失败
    if (!transferRet) {
        VIRTRUST_LOG_ERROR("|OnTransferResponseReceived|END|returnF||peer verify data faild: {}", domainName_);
        UndoMigration();
        return MigrateSessionRc::ERROR;
    }

    // 通知TSB迁移成功
    auto ret = MigrationNotify(const_cast<char *>(sessionId_.c_str()), 0);
    if (ret != 0) {
        VIRTRUST_LOG_ERROR("|DomainMigrate|END|returnF|MigrationNotify failure failed uuid: {}.", sessionId_);
        UndoMigration();
        return MigrateSessionRc::ERROR;
    }

    // 所有动作执行完后，判断是否删除本地虚机
    if (flags_ & MIGRATE_UNDEFINE_SOURCE) {
        // TODO 执行删除本地虚机操作
    }

    // 向对端发送最终通知，忽略通知结果
    SendFinishedNotify(true);
    EnterState(State::Finished);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::SendFinishedNotify(bool success)
{
    protos::MigrateResultRequest req;
    req.set_result(success ? 0 : 1);
    req.set_uuid(sessionId_);
    protos::MigrateResultReply res;
    auto ret = rpcClient_->NotifyVRMigrateResult(5, req, &res);
    if (ret != 0) {
        VIRTRUST_LOG_INFO("|SendFinishedNotify|END|returnF|domain name: {}|Send notify failed.", domainName_);
        return MigrateSessionRc::ERROR;
    }
    return OnFinishedResponseReceived(res.result() == 0);
}

MigrateSessionRc MigrationSession::OnFinishedResponseReceived(bool finished)
{
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::GetExchangePkAndReport(protos::EXchangePkAndReportRequest *req,
                                                          protos::EXchangePkAndReportReply *res)
{
    constexpr uint32_t CERT_BUF_LEN = 4096;
    constexpr uint32_t PUBKEY_BUF_LEN = 1024;

    char cert[CERT_BUF_LEN] = {0};
    char pubKey[PUBKEY_BUF_LEN] = {0};

    auto uuid = sessionId_;

    int ret = MigrationGetCert(uuid.data(), cert, pubKey);
    if (ret != 0) {
        VIRTRUST_LOG_ERROR("|GetExchangePkAndReport|END|returnF|uuid: {}|Get local cert failed.");
        return MigrateSessionRc::ERROR;
    }

    trust_report_new hostReport;
    trust_report_new vmReport;
    ret = GetReport(nullptr, uuid.data(), &hostReport, &vmReport);
    if (ret != 0) {
        VIRTRUST_LOG_ERROR("|GetExchangePkAndReport|END|returnF|uuid: {}|Get local report failed.");
        return MigrateSessionRc::ERROR;
    }

    if (role_ == Role::Initiator) {
        req->set_domainname(domainName_);
        req->set_uuid(uuid);
        req->set_cert(cert);
        req->set_publickey(pubKey);
        auto hostReportProto = req->mutable_hostreport();
        ReportToProto(hostReport, hostReportProto);
        auto vmReportProto = req->mutable_vmreport();
        ReportToProto(vmReport, vmReportProto);
    } else {
        res->set_domainname(domainName_);
        res->set_uuid(uuid);
        res->set_cert(cert);
        res->set_publickey(pubKey);
        auto hostReportProto = res->mutable_hostreport();
        ReportToProto(hostReport, hostReportProto);
        auto vmReportProto = res->mutable_vmreport();
        ReportToProto(vmReport, vmReportProto);
    }
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::VerifyCertificate(std::string uuid, std::string cert, std::string pubkey)
{
    int ret = MigrationCheckPeerPk(uuid.data(), cert.data(), pubkey.data());
    return ret == 0 ? MigrateSessionRc::OK : MigrateSessionRc::ERROR;
}

MigrateSessionRc MigrationSession::VerifyHostAndVmReport(const protos::TrustReportNew &hostProtoReport,
                                                         const protos::TrustReportNew &vmProtoReport)
{
    trust_report_new hostReport = ReportFromProto(hostProtoReport);
    trust_report_new vmReport = ReportFromProto(vmProtoReport);

    // 调用TSB API进行报告校验
    auto ret = VerifyReport(nullptr, sessionId_.data(), &hostReport, &vmReport);
    return ret == 0 ? MigrateSessionRc::OK : MigrateSessionRc::ERROR;
}

// 调用libvirt接口迁移
MigrateSessionRc MigrationSession::MigrateByLibvirt()
{
    auto &libvirt = Libvirt::GetInstance();

    std::unique_ptr<ConnCtx> destConn;
    auto rc = GetVirConnContext(destUri_, destConn);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|MigrateByLibvirt|END|returnF||failed to get virt connect: {}", destUri_);
        return rc;
    }

    std::unique_ptr<ConnCtx> localConn;
    rc = GetVirConnContext(localUri_, localConn);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|MigrateByLibvirt|END|returnF||failed to get virt connect: {}", localUri_);
        return rc;
    }

    auto domain = std::make_unique<DomainCtx>(localConn, domainName_);
    if (domain->Get() == nullptr) {
        VIRTRUST_LOG_ERROR("|SendTransferOnce|END|returnF||failed to find domain: {}", domainName_);
        return MigrateSessionRc::ERROR;
    }
    auto *domainPtr = libvirt.virDomainMigrate3(domain->Get(), destConn->Get(), nullptr, 0, GetFlagCleard(flags_, MIGRATE_UNDEFINE_SOURCE));
    if (domainPtr == nullptr) {
        VIRTRUST_LOG_ERROR("|SendTransferOnce|END|returnF||failed to migrate domain: {}", domainName_);
        return MigrateSessionRc::ERROR;
    }
    libvirt.virDomainFree(domainPtr);

    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::GetVirConnContext(const std::string& uri, std::unique_ptr<ConnCtx>& outConn)
{
    auto conn = std::make_unique<ConnCtx>();
    if (!conn->SetUri(uri)) {
        VIRTRUST_LOG_ERROR("|SendTransferOnce|END|returnF||destUri is not valid: {}", uri);
        return MigrateSessionRc::ERROR;
    }

    conn->Connect();
    if (conn->Get() == nullptr) {
        VIRTRUST_LOG_ERROR("|SendTransferOnce|END|returnF||failed to establish connection to: {}", uri);
        return MigrateSessionRc::ERROR;
    }

    // 成功了再把拥有权交出去
    outConn = std::move(conn);
    return MigrateSessionRc::OK;
}

void MigrationSession::UndoMigration()
{
    // 防止server端误调
    if (role_ != Role::Initiator) {
        return;
    }

    // 1.删除对端虚拟机
    UndefineForPeer();

    // 2.通知TSB迁移失败
    NotifyVRMigration(false);

    // 3.通知peer迁移失败，并进行清理
    OnFail();
}

// 删除对端虚拟机
MigrateSessionRc MigrationSession::UndefineForPeer()
{
    std::unique_ptr<ConnCtx> destConn;
    auto rc = GetVirConnContext(destUri_, destConn);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|UndefineForPeer|END|returnF||failed to get virt connect: {}", destUri_);
        return rc;
    }

    auto destDomain = std::make_unique<DomainCtx>(destConn, domainName_);
    if (destDomain->Get() == nullptr) {
        VIRTRUST_LOG_ERROR("|UndefineForPeer|END|returnF|failed to find destDomain: {}", domainName_);
        return MigrateSessionRc::ERROR;
    }

    auto &libvirt = Libvirt::GetInstance();
    if (libvirt.virDomainUndefineFlags(destDomain->Get(), DOMAIN_UNDEFINE_NVRAM) != 0) {
        VIRTRUST_LOG_INFO("|UndefineForPeer|END|returnF|undefine dest domain: {} failed.", domainName_);
        return MigrateSessionRc::ERROR;
    }
    return MigrateSessionRc::OK;
}

// 通知TSB迁移结果
MigrateSessionRc MigrationSession::NotifyVRMigration(bool success)
{
    auto status = success ? 0 : -1;
    auto ret = MigrationNotify(const_cast<char *>(sessionId_.c_str()), status);
    if (ret != 0) {
        VIRTRUST_LOG_INFO("|NotifyVRMigration|END|returnF|domainName:{}, migration statu: {}|Notify TSB failed.", domainName_, success);
        return MigrateSessionRc::ERROR;
    }
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

void MigrationSession::OnFail()
{
    // 向服务端发送迁移失败通知
    if (role_ == Role::Initiator) {
        MigrateSessionRc sendRet = SendFinishedNotify(1);
        if (sendRet != MigrateSessionRc::OK) {
            VIRTRUST_LOG_ERROR("|DomainMigrate|END|returnF|SendFinishedNotify failed uuid: {}.", sessionId_);
        }
    }

    // 进入失败状态并进行清理
    EnterState(State::Failed);
    Cleanup();
}

MigrateSessionRc MigrationSession::OnMigrateRequestReceived()
{
    EnterState(State::WaitingKey);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnExchangeKeyRequestReceived(const protos::EXchangePkAndReportRequest *request,
                                                                protos::EXchangePkAndReportReply *response)
{
    if (state_ != State::WaitingKey) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyRequestReceived|END|returnF|uuid:{}|Waiting for exchanging key timeout.",
                           sessionId_);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }

    // 1. 获取本端证书和报告
    MigrateSessionRc rc = GetExchangePkAndReport(nullptr, response);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyRequestReceived|END|returnF|uuid: {}|Get public key and report failed.",
                           sessionId_);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }

    // 2. 校验对端证书
    rc = VerifyCertificate(request->uuid(), request->cert(), request->publickey());
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyRequestReceived|END|returnF|uuid: {}|Verify peer cert failed.", sessionId_);
        return MigrateSessionRc::ERROR;
    }

    // 3. 校验对端报告
    rc = VerifyHostAndVmReport(request->hostreport(), request->vmreport());
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyRequestReceived|END|returnF|uuid: {}|Verify peer report failed.", sessionId_);
        return MigrateSessionRc::ERROR;
    }

    // 等待对端校验证书后的进一步信号：开始迁移信号
    EnterState(State::CertVerify);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnStartMigrationRequestReceived()
{
    if (state_ != State::CertVerify) {
        Cleanup();
        VIRTRUST_LOG_ERROR(
            "|OnStartMigrationRequestReceived|END|returnF||Waiting for starting migration signal timeout.");
        return MigrateSessionRc::ERROR;
    }

    // 等待对端发起数据传数
    EnterState(State::Transferring);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnTransferDataRequestReceived(const protos::VRsourceInfoRequest *request)
{
    if (state_ != State::Transferring) {
        Cleanup();
        VIRTRUST_LOG_ERROR("|OnTransferDataRequestReceived|END|returnF||Waiting for transfering timeout.");
        return MigrateSessionRc::ERROR;
    }
    // 服务端校验客户端发来的虚拟机资源信息
    auto ret = MigrationImportVRootCipher(const_cast<char *>(request->data().c_str()),
                                          const_cast<char *>(request->uuid().c_str()));
    if (ret != 0) {
        EnterState(State::Failed);
        Cleanup();
        VIRTRUST_LOG_ERROR(
            "|DomainMigrate|END|returnF|OnTransferDataRequestReceived MigrationImportVrootCipher failed.");
        return MigrateSessionRc::ERROR;
    }
    EnterState(State::Transferring);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnFinishedRequestReceived(bool finished)
{
    if (role_ != Role::Responder) {
        return MigrateSessionRc::ERROR;
    }
    if (!finished) {
        Cleanup();
        return MigrateSessionRc::ERROR;
    }
    EnterState(State::Finished);
    Cleanup();
    return MigrateSessionRc::OK;
}
} // namespace virtrust
