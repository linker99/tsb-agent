/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "virtrust/link/migration_session.h"

#include <iostream>
#include <memory>
#include <mutex>

#include "virtrust/api/define_private.h"
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
} // namespace

MigrationSession *SessionManager::CreateSession(MigrationSession::Role role, const std::string &sessionId,
                                                const std::string &domainName, const std::string &destUri,
                                                const std::string &localUri, const unsigned int flags)
{
    std::lock_guard<std::mutex> lock(mtx_);

    auto it = sessions_.find(sessionId);
    if (it != sessions_.end()) {
        VIRTRUST_LOG_ERROR("|CreateSession|END|returnF|uuid: {}|already exists session with same uuid.", sessionId);
        return nullptr;
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
    if (it == sessions_.end()) {
        return nullptr;
    }
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
        VIRTRUST_LOG_ERROR("|SendMigrateRequest|END|returnF|domain name: {}|rpc client is nullptr.", domainName_);
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
        VIRTRUST_LOG_ERROR("|SendMigrateRequest|END|returnF|domain name: {}|send migrate request failed.", domainName_);
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
        VIRTRUST_LOG_ERROR("|SendExchangeKey|END|returnF|domain name: {}|Get local cert and report failed.",
                           domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    protos::EXchangePkAndReportReply res;
    int32_t ret = rpcClient_->ExchangePkAndReport(5, req, &res);
    if (ret != 0 || res.result() != 0) {
        VIRTRUST_LOG_ERROR("|SendExchangeKey|END|returnF|domain name: {}|Exchange cert and report failed.",
                           domainName_);
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
        VIRTRUST_LOG_ERROR("|OnExchangeKeyResponseReceived|END|returnF|domain name: {}|Verify peer cert failed.",
                           domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    // 2.校验对端报告
    rc = VerifyHostAndVmReport(res.hostreport(), res.vmreport());
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyResponseReceived|END|returnF|domain name: {}|Verify peer report failed.",
                           domainName_);
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
        VIRTRUST_LOG_ERROR("|SendStartMigration|END|returnF|domain name: {}|Send start migration signal failed.",
                           domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }
    if (res.result() != 0) {
        VIRTRUST_LOG_ERROR("|SendStartMigration|END|returnF|domain name: {}|Start migration failed.", domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    return OnStartMigrationResponseReceived();
}

MigrateSessionRc MigrationSession::OnStartMigrationResponseReceived()
{
    char *cipher = nullptr;
    int cipherLen = 0;
    // 收集密码资源
    auto ret = MigrationGetVrootCipher(const_cast<char *>(sessionId_.c_str()), &cipher, &cipherLen);
    if (ret != 0 || cipher == nullptr) {
        VIRTRUST_LOG_ERROR(
            "|OnStartMigrationResponseReceived|END|returnF|domain name: {}|MigrationGetVRootCipher failed.",
            domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }
    std::string cipherStr(cipher, cipherLen);
    free(cipher);

    // 收集虚机描述信息
    Description vmInfo;
    auto rc = GetVmInfo(vmInfo);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnStartMigrationResponseReceived|END|returnF|domain name: {}|Get VM description failed.",
                           domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    // 进入传输阶段
    EnterState(State::Transferring);
    return SendTransferOnce(cipherStr, vmInfo);
}

MigrateSessionRc MigrationSession::SendTransferOnce(const std::string &cipher, const Description &vmInfo)
{
    // 1.调用libvirt命令进行迁移
    MigrateSessionRc rc = MigrateByLibvirt();
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|SendTransferOnce|END|returnF||migrate by libvirt failed.");
        OnFail();
        return rc;
    }

    // 2.传输数据
    protos::VRsourceInfoRequest req;
    req.set_uuid(sessionId_);
    req.set_cipherdata(cipher);
    auto protosDesc = req.mutable_vtpcminfo();
    DescriptionToProto(vmInfo, protosDesc);

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
    auto rc = NotifyVRMigration(true);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnTransferResponseReceived|END|returnF|domain name: {}|MigrationNotify failure failed.",
                           domainName_);
        UndoMigration();
        return MigrateSessionRc::ERROR;
    }

    // 所有动作执行完后，判断是否删除本地虚机
    if (flags_ & MIGRATE_UNDEFINE_SOURCE) {
        (void)UndefineVirtDomainBaseUri(localUri_);
        int tsbRet = RemoveVRoot(const_cast<char *>(sessionId_.c_str()));
        if (tsbRet != 0) {
            VIRTRUST_LOG_ERROR("|OnTransferResponseReceived|END|returnF||tsb resource remove "
                               "failed, maybe not exist tsb resource uuid: "
                               "{},domainName: {},use virsh to undefine domain.",
                               sessionId_, domainName_);
        }
    }

    // 向对端发送最终通知，忽略通知结果
    (void)SendFinishedNotify(true);
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
        VIRTRUST_LOG_ERROR("|SendFinishedNotify|END|returnF|domain name: {}|Send notify failed.", domainName_);
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
    auto uuid = sessionId_;
    char *cert = nullptr;
    int certLen = 0;
    char *pubKey = nullptr;
    int pubKeyLen = 0;

    int ret = MigrationGetCert(uuid.data(), &cert, &certLen, &pubKey, &pubKeyLen);
    if (ret != 0) {
        VIRTRUST_LOG_ERROR("|GetExchangePkAndReport|END|returnF|domain name: {}|Get local cert failed.", domainName_);
        return MigrateSessionRc::ERROR;
    }

    std::string certStr(cert, certLen);
    std::string pubKeyStr(pubKey, pubKeyLen);
    free(cert);
    free(pubKey);

    trust_report_new hostReport;
    trust_report_new vmReport;
    ret = GetReport(uuid.data(), uuid.data(), &hostReport, &vmReport);
    if (ret != 0) {
        VIRTRUST_LOG_ERROR("|GetExchangePkAndReport|END|returnF|domain name: {}|Get local report failed.", domainName_);
        return MigrateSessionRc::ERROR;
    }

    if (role_ == Role::Initiator) {
        req->set_domainname(domainName_);
        req->set_uuid(uuid);
        req->set_cert(certStr);
        req->set_publickey(pubKeyStr);
        auto hostReportProto = req->mutable_hostreport();
        ReportToProto(hostReport, hostReportProto);
        auto vmReportProto = req->mutable_vmreport();
        ReportToProto(vmReport, vmReportProto);
    } else {
        res->set_domainname(domainName_);
        res->set_uuid(uuid);
        res->set_cert(certStr);
        res->set_publickey(pubKeyStr);
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

    // 调用TSB API进行报告校验, 目前不对UUID进行校验
    auto ret = VerifyTrustReport(sessionId_.data(), sessionId_.data(), &hostReport, &vmReport);
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
        VIRTRUST_LOG_ERROR("|MigrateByLibvirt|END|returnF||failed to find domain: {}", domainName_);
        return MigrateSessionRc::ERROR;
    }
    auto *domainPtr = libvirt.virDomainMigrate3(domain->Get(), destConn->Get(), nullptr, 0,
                                                GetFlagCleard(flags_, MIGRATE_UNDEFINE_SOURCE));
    if (domainPtr == nullptr) {
        VIRTRUST_LOG_ERROR("|MigrateByLibvirt|END|returnF||failed to migrate domain: {}", domainName_);
        return MigrateSessionRc::ERROR;
    }
    libvirt.virDomainFree(domainPtr);

    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::GetVirConnContext(const std::string &uri, std::unique_ptr<ConnCtx> &outConn)
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

// 撤销迁移操作
void MigrationSession::UndoMigration()
{
    // 防止server端误调
    if (role_ != Role::Initiator) {
        return;
    }

    // 1.基于uri删除libvirt虚拟机
    UndefineVirtDomainBaseUri(destUri_);

    // 2.通知TSB迁移失败
    NotifyVRMigration(false);

    // 3.通知peer迁移失败，并进行清理
    OnFail();
}

// 基于uri删除libvirt虚拟机
MigrateSessionRc MigrationSession::UndefineVirtDomainBaseUri(const std::string &uri)
{
    std::unique_ptr<ConnCtx> destConn;
    auto rc = GetVirConnContext(uri, destConn);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|UndefineVirtDomainBaseUri|END|returnF||failed to get virt connect: {}", uri);
        return rc;
    }

    auto destDomain = std::make_unique<DomainCtx>(destConn, domainName_);
    if (destDomain->Get() == nullptr) {
        VIRTRUST_LOG_ERROR("|UndefineVirtDomainBaseUri|END|returnF|failed to find destDomain: {}, uri: {}", domainName_,
                           uri);
        return MigrateSessionRc::ERROR;
    }

    auto &libvirt = Libvirt::GetInstance();
    if (libvirt.virDomainUndefineFlags(destDomain->Get(), DOMAIN_UNDEFINE_NVRAM) != 0) {
        VIRTRUST_LOG_INFO("|UndefineVirtDomainBaseUri|END|returnF|undefine dest domain: {} failed, uri: {}",
                          domainName_, uri);
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
        VIRTRUST_LOG_INFO("|NotifyVRMigration|END|returnF|domainName:{}, migration statu: {}|Notify TSB failed.",
                          domainName_, success);
        return MigrateSessionRc::ERROR;
    }
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::GetVmInfo(Description &vmInfo)
{
    Description* raw = nullptr;
    int vNums = 0;
    int ret = GetVRoots(&vNums, &raw);

    std::unique_ptr<Description, void(*)(Description*)> vInfos(raw, [](Description* p){ if (p) free(p); });

    if (ret != 0 || raw == nullptr || vNums <= 0) {
        VIRTRUST_LOG_INFO("|GetVmInfo|END|returnF||Get all vm descriptions failed.");
        return MigrateSessionRc::ERROR;
    }

    const std::string& uuid = sessionId_;

    for (int i = 0; i < vNums; ++i) {
        if (std::strncmp(vInfos.get()[i].uuid, uuid.c_str(), sizeof(vInfos.get()[i].uuid)) == 0) {
            vmInfo = vInfos.get()[i];
            return MigrateSessionRc::OK;
        }
    }

    VIRTRUST_LOG_ERROR("|GetVmInfo|END|returnF|uuid: {}|VM with specified UUID not found.", uuid);
    return MigrateSessionRc::ERROR;
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
        MigrateSessionRc sendRet = SendFinishedNotify(false);
        if (sendRet != MigrateSessionRc::OK) {
            VIRTRUST_LOG_ERROR("|DomainMigrate|END|returnF| domain name: {}|SendFinishedNotify failed.", domainName_);
        }
    }

    // 进入失败状态
    EnterState(State::Failed);
}

MigrateSessionRc MigrationSession::OnMigrateRequestReceived()
{
    if (CheckMaxDomainCount() != VirtrustRc::OK) {
        EnterState(State::Failed);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }
    EnterState(State::WaitingKey);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnExchangeKeyRequestReceived(const protos::EXchangePkAndReportRequest *request,
                                                                protos::EXchangePkAndReportReply *response)
{
    if (state_ != State::WaitingKey) {
        VIRTRUST_LOG_ERROR(
            "|OnExchangeKeyRequestReceived|END|returnF|domain name: {}|Waiting for exchanging key timeout.",
            domainName_);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }

    // 1. 获取本端证书和报告
    MigrateSessionRc rc = GetExchangePkAndReport(nullptr, response);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR(
            "|OnExchangeKeyRequestReceived|END|returnF|domain name: {}|Get public key and report failed.", domainName_);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }

    // 2. 校验对端证书
    rc = VerifyCertificate(request->uuid(), request->cert(), request->publickey());
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyRequestReceived|END|returnF|domain name: {}|Verify peer cert failed.",
                           domainName_);
        Cleanup();
        return MigrateSessionRc::ERROR;
    }

    // 3. 校验对端报告
    rc = VerifyHostAndVmReport(request->hostreport(), request->vmreport());
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyRequestReceived|END|returnF|domain name: {}|Verify peer report failed.",
                           domainName_);
        Cleanup();
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
        VIRTRUST_LOG_ERROR("|OnStartMigrationRequestReceived|END|returnF|domain name: {}|Waiting for starting "
                           "migration signal timeout.",
                           domainName_);
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
        VIRTRUST_LOG_ERROR(
            "|OnTransferDataRequestReceived|END|returnF|domain name: {}|Waiting for transfering timeout.", domainName_);
        return MigrateSessionRc::ERROR;
    }
    // 导入服务端校验客户端发来的虚拟机资源信息
    auto ret = MigrationImportVrootCipher(const_cast<char *>(request->uuid().c_str()),
                                          const_cast<char *>(request->cipherdata().c_str()));
    if (ret != 0) {
        EnterState(State::Failed);
        Cleanup();
        VIRTRUST_LOG_ERROR(
            "|OnTransferDataRequestReceived|END|returnF|domain name: {}|MigrationImportVrootCipher failed.",
            domainName_);
        return MigrateSessionRc::ERROR;
    }

    // 导入服务端发来的虚拟机描述信息
    auto protosDesc = request->vtpcminfo();
    auto vmInfo = DescriptionFromProto(protosDesc);
    ret = CreateVRoot(&vmInfo);
    if (ret != 0) {
        EnterState(State::Failed);
        Cleanup();
        VIRTRUST_LOG_ERROR(
            "|OnTransferDataRequestReceived|END|returnF|domain name: {}|CreateVRoot failed.", domainName_);
        return MigrateSessionRc::ERROR;
    }

    // 刷新定时器
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
    VIRTRUST_LOG_INFO("|OnFinishedRequestReceived|END|returnS|domain name: {}|Migrate success.", domainName_);
    EnterState(State::Finished);
    Cleanup();
    return MigrateSessionRc::OK;
}
} // namespace virtrust
