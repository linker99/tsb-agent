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
// RPC timeout unit: seconds
constexpr uint32_t RPC_SIGNAL_TIMEOUT = 5;
constexpr uint32_t RPC_TRANSFER_TIMEOUT = 20;

unsigned int GetFlagCleard(const unsigned int &flags, const unsigned int &clear)
{
    return flags & ~clear;
}
} // namespace

MigrationSession *SessionManager::CreateSession(MigrationSession::Role role, const std::string &uuid,
                                                const std::string &domainName, const std::string &destUri,
                                                const std::string &localUri, const unsigned int flags)
{
    std::lock_guard<std::mutex> lock(mtx_);

    auto it = sessions_.find(uuid);
    if (it != sessions_.end()) {
        VIRTRUST_LOG_ERROR("|CreateSession|END|returnF|uuid: {}|already exists session with same uuid.", uuid);
        return nullptr;
    }

    auto session = std::make_unique<MigrationSession>(role, uuid, domainName, destUri, localUri, flags);
    MigrationSession *raw = session.get();
    sessions_[uuid] = std::move(session);
    return raw;
}

MigrationSession *SessionManager::GetSession(const std::string &uuid)
{
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = sessions_.find(uuid);
    if (it == sessions_.end()) {
        return nullptr;
    }
    return it->second.get();
}

void SessionManager::RemoveSession(const std::string &uuid)
{
    std::lock_guard<std::mutex> lock(mtx_);
    sessions_.erase(uuid);
}

MigrationSession::MigrationSession(Role role, const std::string &uuid, const std::string &domainName,
                                   const std::string &destUri, const std::string &localUri, const unsigned int flags)
    : role_(role),
      state_(State::Init),
      uuid_(uuid),
      domainName_(domainName),
      destUri_(destUri),
      localUri_(localUri),
      flags_(flags)
{}

MigrateSessionRc MigrationSession::Start()
{
    VIRTRUST_LOG_DEBUG("|Start|START|");
    if (role_ != Role::Initiator) {
        return MigrateSessionRc::ERROR;
    }
    EnterState(State::Init);
    return SendMigrateRequest();
}

MigrateSessionRc MigrationSession::SendMigrateRequest()
{
    VIRTRUST_LOG_DEBUG("|SendMigrateRequest|START|");
    if (!rpcClient_) {
        VIRTRUST_LOG_ERROR("|SendMigrateRequest|END|returnF|domain name: {}|rpc client is nullptr.", domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    protos::PrepareMigRequest req;
    req.set_uuid(uuid_);
    req.set_domainname(domainName_);

    protos::PrepareMigReply reply;

    int32_t rc = rpcClient_->PrepareMigration(RPC_SIGNAL_TIMEOUT, req, &reply);
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
    VIRTRUST_LOG_DEBUG("|OnMigrateResponseReceived|START|");
    EnterState(State::WaitingKey);
    return SendExchangeKey();
}

MigrateSessionRc MigrationSession::SendExchangeKey()
{
    VIRTRUST_LOG_DEBUG("|SendExchangeKey|START|");
    protos::EXchangePkAndReportRequest req;
    MigrateSessionRc rc = GetExchangePkAndReport(&req, nullptr);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|SendExchangeKey|END|returnF|domain name: {}|Get local cert and report failed.",
                           domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    protos::EXchangePkAndReportReply res;
    int32_t ret = rpcClient_->ExchangePkAndReport(RPC_TRANSFER_TIMEOUT, req, &res);
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
    VIRTRUST_LOG_DEBUG("|OnExchangeKeyResponseReceived|START|");
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
    rc = VerifyHostAndVmReport(res.hostreport(), res.vmreport(), false);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyResponseReceived|END|returnF|domain name: {}|Verify peer report failed.",
                           domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    // 3.导入tcm2 key
    rc = ImportTcm2Key(res.tcm2key());
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyResponseReceived|END|returnF|domain name: {}|Import tcm2 key failed.",
                           domainName_);
        OnFail();
        return MigrateSessionRc::ERROR;
    }

    return SendStartMigration();
}

MigrateSessionRc MigrationSession::SendStartMigration()
{
    VIRTRUST_LOG_DEBUG("|SendStartMigration|START|");
    protos::StartMigRequest req;
    req.set_domainname(domainName_);
    req.set_uuid(uuid_);

    protos::StartMigReply res;
    int32_t ret = rpcClient_->StartMigration(RPC_SIGNAL_TIMEOUT, req, &res);
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
    VIRTRUST_LOG_DEBUG("|OnStartMigrationResponseReceived|START|");
    char *cipher = nullptr;
    int cipherLen = 0;
    // 收集密码资源
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: MigrationGetVrootCipher start.", domainName_);
    auto ret = MigrationGetVrootCipher(uuid_.data(), uuid_.data(), &cipher, &cipherLen);
    if (ret != 0 || cipher == nullptr) {
        if (cipher != nullptr) {
            free(cipher);
        }
        VIRTRUST_LOG_ERROR(
            "|OnStartMigrationResponseReceived|END|returnF|domain name: {}|TSB: MigrationGetVRootCipher failed.",
            domainName_);
        if (ret == ERR_VM_NOT_STARTED) {
            VIRTRUST_LOG_ERROR("call MigrationGetVRootCipher failed: the VM has not been started yet.");
        }
        OnFail();
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: MigrationGetVrootCipher success.", domainName_);

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
    VIRTRUST_LOG_DEBUG("|SendTransferOnce|START|");
    MigrateSessionRc rc = MigrateByLibvirt();
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|SendTransferOnce|END|returnF||migrate by libvirt failed.");
        OnFail();
        return rc;
    }

    // 2.传输数据
    protos::VRsourceInfoRequest req;
    req.set_uuid(uuid_);
    req.set_cipherdata(cipher);
    auto protosDesc = req.mutable_vtpcminfo();
    DescriptionToProto(vmInfo, protosDesc);

    protos::VRsourceInfoReply res;
    int32_t ret = rpcClient_->SendVRsourceData(RPC_TRANSFER_TIMEOUT, req, &res);
    // 传输数据失败
    if (ret != 0) {
        VIRTRUST_LOG_ERROR("|SendTransferOnce|END|returnF||failed to tansfer data for: {}, ret {}.", domainName_, ret);
        if (ret == ERR_DUPLICATE_UUID) {
            VIRTRUST_LOG_ERROR("|SendTransferOnce|END|returnF||failed to tansfer data for: {}, already exist in dest",
                               domainName_);
        }
        UndoMigration(ret);
        return MigrateSessionRc::ERROR;
    }

    return OnTransferResponseReceived(res.result() == 0);
}

MigrateSessionRc MigrationSession::OnTransferResponseReceived(bool transferRet)
{
    // 对端校验数据失败
    VIRTRUST_LOG_DEBUG("|OnTransferResponseReceived|START|");
    if (!transferRet) {
        VIRTRUST_LOG_ERROR("|OnTransferResponseReceived|END|returnF||peer verify data faild: {}", domainName_);
        UndoMigration(0);
        return MigrateSessionRc::ERROR;
    }

    // 通知TSB迁移成功，如果调用失败，TSB虚机状态会保持 VM_MIGRATION
    auto rc = NotifyVRMigration(true);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_WARN("|OnTransferResponseReceived|END|returnF|domain name: {}|Migrate libvirt and tsb resource "
                          "success but MigrationNotify(success) failed, please resolve tsb status.",
                          domainName_);
        return MigrateSessionRc::OK;
    }

    // 所有动作执行完后，判断是否删除本地虚机
    if (flags_ & MIGRATE_UNDEFINE_SOURCE) {
        (void)UndefineVirtDomainBaseUri(localUri_);
        int tsbRet = RemoveVRoot(uuid_.data());
        if (tsbRet != 0) {
            VIRTRUST_LOG_ERROR("|OnTransferResponseReceived|END|returnF||tsb resource remove "
                               "failed, maybe not exist tsb resource uuid: "
                               "{},domainName: {}.",
                               uuid_, domainName_);
        }
    }

    // 向对端发送最终通知，忽略通知结果
    (void)SendFinishedNotify(true);
    EnterState(State::Finished);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::SendFinishedNotify(bool success)
{
    VIRTRUST_LOG_DEBUG("|SendFinishedNotify|START|");
    protos::MigrateResultRequest req;
    req.set_result(success ? 0 : 1);
    req.set_uuid(uuid_);
    protos::MigrateResultReply res;
    auto ret = rpcClient_->NotifyVRMigrateResult(RPC_SIGNAL_TIMEOUT, req, &res);
    if (ret != 0) {
        VIRTRUST_LOG_ERROR("|SendFinishedNotify|END|returnF|domain name: {}|Send notify failed.", domainName_);
        return MigrateSessionRc::ERROR;
    }
    return OnFinishedResponseReceived(res.result() == 0);
}

MigrateSessionRc MigrationSession::OnFinishedResponseReceived(bool finished)
{
    VIRTRUST_LOG_DEBUG("|OnFinishedResponseReceived|START|");
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::GetExchangePkAndReport(protos::EXchangePkAndReportRequest *req,
                                                          protos::EXchangePkAndReportReply *res)
{
    VIRTRUST_LOG_DEBUG("|GetExchangePkAndReport|START|");
    auto uuid = uuid_;
    char *cert = nullptr;
    int certLen = 0;
    char *pubKey = nullptr;
    int pubKeyLen = 0;

    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: MigrationGetCert start.", domainName_);
    int ret = MigrationGetCert(uuid.data(), &cert, &certLen, &pubKey, &pubKeyLen);
    if (ret != 0 || cert == nullptr || pubKey == nullptr) {
        if (cert != nullptr) {
            free(cert);
        }
        if (pubKey != nullptr) {
            free(pubKey);
        }
        VIRTRUST_LOG_ERROR("|GetExchangePkAndReport|END|returnF|domain name: {}|TSB: MigrationGetCert failed.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: MigrationGetCert success.", domainName_);

    std::string certStr(cert, certLen);
    std::string pubKeyStr(pubKey, pubKeyLen);
    free(cert);
    free(pubKey);

    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: GetReport start.", domainName_);
    trust_report_new hostReport;
    trust_report_new vmReport;
    ret = GetReport(uuid.data(), uuid.data(), &hostReport, &vmReport);
    if (ret != 0) {
        VIRTRUST_LOG_ERROR("|GetExchangePkAndReport|END|returnF|domain name: {}|Get local report failed.", domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: GetReport success.", domainName_);

    if (role_ == Role::Initiator) {
        if (req == nullptr) {
            VIRTRUST_LOG_ERROR("|GetExchangePkAndReport|END|returnF|domain name: {}|req is null.", domainName_);
            return MigrateSessionRc::ERROR;
        }
        req->set_domainname(domainName_);
        req->set_uuid(uuid);
        req->set_cert(certStr);
        req->set_publickey(pubKeyStr);
        auto hostReportProto = req->mutable_hostreport();
        ReportToProto(hostReport, hostReportProto);
        auto vmReportProto = req->mutable_vmreport();
        ReportToProto(vmReport, vmReportProto);
    } else {
        if (res == nullptr) {
            VIRTRUST_LOG_ERROR("|GetExchangePkAndReport|END|returnF|domain name: {}|res is null.", domainName_);
            return MigrateSessionRc::ERROR;
        }
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
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: MigrationCheckPeerPk start.", domainName_);
    int ret = MigrationCheckPeerPk(uuid.data(), cert.data(), pubkey.data());
    if (ret != 0) {
        VIRTRUST_LOG_DEBUG("|VerifyCertificate|END|returnF|domain name: {}|TSB: MigrationCheckPeerPk failed.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: MigrationCheckPeerPk success.", domainName_);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::VerifyHostAndVmReport(const protos::TrustReportNew &hostProtoReport,
                                                         const protos::TrustReportNew &vmProtoReport,
                                                         bool isDestEnd)
{
    VIRTRUST_LOG_DEBUG("|VerifyHostAndVmReport|START|");
    trust_report_new hostReport;
    bool success = ReportFromProto(hostProtoReport, hostReport);
    if (!success) {
        VIRTRUST_LOG_DEBUG("|VerifyHostAndVmReport|END|returnF|domain name: {}|TSB: report from proto failed.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }

    int ret = 0;
    // 只有目的端需要校验 vmReport，源端该参数直接传入nullptr
    if (isDestEnd) {
        trust_report_new vmReport;
        success = ReportFromProto(vmProtoReport, vmReport);
        if (!success) {
            VIRTRUST_LOG_DEBUG("|VerifyHostAndVmReport|END|returnF|domain name: {}|TSB: report from proto failed.",
                               domainName_);
            return MigrateSessionRc::ERROR;
        }
        VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: VerifyTrustReport start.", domainName_);
        ret = VerifyTrustReport(uuid_.data(), uuid_.data(), &hostReport, &vmReport);
    } else {
        ret = VerifyTrustReport(uuid_.data(), uuid_.data(), &hostReport, nullptr);
    }
    if (ret != 0) {
        VIRTRUST_LOG_DEBUG("|VerifyHostAndVmReport|END|returnF|domain name: {}|TSB: VerifyTrustReport failed.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: VerifyTrustReport success.", domainName_);
    return MigrateSessionRc::OK;
}

// 调用libvirt接口迁移
MigrateSessionRc MigrationSession::MigrateByLibvirt()
{
    VIRTRUST_LOG_DEBUG("|MigrateByLibvirt|START|");
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
    if (destConn->Get() == nullptr) {
        VIRTRUST_LOG_ERROR("|MigrateByLibvirt|END|returnF||failed to find desturl: {}", destUri_);
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
    VIRTRUST_LOG_DEBUG("|GetVirConnContext|START|");
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
void MigrationSession::UndoMigration(int32_t ret)
{
    VIRTRUST_LOG_DEBUG("|UndoMigration|START|");
    // 防止server端误调
    if (role_ != Role::Initiator) {
        return;
    }
    // 对端已存在 不删除
    if (ret != ERR_DUPLICATE_UUID) {
        // 1.基于uri删除libvirt虚拟机
        UndefineVirtDomainBaseUri(destUri_);
    }

    // 2.通知TSB迁移失败
    NotifyVRMigration(false);

    // 3.通知peer迁移失败，并进行清理
    OnFail();
}

// 基于uri删除libvirt虚拟机
MigrateSessionRc MigrationSession::UndefineVirtDomainBaseUri(const std::string &uri)
{
    VIRTRUST_LOG_DEBUG("|UndefineVirtDomainBaseUri|START|");
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
    VIRTRUST_LOG_DEBUG("|NotifyVRMigration|START|");
    auto status = success ? 0 : -1;
    auto ret = MigrationNotify(uuid_.data(), status);
    if (ret != 0) {
        VIRTRUST_LOG_INFO("|NotifyVRMigration|END|returnF|domainName:{}, migration statu: {}|Notify TSB failed.",
                          domainName_, success);
        return MigrateSessionRc::ERROR;
    }
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::GetVmInfo(Description &vmInfo)
{
    Description *raw = nullptr;
    int vNums = 0;
    int ret = GetVRoots(&vNums, &raw);

    std::unique_ptr<Description, void (*)(Description *)> vInfos(raw, [](Description *p) {
        if (p)
            free(p);
    });

    if (ret != 0 || raw == nullptr || vNums <= 0) {
        VIRTRUST_LOG_INFO("|GetVmInfo|END|returnF||Get all vm descriptions failed.");
        return MigrateSessionRc::ERROR;
    }

    const std::string &uuid = uuid_;

    for (int i = 0; i < vNums; ++i) {
        if (std::strncmp(vInfos.get()[i].uuid, uuid.c_str(), sizeof(vInfos.get()[i].uuid)) == 0) {
            vmInfo = vInfos.get()[i];
            return MigrateSessionRc::OK;
        }
    }

    VIRTRUST_LOG_ERROR("|GetVmInfo|END|returnF|uuid: {}|VM with specified UUID not found.", uuid);
    return MigrateSessionRc::ERROR;
}

MigrateSessionRc MigrationSession::ExportTcm2Key(std::string &tcm2Key)
{
    char *key = nullptr;
    int keyLen = 0;

    VIRTRUST_LOG_DEBUG("|domain name: {} |TSB: TransDupPub export start.", domainName_);
    auto ret = TransDupPub(EN_EXPORT, nullptr, &key, &keyLen, nullptr, 0);
    if (ret != 0 || key == nullptr || keyLen <= 0) {
        if (key != nullptr) {
            free(key);
        }
        VIRTRUST_LOG_ERROR("|ExportTcm2Key|END|returnF|domain name: {} |TSB: TransDupPub export failed.", domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {} |TSB: TransDupPub export success.", domainName_);

    tcm2Key = std::string(key, keyLen);
    free(key);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::ImportTcm2Key(std::string_view tcm2Key)
{
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: TransDupPub import start.", domainName_);
    auto ret = TransDupPub(EN_IMPORT, uuid_.data(), nullptr, nullptr, std::string(tcm2Key).data(), tcm2Key.size());
    if (ret != 0) {
        VIRTRUST_LOG_ERROR("|ImportTcm2Key|END|returnF|domain name: {}|TSB: TransDupPub import failed.", domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: TransDupPub import success.", domainName_);

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
    VIRTRUST_LOG_DEBUG("|Cleanup|START|uuid: {}", uuid_);
    SessionManager::GetInstance().RemoveSession(uuid_);
}

void MigrationSession::OnFail()
{
    VIRTRUST_LOG_DEBUG("|OnFail|START|");
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
    VIRTRUST_LOG_DEBUG("|OnMigrateRequestReceived|START|");
    if (CheckMaxDomainCount() != VirtrustRc::OK) {
        EnterState(State::Failed);
        return MigrateSessionRc::ERROR;
    }
    EnterState(State::WaitingKey);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnExchangeKeyRequestReceived(const protos::EXchangePkAndReportRequest *request,
                                                                protos::EXchangePkAndReportReply *response)
{
    VIRTRUST_LOG_DEBUG("|OnExchangeKeyRequestReceived|START|");
    if (state_ != State::WaitingKey) {
        VIRTRUST_LOG_ERROR(
            "|OnExchangeKeyRequestReceived|END|returnF|domain name: {}|Waiting for exchanging key timeout.",
            domainName_);
        return MigrateSessionRc::ERROR;
    }

    // 1. 获取本端证书和报告
    MigrateSessionRc rc = GetExchangePkAndReport(nullptr, response);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR(
            "|OnExchangeKeyRequestReceived|END|returnF|domain name: {}|Get public key and report failed.", domainName_);
        return MigrateSessionRc::ERROR;
    }

    // 2. 校验对端证书
    rc = VerifyCertificate(request->uuid(), request->cert(), request->publickey());
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyRequestReceived|END|returnF|domain name: {}|Verify peer cert failed.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }

    // 3. 校验对端报告
    rc = VerifyHostAndVmReport(request->hostreport(), request->vmreport(), true);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyRequestReceived|END|returnF|domain name: {}|Verify peer report failed.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }

    // 4. 导出tcm2密钥，返回给源
    std::string tcm2Key;
    rc = ExportTcm2Key(tcm2Key);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_ERROR("|OnExchangeKeyRequestReceived|END|returnF|domain name: {}|Export tcm2 key failed.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }
    response->set_tcm2key(tcm2Key);

    // 等待对端校验证书后的进一步信号：开始迁移信号
    EnterState(State::CertVerify);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnStartMigrationRequestReceived()
{
    VIRTRUST_LOG_DEBUG("|OnStartMigrationRequestReceived|START|");
    if (state_ != State::CertVerify) {
        VIRTRUST_LOG_ERROR("|OnStartMigrationRequestReceived|END|returnF|domain name: {}|Waiting for starting "
                           "migration signal timeout.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }

    // 等待对端发起数据传数
    EnterState(State::Transferring);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnTransferDataRequestReceived(const protos::VRsourceInfoRequest *request,
                                                                 int32_t &result)
{
    VIRTRUST_LOG_DEBUG("|OnTransferDataRequestReceived|START|");
    if (state_ != State::Transferring) {
        VIRTRUST_LOG_ERROR(
            "|OnTransferDataRequestReceived|END|returnF|domain name: {}|Waiting for transfering timeout.", domainName_);
        return MigrateSessionRc::ERROR;
    }

    // 导入服务端校验客户端发来的虚拟机资源信息
    auto uuid = request->uuid();
    auto cipherData = request->cipherdata();

    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: MigrationImportVrootCipher start", domainName_);
    auto ret = MigrationImportVrootCipher(uuid.data(), uuid.data(), cipherData.data(), cipherData.size());
    if (ret != 0) {
        EnterState(State::Failed);
        VIRTRUST_LOG_ERROR(
            "|OnTransferDataRequestReceived|END|returnF|domain name: {}|TSB: MigrationImportVrootCipher failed.",
            domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: MigrationImportVrootCipher success.", domainName_);

    // 导入服务端发来的虚拟机描述信息
    auto protosDesc = request->vtpcminfo();
    Description vmInfo;
    bool success = DescriptionFromProto(protosDesc, vmInfo);
    if (!success) {
        EnterState(State::Failed);
        VIRTRUST_LOG_ERROR(
            "|OnTransferDataRequestReceived|END|returnF|domain name: {}|TSB: description from proto failed.",
            domainName_);
        return MigrateSessionRc::ERROR;
    }
    vmInfo.state = VM_SHUTUP;
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: CreateVRoot start", domainName_);
    ret = CreateVRoot(&vmInfo);
    if (ret != 0) {
        result = ret;
        EnterState(State::Failed);
        VIRTRUST_LOG_ERROR("|OnTransferDataRequestReceived|END|returnF|domain name: {}|TSB: CreateVRoot failed.",
                           domainName_);
        return MigrateSessionRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|domain name: {}|TSB: CreateVRoot success", domainName_);

    // 刷新定时器
    EnterState(State::Transferring);
    return MigrateSessionRc::OK;
}

MigrateSessionRc MigrationSession::OnFinishedRequestReceived(bool finished)
{
    VIRTRUST_LOG_DEBUG("|OnFinishedRequestReceived|START|");
    if (role_ != Role::Responder) {
        return MigrateSessionRc::ERROR;
    }
    if (!finished) {
        VIRTRUST_LOG_ERROR("|OnFinishedRequestReceived|END|returnF|domain name: {}|Migrate failed.", domainName_);
        Cleanup();
        return MigrateSessionRc::OK;
    }
    VIRTRUST_LOG_DEBUG("|OnFinishedRequestReceived|END|returnS|domain name: {}|Migrate success.", domainName_);

    // 通知TSB迁移成功，如果调用失败，TSB虚机状态会保持 VM_MIGRATION
    auto rc = NotifyVRMigration(true);
    if (rc != MigrateSessionRc::OK) {
        VIRTRUST_LOG_WARN("|OnFinishedRequestReceived|END|returnF|domain name: {}|Migrate libvirt and tsb resource "
                          "success but MigrationNotify(success) failed, please resolve tsb status.",
                          domainName_);
        return MigrateSessionRc::OK;
    }

    EnterState(State::Finished);
    Cleanup();
    return MigrateSessionRc::OK;
}
} // namespace virtrust
