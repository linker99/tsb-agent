/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "tsb_agent/tsb_agent.h"

#include "virtrust/api/context.h"
#include "virtrust/link/grpc_client.h"
#include "virtrust/utils/async_timer.h"

namespace virtrust {

enum class MigrateSessionRc : uint32_t {
    OK = 0,
    ERROR = 1,
};

class MigrationSession {
public:
    enum class Role {
        Initiator, // 客户端状态
        Responder  // 服务端状态
    };

    enum class State { Init, WaitingKey, CertVerify, Transferring, Finished, Failed };

    MigrationSession(Role role, const std::string &sessionId, const std::string &domainName,
                     const std::string &destUri = "", const std::string &localUri = "", const unsigned int flags = 0);

    // 主动方起步
    MigrateSessionRc Start();

    // 定时器触发时调用
    void OnTimeout(State stateWhenSet);

    // 失败时调用：状态设置为失败，并进行清理
    void OnFail();

    // 让manager删掉自己
    void Cleanup();

    const std::string &Id() const
    {
        return sessionId_;
    }

    // 仅 Initiator 使用：注入 RPC 客户端（会话拥有其生命周期）
    void SetRpcClient(std::unique_ptr<RpcClient> rpc)
    {
        rpcClient_ = std::move(rpc);
    }

    // 响应方使用
    MigrateSessionRc OnMigrateRequestReceived();

    MigrateSessionRc OnExchangeKeyRequestReceived(const protos::EXchangePkAndReportRequest *request,
                                                  protos::EXchangePkAndReportReply *response);

    MigrateSessionRc OnStartMigrationRequestReceived();

    MigrateSessionRc OnTransferDataRequestReceived(const protos::VRsourceInfoRequest *request, int32_t &result);

    MigrateSessionRc OnFinishedRequestReceived(bool finished);

private:
    // 这几个是收到对端应答时要调用的
    MigrateSessionRc OnMigrateResponseReceived();

    MigrateSessionRc OnExchangeKeyResponseReceived(protos::EXchangePkAndReportReply &res);

    MigrateSessionRc OnStartMigrationResponseReceived();

    MigrateSessionRc OnTransferResponseReceived(bool finished);

    MigrateSessionRc OnFinishedResponseReceived(bool finished);

    void EnterState(State s);

    void StartTimerFor(State s);

    void CancelTimer();

    // 主动方要发的几步
    MigrateSessionRc SendMigrateRequest();

    MigrateSessionRc SendExchangeKey();

    MigrateSessionRc SendStartMigration();

    MigrateSessionRc SendTransferOnce(const std::string &cipher, const Description &vmInfo);

    MigrateSessionRc SendFinishedNotify(bool success);

    // 辅助函数
    MigrateSessionRc GetExchangePkAndReport(protos::EXchangePkAndReportRequest *req,
                                            protos::EXchangePkAndReportReply *res);

    MigrateSessionRc VerifyCertificate(std::string uuid, std::string cert, std::string pubkey);

    MigrateSessionRc VerifyHostAndVmReport(const protos::TrustReportNew &hostReport,
                                           const protos::TrustReportNew &vmReport);

    MigrateSessionRc GetVmInfo(Description &vmInfo);

    MigrateSessionRc MigrateByLibvirt();

    MigrateSessionRc GetVirConnContext(const std::string &uri, std::unique_ptr<ConnCtx> &outConn);

    void UndoMigration(int32_t result);

    MigrateSessionRc UndefineVirtDomainBaseUri(const std::string &uri);

    MigrateSessionRc NotifyVRMigration(bool success);

    MigrateSessionRc ExportTcm2Key(std::string &tcm2Key);

    MigrateSessionRc ImportTcm2Key(std::string_view tcm2Key);

private:
    Role role_;
    State state_;
    std::string sessionId_;
    std::string domainName_;
    std::string destUri_;
    std::string localUri_;
    unsigned int flags_;

    // 仅 Initiator 侧使用
    std::unique_ptr<RpcClient> rpcClient_;

    std::atomic<bool> timerActive_{false};

    AsyncTimer timer_;
};

class SessionManager {
public:
    static SessionManager &GetInstance()
    {
        static SessionManager instance;
        return instance;
    }

    // 禁止拷贝和移动
    SessionManager(const SessionManager &) = delete;

    SessionManager &operator=(const SessionManager &) = delete;

    // 创建并托管一个会话，返回裸指针，所有权仍在manager内
    MigrationSession *CreateSession(MigrationSession::Role role, const std::string &sessionId,
                                    const std::string &domainName, const std::string &destUri,
                                    const std::string &localUri, const unsigned int flags);

    // 查找会话（比如 gRPC handler 用这个）
    MigrationSession *GetSession(const std::string &sessionId);

    // 会话结束时调用，真正删除
    void RemoveSession(const std::string &sessionId);

private:
    SessionManager() = default;

    ~SessionManager() = default;

    std::mutex mtx_;

    std::unordered_map<std::string, std::unique_ptr<MigrationSession>> sessions_;
};

struct EXchangePkAndReport {
    std::string domainName;
    std::string uuid;
    std::string cert;
    std::string pubKey;
    std::string hostReport;
    std::string vmReport;
};

} // namespace virtrust
