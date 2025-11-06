/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

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

    enum class State {
        Init,
        WaitingKey,
        Transferring,
        Finished,
        Failed
    };

    MigrationSession(Role role, const std::string &sessionId, const std::string &domainName,
                     const std::string &destUri = "");

    // 主动方起步
    MigrateSessionRc Start();

    // 定时器触发时调用
    void OnTimeout(State stateWhenSet);

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

    MigrateSessionRc OnExchangeKeyRequestReceived(const std::string &peerPubKey);

    MigrateSessionRc OnStartMigrationRequestReceived(const std::string &domainName);

    MigrateSessionRc OnTransferDataRequestReceived(const std::string &vmData, bool finished);

    MigrateSessionRc OnFinishedRequestReceived(const std::string &vmData, bool finished);

private:
    // 这几个是收到对端应答时要调用的
    MigrateSessionRc OnMigrateResponseReceived(bool agree);

    MigrateSessionRc OnExchangeKeyResponseReceived(const std::string &peerReport, const std::string &peerPubKey);

    MigrateSessionRc OnStartMigrationResponseReceived(bool agree);

    MigrateSessionRc OnTransferResponseReceived(bool finished);

    MigrateSessionRc OnFinishedResponseReceived(bool finished);

    void EnterState(State s);

    void StartTimerFor(State s);

    void CancelTimer();

    // 主动方要发的几步
    MigrateSessionRc SendMigrateRequest();

    MigrateSessionRc SendExchangeKey();

    MigrateSessionRc SendStartMigration();

    MigrateSessionRc SendTransferOnce();

    MigrateSessionRc SendFinishedNotify();

private:
    Role role_;
    State state_;
    std::string sessionId_;
    std::string domainName_;
    std::string destUri_;

    std::string myPubKey_;
    std::string peerPubKey_;

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
                                    const std::string &domainName, const std::string &destUri);

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

} // namespace virtrust
