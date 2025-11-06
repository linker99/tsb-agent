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

class SessionManager;

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

    MigrationSession(Role role, const std::string &sessionId);

    // 主动方起步
    void Start();

    // 这几个是收到对端应答时要调用的
    void OnMigrateResponseReceived(bool agree);

    void OnExchangeKeyResponseReceived(const std::string &peerPubKey);

    void OnStartMigrationResponseReceived(bool agree);

    void OnTransferResponseReceived(bool finished);

    void OnFinishedResponseReceived(bool finished);

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
    void OnMigrateRequestReceived(const std::string &domainName);

    void OnExchangeKeyRequestReceived(const std::string &peerPubKey);

    void OnStartMigrationRequestReceived(const std::string &domainName);

    void OnTransferDataRequestReceived(const std::string &vmData, bool finished);

    void OnFinishedRequestReceived(const std::string &vmData, bool finished);

private:
    void EnterState(State s);

    void StartTimerFor(State s);

    void CancelTimer();

    // 主动方要发的几步
    void SendMigrateRequest();

    void SendExchangeKey();

    void SendStartMigration();

    void SendTransferOnce();

    void SendFinishedNotify();

private:
    Role role_;
    State state_;
    std::string sessionId_;

    std::string myPubKey_;
    std::string peerPubKey_;

    // 仅 Initiator 侧使用
    std::unique_ptr<RpcClient> rpcClient_;

    State timerForState_;
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
    MigrationSession *CreateSession(const std::string &sessionId, MigrationSession::Role role);

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
