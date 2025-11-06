/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include "virtrust/link/grpc_server.h"

#include "migration_service_impl.h"

#include "virtrust/base/logger.h"
#include "virtrust/link/defines.h"

#include "proto/migrate.grpc.pb.h"

namespace virtrust {
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

GrpcServer::GrpcServer(LinkConfig config) : config_(config)
{}

LinkRc GrpcServer::Start()
{
    if (running_) {
        return LinkRc::ERROR;
    }
    ::unlink(config_.udsPath.c_str());
    server_thread_ = std::make_unique<std::thread>([this]() { RunServer(); });

    // 等待服务器启动
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    if (!running_) {
        return LinkRc::ERROR;
    }
    return LinkRc::OK;
}

void GrpcServer::Stop()
{
    if (!running_) {
        return;
    }
    if (server_) {
        server_->Shutdown();
        server_.reset();
    }
    if (server_thread_ && server_thread_->joinable()) {
        server_thread_->join();
        server_thread_.reset();
    }

    // 清理 UDS 文件
    ::unlink(config_.udsPath.c_str());
    running_ = false;
}

void GrpcServer::RunServer()
{
    try {
        MigrationServiceImpl service;
        std::string serverAddress = "0.0.0.0:" + std::to_string(config_.port);
        grpc::EnableDefaultHealthCheckService(true);
        grpc::reflection::InitProtoReflectionServerBuilderPlugin();

        grpc::ServerBuilder builder;
        // 监听tcp地址
        builder.AddListeningPort(serverAddress, grpc::InsecureServerCredentials());
        // 监听uds地址
        builder.AddListeningPort("unix:" + config_.udsPath, grpc::InsecureServerCredentials());

        builder.RegisterService(&service);
        server_ = builder.BuildAndStart();
        if (!server_) {
            // LOG
            return;
        }
        running_ = true;
        server_->Wait();
    } catch (const std::exception &e) {
        running_ = false;
    }
}

} // namespace virtrust
