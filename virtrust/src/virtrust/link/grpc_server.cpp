/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include "virtrust/link/grpc_server.h"

#include "virtrust/base/logger.h"
#include "virtrust/base/str_utils.h"
#include "virtrust/link/defines.h"
#include "virtrust/link/migration_service_impl.h"

#include "virtrust/link/proto/migrate.grpc.pb.h"

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
    std::this_thread::sleep_for(std::chrono::seconds(2)); // 2秒之后启动

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
        std::string serverAddress = config_.ip + ":" + std::to_string(config_.port);
        grpc::EnableDefaultHealthCheckService(true);
        grpc::reflection::InitProtoReflectionServerBuilderPlugin();

        grpc::ServerBuilder builder;
        auto server_creds = grpc::InsecureServerCredentials();
        // 创建 SSL 凭证
        if (!config_.skPath.empty() && !config_.certPath.empty() && !config_.caPath.empty()) {
            VIRTRUST_LOG_DEBUG("|RunServer|||Start in certificate");
            grpc::SslServerCredentialsOptions::PemKeyCertPair key_cert_pair;
            key_cert_pair.private_key = ReadFile(config_.skPath);
            key_cert_pair.cert_chain = ReadFile(config_.certPath);

            grpc::SslServerCredentialsOptions ssl_opts;
            ssl_opts.client_certificate_request = GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
            ssl_opts.pem_key_cert_pairs.push_back(key_cert_pair);
            ssl_opts.pem_root_certs = ReadFile(config_.caPath);
            server_creds = grpc::SslServerCredentials(ssl_opts);
        }

        // 监听tcp地址
        builder.AddListeningPort(serverAddress, server_creds);
        // 监听uds地址
        builder.AddListeningPort("unix:" + config_.udsPath, grpc::InsecureServerCredentials());
        builder.RegisterService(&service);

        server_ = builder.BuildAndStart();
        if (!server_) {
            VIRTRUST_LOG_ERROR("|RunServer|END|returnF|rpc buildAndStart failed");
            return;
        }

        running_ = true;
        server_->Wait();
    } catch (const std::exception &e) {
        running_ = false;
    }
}

} // namespace virtrust
