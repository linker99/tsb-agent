/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include "virtrust/link/grpc_client.h"

#include <grpcpp/grpcpp.h>

#include <memory>
#include <string>

#include "virtrust/base/str_utils.h"
#include "virtrust/link/defines.h"

namespace virtrust {
UdsClient::UdsClient(LinkConfig config) : config_(config)
{}

int32_t UdsClient::DomainMigrate(const MigrationConfig &config)
{
    protos::DomainMigraterRequest request;
    request.set_domainname(config.domainName);
    request.set_uuid(config.uuid);
    request.set_desturi(config.destUri);
    request.set_localuri(config.localUri);
    request.set_flags(config.flags);
    // Container for the response from the server.
    protos::DomainMigraterReply reply;

    // Context for the client.
    grpc::ClientContext context;

    // The actual RPC.
    std::shared_ptr<grpc::Channel> channel =
        grpc::CreateChannel("unix:" + config_.udsPath, grpc::InsecureChannelCredentials());

    std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);
    grpc::Status status = stub->DomainMigrate(&context, request, &reply);

    if (!status.ok()) {
        VIRTRUST_LOG_ERROR("|DomainMigrate|END|returnF|fail to triggle DomainMigrate:{}, serverAddress is: {}",
                           status.error_message(), config_.udsPath);
        return -1;
    }
    return reply.result();
}

RpcClient::RpcClient(LinkConfig config) : config_(config)
{}

int32_t RpcClient::PrepareMigration(uint32_t timeout, const protos::PrepareMigRequest &request,
                                    protos::PrepareMigReply *response)
{
    std::string serverAddress = config_.ip + ":" + std::to_string(config_.port);
    // 创建 SSL 凭证
    auto channel_creds = grpc::InsecureChannelCredentials();
    if (!config_.caPath.empty() && !config_.certPath.empty() && !config_.skPath.empty()) {
        VIRTRUST_LOG_DEBUG("|PrepareMigration|||Connect in certificate form");
        grpc::SslCredentialsOptions ssl_opts;
        ssl_opts.pem_root_certs = ReadFile(config_.caPath);
        // 设置客户端证书（如果需要）
        ssl_opts.pem_private_key = ReadFile(config_.skPath);
        ssl_opts.pem_cert_chain = ReadFile(config_.certPath);
        channel_creds = grpc::SslCredentials(ssl_opts);
    }

    std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(serverAddress, channel_creds);
    std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);

    // 创建 ClientContext
    grpc::ClientContext context;

    // 设置超时
    auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(timeout);
    context.set_deadline(deadline);
    grpc::Status status = stub->PrepareMigration(&context, request, response);
    if (!status.ok()) {
        VIRTRUST_LOG_ERROR("|PrepareMigration|END|returnF|fail to triggle prepare migration:{}, serverAddress is: {}",
                           status.error_message(), serverAddress);
        return -1;
    }
    return response->result();
}

// 2: 交换公钥
int32_t RpcClient::ExchangePkAndReport(uint32_t timeout, const protos::EXchangePkAndReportRequest &request,
                                       protos::EXchangePkAndReportReply *response)
{
    std::string serverAddress = config_.ip + ":" + std::to_string(config_.port);

    // 创建 SSL 凭证
    auto channel_creds = grpc::InsecureChannelCredentials();
    if (!config_.caPath.empty() && !config_.certPath.empty() && !config_.skPath.empty()) {
        VIRTRUST_LOG_DEBUG("|ExchangePkAndReport|||Connect in certificate form");
        grpc::SslCredentialsOptions ssl_opts;
        ssl_opts.pem_root_certs = ReadFile(config_.caPath);
        // 设置客户端证书（如果需要）
        ssl_opts.pem_private_key = ReadFile(config_.skPath);
        ssl_opts.pem_cert_chain = ReadFile(config_.certPath);
        channel_creds = grpc::SslCredentials(ssl_opts);
    }

    std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(serverAddress, channel_creds);
    std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);

    // 创建 ClientContext
    grpc::ClientContext context;

    // 设置超时
    auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(timeout);
    context.set_deadline(deadline);
    grpc::Status status = stub->ExchangePkAndReport(&context, request, response);
    if (!status.ok()) {
        VIRTRUST_LOG_ERROR(
            "|ExchangePkAndReport|END|returnF|fail to triggle exchange pkandReport:{}, serverAddress is: {}",
            status.error_message(), serverAddress);
        return -1;
    }
    return response->result();
}

// 3: 开始迁移
int32_t RpcClient::StartMigration(uint32_t timeout, const protos::StartMigRequest &request,
                                  protos::StartMigReply *response)
{
    std::string serverAddress = config_.ip + ":" + std::to_string(config_.port);
    // 创建 SSL 凭证
    auto channel_creds = grpc::InsecureChannelCredentials();
    if (!config_.caPath.empty() && !config_.certPath.empty() && !config_.skPath.empty()) {
        VIRTRUST_LOG_DEBUG("|StartMigration|||Connect in certificate form");
        grpc::SslCredentialsOptions ssl_opts;
        ssl_opts.pem_root_certs = ReadFile(config_.caPath);
        // 设置客户端证书（如果需要）
        ssl_opts.pem_private_key = ReadFile(config_.skPath);
        ssl_opts.pem_cert_chain = ReadFile(config_.certPath);
        channel_creds = grpc::SslCredentials(ssl_opts);
    }

    std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(serverAddress, channel_creds);
    std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);

    // 创建 ClientContext
    grpc::ClientContext context;

    // 设置超时
    auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(timeout);
    context.set_deadline(deadline);
    grpc::Status status = stub->StartMigration(&context, request, response);
    if (!status.ok()) {
        VIRTRUST_LOG_ERROR("|StartMigration|END|returnF|fail to triggle start migration:{}, serverAddress is: {}",
                           status.error_message(), serverAddress);
        return -1;
    }
    return response->result();
}

// 4：迁移虚机密码资源
int32_t RpcClient::SendVRsourceData(uint32_t timeout, const protos::VRsourceInfoRequest &request,
                                    protos::VRsourceInfoReply *response)
{
    std::string serverAddress = config_.ip + ":" + std::to_string(config_.port);
    // 创建 SSL 凭证
    auto channel_creds = grpc::InsecureChannelCredentials();
    if (!config_.caPath.empty() && !config_.certPath.empty() && !config_.skPath.empty()) {
        VIRTRUST_LOG_DEBUG("|SendVRsourceData|||Connect in certificate form");
        grpc::SslCredentialsOptions ssl_opts;
        ssl_opts.pem_root_certs = ReadFile(config_.caPath);
        // 设置客户端证书（如果需要）
        ssl_opts.pem_private_key = ReadFile(config_.skPath);
        ssl_opts.pem_cert_chain = ReadFile(config_.certPath);
        channel_creds = grpc::SslCredentials(ssl_opts);
    }

    std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(serverAddress, channel_creds);
    std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);

    // 创建 ClientContext
    grpc::ClientContext context;

    // 设置超时
    auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(timeout);
    context.set_deadline(deadline);
    grpc::Status status = stub->SendVRsourceData(&context, request, response);
    if (!status.ok()) {
        VIRTRUST_LOG_ERROR("|SendVRsourceData|END|returnF|fail to triggle send vrsourceData:{}, serverAddress is: {}",
                           status.error_message(), serverAddress);
        return -1;
    }
    return response->result();
}

// 5: 通知迁移结果
int32_t RpcClient::NotifyVRMigrateResult(uint32_t timeout, const protos::MigrateResultRequest &request,
                                         protos::MigrateResultReply *response)
{
    std::string serverAddress = config_.ip + ":" + std::to_string(config_.port);
    // 创建 SSL 凭证
    auto channel_creds = grpc::InsecureChannelCredentials();
    if (!config_.caPath.empty() && !config_.certPath.empty() && !config_.skPath.empty()) {
        VIRTRUST_LOG_DEBUG("|NotifyVRMigrateResult|||Connect in certificate form");
        grpc::SslCredentialsOptions ssl_opts;
        ssl_opts.pem_root_certs = ReadFile(config_.caPath);
        // 设置客户端证书（如果需要）
        ssl_opts.pem_private_key = ReadFile(config_.skPath);
        ssl_opts.pem_cert_chain = ReadFile(config_.certPath);
        channel_creds = grpc::SslCredentials(ssl_opts);
    }

    std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(serverAddress, channel_creds);
    std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);

    // 创建 ClientContext
    grpc::ClientContext context;

    // 设置超时
    auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(timeout);
    context.set_deadline(deadline);
    grpc::Status status = stub->NotifyVRMigrateResult(&context, request, response);
    if (!status.ok()) {
        VIRTRUST_LOG_ERROR(
            "|NotifyVRMigrateResult|END|returnF|fail to triggle NotifyVRMigrateResult :{}, serverAddress is: {}",
            status.error_message(), serverAddress);
        return -1;
    }
    return response->result();
}
}; // namespace virtrust