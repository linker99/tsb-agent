#include <grpcpp/grpcpp.h>

#include <iostream>
#include <memory>
#include <string>
#include <fstream>
#include "grpc_client.h"

namespace virtrust {
    UdsClient::UdsClient(LinkConfig config):config_(config){}

    int32_t UdsClient::DomainMigrate(const std::string &domainName) {
        protos::DomainMigraterRequest request;
        request.set_domainname(domainName);

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
            return -1;
        }
        return reply.result();
    }

    RpcClient::RpcClient(LinkConfig config):config_(config) {}

    int32_t RpcClient::PrepareMigration(uint32_t timeout,  const protos::PrepareMigRequest& request, protos::PrepareMigReply* response) {
        std::string serverAddress = config_.ip + ":" + std::to_string(config_.port);

        std::shared_ptr<grpc::Channel> channel =
            grpc::CreateChannel(serverAddress, grpc::InsecureChannelCredentials());
        std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);

        // 创建 ClientContext
        grpc::ClientContext context;

        // 设置超时
        auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(timeout);
        context.set_deadline(deadline);
        grpc::Status status = stub->PrepareMigration(&context, request, response);
        if (!status.ok()) {
            return -1;
        }
        return response->result();
    }


    // 2: 交换公钥
    int32_t RpcClient::ExchangePkAndReport(uint32_t timeout,  const protos::EXchangePkAndReportRequest& request, protos::EXchangePkAndReportReply* response) {
        std::string serverAddress = config_.ip + ":" + std::to_string(config_.port);

        std::shared_ptr<grpc::Channel> channel =
            grpc::CreateChannel(serverAddress, grpc::InsecureChannelCredentials());
        std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);

        // 创建 ClientContext
        grpc::ClientContext context;

        // 设置超时
        auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(timeout);
        context.set_deadline(deadline);
        grpc::Status status = stub->ExchangePkAndReport(&context, request, response);
        if (!status.ok()) {
            return -1;
        }
        return response->result();
    }

    // 3: 开始迁移
    int32_t RpcClient::StartMigration(uint32_t timeout,  const protos::StartMigRequest& request, protos::StartMigReply* response) {
        std::string serverAddress = config_.ip + ":" + std::to_string(config_.port);

        std::shared_ptr<grpc::Channel> channel =
            grpc::CreateChannel(serverAddress, grpc::InsecureChannelCredentials());
        std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);

        // 创建 ClientContext
        grpc::ClientContext context;

        // 设置超时
        auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(timeout);
        context.set_deadline(deadline);
        grpc::Status status = stub->StartMigration(&context, request, response);
        if (!status.ok()) {
            return -1;
        }
        return response->result();
    }

    // 4：迁移虚机密码资源
    int32_t RpcClient::SendVRsourceData(uint32_t timeout,  const protos::VRsourceInfoRequest& request, protos::VRsourceInfoReply* response) {
        std::string serverAddress = config_.ip + ":" + std::to_string(config_.port);

        std::shared_ptr<grpc::Channel> channel =
            grpc::CreateChannel(serverAddress, grpc::InsecureChannelCredentials());
        std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);

        // 创建 ClientContext
        grpc::ClientContext context;

        // 设置超时
        auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(timeout);
        context.set_deadline(deadline);
        grpc::Status status = stub->SendVRsourceData(&context, request, response);
        if (!status.ok()) {
            return -1;
        }
        return response->result();
    }

    // 5: 通知迁移结果
    int32_t RpcClient::NotifyVRMigrateResult(uint32_t timeout,  const protos::MigrateResultRequest& request, protos::MigrateResultReply* response) {
        std::string serverAddress = config_.ip + ":" + std::to_string(config_.port);

        std::shared_ptr<grpc::Channel> channel =
            grpc::CreateChannel(serverAddress, grpc::InsecureChannelCredentials());
        std::unique_ptr<protos::MigrationService::Stub> stub = protos::MigrationService::NewStub(channel);

        // 创建 ClientContext
        grpc::ClientContext context;

        // 设置超时
        auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(timeout);
        context.set_deadline(deadline);
        grpc::Status status = stub->NotifyVRMigrateResult(&context, request, response);
        if (!status.ok()) {
            return -1;
        }
        return response->result();
    }
};