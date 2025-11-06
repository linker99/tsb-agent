/*
* Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <grpcpp/grpcpp.h>

#include <string>
#include "migration_service_impl.h"

namespace virtrust {
    // 给virsh-sh命令行使用
    class UdsClient
    {
    public:
        explicit UdsClient(LinkConfig config);

        int32_t DomainMigrate(const std::string &domainName);

    private:
        LinkConfig config_;
    };


    // 守护进程之间使用
    class RpcClient
    {
    public:
        explicit RpcClient(LinkConfig config);

        int32_t PrepareMigration(uint32_t timeout, const protos::PrepareMigRequest& request, protos::PrepareMigReply* response);

        // 2: 交换公钥
        int32_t ExchangePkAndReport(uint32_t timeout,  const protos::EXchangePkAndReportRequest& request, protos::EXchangePkAndReportReply* response);

        // 3: 开始迁移
        int32_t StartMigration(uint32_t timeout,  const protos::StartMigRequest& request, protos::StartMigReply* response);

        // 4：迁移虚机密码资源
        int32_t SendVRsourceData(uint32_t timeout,  const protos::VRsourceInfoRequest& request, protos::VRsourceInfoReply* response);

        // 5: 通知迁移结果
        int32_t NotifyVRMigrateResult(uint32_t timeout,  const protos::MigrateResultRequest& request, protos::MigrateResultReply* response);

    private:
        LinkConfig config_;
    };


}