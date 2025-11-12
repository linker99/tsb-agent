/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <grpcpp/grpcpp.h>

#include <memory>
#include <thread>

#include "virtrust/link/defines.h"

namespace virtrust {
class GrpcServer {
public:
    explicit GrpcServer(LinkConfig config);

    LinkRc Start();
    void Stop();

private:
    void RunServer();

    LinkConfig config_;
    std::atomic<bool> running_{false};

    std::unique_ptr<grpc::Server> server_;
    std::unique_ptr<std::thread> server_thread_;
};
} // namespace virtrust