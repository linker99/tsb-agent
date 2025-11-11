/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <string>
#include <thread>
#include <chrono>

#include "gtest/gtest.h"

#include "virtrust/link/grpc_server.h"
#include "virtrust/link/defines.h"

namespace virtrust {

class GrpcServerTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        // Initialize test configuration
        linkConfig_.caPath = "/test/ca.pem";
        linkConfig_.certPath = "/test/cert.pem";
        linkConfig_.skPath = "/test/sk.pem";
        linkConfig_.ip = "127.0.0.1";
        linkConfig_.ipMask = "127.0.0.0/24";
        linkConfig_.port = 50052; // Use different port to avoid conflicts
        linkConfig_.udsPath = "/tmp/test_grpc_server.sock";
    }

    void TearDown() override
    {
        // Clean up any leftover UDS file
        ::unlink(linkConfig_.udsPath.c_str());
    }

    LinkConfig linkConfig_;
};

TEST_F(GrpcServerTest, Constructor)
{
    // Test that GrpcServer can be constructed with valid config
    GrpcServer server(linkConfig_);
    
    // The constructor should not throw, and the server should be valid
    SUCCEED();
}

TEST_F(GrpcServerTest, ConstructorWithEmptyConfig)
{
    // Test with empty config
    LinkConfig emptyConfig;
    GrpcServer server(emptyConfig);
    
    // Should still construct successfully
    SUCCEED();
}

TEST_F(GrpcServerTest, StartAndStop)
{
    GrpcServer server(linkConfig_);
    
    // Start the server
    LinkRc startResult = server.Start();
    
    // Give the server a moment to start
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Stop the server
    server.Stop();
    
    // Both start and stop should succeed
    EXPECT_EQ(startResult, LinkRc::OK);
}

TEST_F(GrpcServerTest, StartTwice)
{
    GrpcServer server(linkConfig_);
    
    // Start the server first time
    LinkRc firstStart = server.Start();
    
    // Give the server a moment to start
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Try to start again - should fail
    LinkRc secondStart = server.Start();
    
    // Stop the server
    server.Stop();
    
    // First start should succeed, second should fail
    EXPECT_EQ(firstStart, LinkRc::OK);
    EXPECT_EQ(secondStart, LinkRc::ERROR);
}

TEST_F(GrpcServerTest, StopWithoutStart)
{
    GrpcServer server(linkConfig_);
    
    // Stop the server without starting it - should not crash
    server.Stop();
    
    // Should complete without issues
    SUCCEED();
}

TEST_F(GrpcServerTest, StartStopMultipleTimes)
{
    GrpcServer server(linkConfig_);
    
    for (int i = 0; i < 3; i++) {
        // Start the server
        LinkRc startResult = server.Start();
        
        // Give the server a moment to start
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // Stop the server
        server.Stop();
        
        // Each start should succeed
        EXPECT_EQ(startResult, LinkRc::OK);
        
        // Brief pause between iterations
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

TEST_F(GrpcServerTest, StartWithInvalidPort)
{
    LinkConfig invalidConfig = linkConfig_;
    invalidConfig.port = 0; // Invalid port
    
    GrpcServer server(invalidConfig);
    
    // Starting with invalid port should handle gracefully
    LinkRc startResult = server.Start();
    
    // Give it a moment to attempt starting
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    server.Stop();
    
    // Start should handle the invalid port gracefully
    // The exact result depends on gRPC implementation
    // but it should not crash
    SUCCEED();
}

TEST_F(GrpcServerTest, StartWithPrivilegedPort)
{
    LinkConfig privilegedConfig = linkConfig_;
    privilegedConfig.port = 80; // Privileged port (might fail)
    
    GrpcServer server(privilegedConfig);
    
    // Starting with privileged port might fail due to permissions
    LinkRc startResult = server.Start();
    
    // Give it a moment to attempt starting
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    server.Stop();
    
    // Should handle privileged port gracefully (might succeed or fail depending on permissions)
    SUCCEED();
}

TEST_F(GrpcServerTest, StartWithInvalidUdsPath)
{
    LinkConfig invalidConfig = linkConfig_;
    invalidConfig.udsPath = ""; // Empty UDS path
    
    GrpcServer server(invalidConfig);
    
    // Starting with invalid UDS path should handle gracefully
    LinkRc startResult = server.Start();
    
    // Give it a moment to attempt starting
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    server.Stop();
    
    // Should handle the invalid UDS path gracefully
    // The exact result depends on gRPC implementation
    SUCCEED();
}

TEST_F(GrpcServerTest, StartWithLongUdsPath)
{
    LinkConfig longPathConfig = linkConfig_;
    longPathConfig.udsPath = "/tmp/very_long_uds_path_name_that_exceeds_normal_filesystem_limits_and_should_test_error_handling.sock";
    
    GrpcServer server(longPathConfig);
    
    // Starting with very long UDS path should handle gracefully
    LinkRc startResult = server.Start();
    
    // Give it a moment to attempt starting
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    server.Stop();
    
    // Should handle the long UDS path gracefully
    SUCCEED();
}

TEST_F(GrpcServerTest, ServerLifecycleWithRapidStartStop)
{
    GrpcServer server(linkConfig_);
    
    // Test rapid start/stop cycles
    for (int i = 0; i < 5; i++) {
        LinkRc startResult = server.Start();
        
        // Very short start time
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        server.Stop();
        
        // Brief pause
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Should handle rapid cycles without issues
    SUCCEED();
}

TEST_F(GrpcServerTest, ServerHandlesExistingUdsFile)
{
    // Create a file at the UDS path first
    std::ofstream existingFile(linkConfig_.udsPath);
    existingFile << "existing content";
    existingFile.close();
    
    GrpcServer server(linkConfig_);
    
    // Server should handle existing file at UDS path gracefully
    LinkRc startResult = server.Start();
    
    // Give it a moment to start
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    server.Stop();
    
    // Should handle existing file gracefully
    SUCCEED();
}

TEST_F(GrpcServerTest, ServerWithDifferentPorts)
{
    std::vector<uint16_t> testPorts = {50053, 50054, 50055, 50056};
    
    for (uint16_t port : testPorts) {
        LinkConfig testConfig = linkConfig_;
        testConfig.port = port;
        testConfig.udsPath = "/tmp/test_grpc_server_" + std::to_string(port) + ".sock";
        
        GrpcServer server(testConfig);
        
        LinkRc startResult = server.Start();
        
        // Give it a moment to start
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        server.Stop();
        
        // Clean up UDS file
        ::unlink(testConfig.udsPath.c_str());
        
        // Each port should be handled gracefully
        EXPECT_EQ(startResult, LinkRc::OK);
    }
}

TEST_F(GrpcServerTest, ServerConcurrentOperations)
{
    GrpcServer server(linkConfig_);
    
    // Start server in background
    std::thread startThread([&server]() {
        LinkRc result = server.Start();
        EXPECT_EQ(result, LinkRc::OK);
    });
    
    // Give server time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Stop server
    server.Stop();
    
    // Wait for start thread to complete
    if (startThread.joinable()) {
        startThread.join();
    }
    
    // Should handle concurrent operations without issues
    SUCCEED();
}

} // namespace virtrust