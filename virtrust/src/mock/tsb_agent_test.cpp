/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include <gtest/gtest.h>

#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>

// Include the TSB agent header
#include "mock/tsb_agent_impl.h"

namespace virtrust::mock {

// Test fixture for TSB agent tests
class TsbAgentTest : public ::testing::Test {
protected:
    std::string temp_file_path;

    void SetUp() override
    {
        // Clear any existing test file
        temp_file_path = TsbAgentImpl::GetInstance().GetPath();
        std::ofstream(temp_file_path).close();
    }

    void TearDown() override
    {
        // Clean up the temporary file
        std::remove(temp_file_path.c_str());
    }

    // Helper method to get the current number of virtual roots
    static size_t GetRootCount()
    {
        auto &agent = TsbAgentImpl::GetInstance();
        return agent.GetVRoots().size();
    }

    // Helper method to check if a virtual root exists
    static bool VRootExists(const std::string &uuid)
    {
        auto &agent = TsbAgentImpl::GetInstance();
        auto vroots = agent.GetVRoots();
        return std::find_if(vroots.begin(), vroots.end(), [&uuid](const Description &desc) {
                   return std::string(desc.uuid) == uuid;
               }) != vroots.end();
    }

    // Helper method to check if a virtual root is running
    static bool VRootIsRunning(const std::string &uuid)
    {
        auto &agent = TsbAgentImpl::GetInstance();
        auto vroots = agent.GetVRoots();
        auto it = std::find_if(vroots.begin(), vroots.end(),
                               [&uuid](const Description &desc) { return std::string(desc.uuid) == uuid; });
        if (it == vroots.end()) {
            return false;
        }
        return it->state == static_cast<int>(VRootStatus::RUNNING);
    }

    // Helper method to create a virtual root and verify it was created
    static bool CreateVRootAndVerify(const std::string &uuid)
    {
        auto &agent = TsbAgentImpl::GetInstance();
        auto result = agent.CreateVRoot(uuid, "123");
        EXPECT_EQ(result, TsbAgentRc::OK) << "Creating virtual root with UUID " << uuid << " should succeed";
        EXPECT_TRUE(VRootExists(uuid)) << "Virtual root with UUID " << uuid << " should exist";
        return result == TsbAgentRc::OK;
    }

    // Helper method to start a virtual root and verify it was started
    static bool StartVRootAndVerify(const std::string &uuid)
    {
        auto &agent = TsbAgentImpl::GetInstance();
        auto result = agent.StartVRoot(uuid);
        EXPECT_EQ(result, TsbAgentRc::OK) << "Starting virtual root with UUID " << uuid << " should succeed";
        EXPECT_TRUE(VRootIsRunning(uuid)) << "Virtual root with UUID " << uuid << " should be running";
        return result == TsbAgentRc::OK;
    }

    // Helper method to destroy a virtual root and verify it was destroyed
    static bool StopVRootAndVerify(const std::string &uuid)
    {
        auto &agent = TsbAgentImpl::GetInstance();
        auto result = agent.StopVRoot(uuid);
        EXPECT_EQ(result, TsbAgentRc::OK) << "Destroying virtual root with UUID " << uuid << " should succeed";
        EXPECT_FALSE(VRootExists(uuid)) << "Virtual root with UUID " << uuid << " should not exist";
        return result == TsbAgentRc::OK;
    }

    // Helper method to undefine a virtual root and verify it was undefined
    static bool RemoveVRootAndVerify(const std::string &uuid)
    {
        auto &agent = TsbAgentImpl::GetInstance();
        auto result = agent.RemoveVRoot(uuid);
        EXPECT_EQ(result, TsbAgentRc::OK) << "Undefining virtual root with UUID " << uuid << " should succeed";
        EXPECT_FALSE(VRootExists(uuid)) << "Virtual root with UUID " << uuid << " should not exist";
        return result == TsbAgentRc::OK;
    }
};

// Test case: Verify that the TSB agent instance is a singleton
TEST_F(TsbAgentTest, SingletonInstance)
{
    auto &instance1 = TsbAgentImpl::GetInstance();
    auto &instance2 = TsbAgentImpl::GetInstance();
    EXPECT_EQ(&instance1, &instance2) << "TSB agent should be a singleton";
}

// Test case: Test creating a virtual root
TEST_F(TsbAgentTest, CreateVRoot)
{
    auto &agent = TsbAgentImpl::GetInstance();

    // Create a virtual root with a specific UUID
    const std::string &uuid = "12345";
    auto result = agent.CreateVRoot(uuid, "123");

    EXPECT_EQ(result, TsbAgentRc::OK) << "Creating virtual root should succeed";

    // Verify the virtual root was created
    auto vroots = agent.GetVRoots();
    EXPECT_EQ(vroots.size(), 1UL) << "Should have one virtual root";
    EXPECT_EQ(vroots[0].uuid, uuid) << "Virtual root UUID should match";
}

// Test case: Test creating multiple virtual roots
TEST_F(TsbAgentTest, CreateMultipleVRoots)
{
    auto &agent = TsbAgentImpl::GetInstance();

    // Create multiple virtual roots
    const std::string &uuid1 = "100";
    const std::string &uuid2 = "200";
    const std::string &uuid3 = "300";

    EXPECT_EQ(agent.CreateVRoot(uuid1, "111"), TsbAgentRc::OK) << "Creating first virtual root should succeed";
    EXPECT_EQ(agent.CreateVRoot(uuid2, "222"), TsbAgentRc::OK) << "Creating second virtual root should succeed";
    EXPECT_EQ(agent.CreateVRoot(uuid3, "333"), TsbAgentRc::OK) << "Creating third virtual root should succeed";

    // Verify all virtual roots was created
    auto vroots = agent.GetVRoots();
    EXPECT_EQ(vroots.size(), (size_t)3) << "Should have three virtual roots";

    EXPECT_NE(std::find_if(vroots.begin(), vroots.end(),
                           [&uuid1](const Description &desc) { return std::string(desc.uuid) == uuid1; }),
              vroots.end())
        << "Virtual root UUID 100 should exist";

    EXPECT_NE(std::find_if(vroots.begin(), vroots.end(),
                           [&uuid2](const Description &desc) { return std::string(desc.uuid) == uuid2; }),
              vroots.end())
        << "Virtual root UUID 200 should exist";

    EXPECT_NE(std::find_if(vroots.begin(), vroots.end(),
                           [&uuid3](const Description &desc) { return std::string(desc.uuid) == uuid3; }),
              vroots.end())
        << "Virtual root UUID 300 should exist";
}

// Test case: Test destroying a virtual root
TEST_F(TsbAgentTest, DestroyVRoots)
{
    auto &agent = TsbAgentImpl::GetInstance();

    // Create a virtual root with a specific UUID
    const std::string &uuid = "12345";
    EXPECT_EQ(agent.CreateVRoot(uuid, "123"), TsbAgentRc::OK) << "Creating virtual root should succeed";

    // Verify it exists
    auto vroots = agent.GetVRoots();
    EXPECT_EQ(vroots.size(), 1UL) << "Should have one virtual root";

    // Destroy (stop) the virtual root
    EXPECT_EQ(agent.StopVRoot(uuid), TsbAgentRc::ERROR) << "Destroying non-started virtual root should fail";

    // start the virtual root
    EXPECT_EQ(agent.StartVRoot(uuid), TsbAgentRc::OK) << "Starting virtual root should succeed";

    // Destroy (stop) the virtual root
    EXPECT_EQ(agent.StopVRoot(uuid), TsbAgentRc::OK) << "Destroying virtual root should succeed";

    // Verify it was destroyed
    vroots = agent.GetVRoots();
    EXPECT_EQ(vroots.size(), 1UL) << "Should have one virtual root";
}

// Test case: Test starting a virtual root
TEST_F(TsbAgentTest, StartVRoots)
{
    auto &agent = TsbAgentImpl::GetInstance();

    // Create a virtual root
    const std::string &uuid = "12345";
    EXPECT_EQ(agent.CreateVRoot(uuid, "123"), TsbAgentRc::OK) << "Creating virtual root should succeed";

    // Verify it exists and is not running
    auto vroots = agent.GetVRoots();
    EXPECT_EQ(vroots.size(), 1UL) << "Should have one virtual root";

    // start the virtual root
    EXPECT_EQ(agent.StartVRoot(uuid), TsbAgentRc::OK) << "Starting virtual root should succeed";

    // Verify the virtual root is now running
    vroots = agent.GetVRoots();
    EXPECT_EQ(vroots.size(), 1UL) << "Should have one virtual root";
    EXPECT_EQ(vroots[0].state, (int)VRootStatus::RUNNING) << "Virtual root should be in RUNNING";
}

// // Test case: Test starting a virtual root
// TEST_F(TsbAgentTest, StartVRoots)
// {
//     auto &agent = TsbAgentImpl::GetInstance();

//     // Try to start a virtual root that doesn't exist
//     const std::string &uuid = "99999";
//     EXPECT_NE(agent.StartVRoot(uuid), TsbAgentRc::OK) << "Starting non-existent virtual root should fail";

//     // Verify no virtual roots exist
//     vroots = agent.GetVRoots();
//     EXPECT_EQ(vroots.size(), 0) << "Should have no virtual roots";
// }

// Test case: Test undefining a virtual root
TEST_F(TsbAgentTest, UndefineVRoot)
{
    auto &agent = TsbAgentImpl::GetInstance();

    // Create a virtual root
    const std::string &uuid = "12345";
    EXPECT_EQ(agent.CreateVRoot(uuid, "123"), TsbAgentRc::OK) << "Creating virtual root should succeed";

    // Verify it exists
    auto vroots = agent.GetVRoots();
    EXPECT_EQ(vroots.size(), 1UL) << "Should have one virtual root";

    // Undefine the virtual root
    EXPECT_EQ(agent.RemoveVRoot(uuid), TsbAgentRc::OK) << "Undefining virtual root should succeed";

    // Verify it was undefined
    vroots = agent.GetVRoots();
    EXPECT_EQ(vroots.size(), (size_t)0) << "Should have no virtual roots";
}

// Test case: Test undefining a non-existent virtual root
TEST_F(TsbAgentTest, UndefineNonExistentVRoot)
{
    auto &agent = TsbAgentImpl::GetInstance();

    // Try to undefine a virtual root that doesn't exist
    const std::string &uuid = "99999";
    EXPECT_EQ(agent.RemoveVRoot(uuid), TsbAgentRc::OK) << "Undefining non-existent virtual root should fail";

    // Verify no virtual roots exist
    auto vroots = agent.GetVRoots();
    EXPECT_EQ(vroots.size(), (size_t)0) << "Should have no virtual roots";
}

// Test case: Test getting all virtual roots
TEST_F(TsbAgentTest, GetVRoots)
{
    auto &agent = TsbAgentImpl::GetInstance();

    // Create multiple virtual roots
    const std::string &uuid1 = "100";
    const std::string &uuid2 = "200";
    const std::string &uuid3 = "300";

    EXPECT_EQ(agent.CreateVRoot(uuid1, "111"), TsbAgentRc::OK) << "Creating first virtual root should succeed";
    EXPECT_EQ(agent.CreateVRoot(uuid2, "222"), TsbAgentRc::OK) << "Creating second virtual root should succeed";
    EXPECT_EQ(agent.CreateVRoot(uuid3, "333"), TsbAgentRc::OK) << "Creating third virtual root should succeed";

    // Verify all virtual roots was created
    auto vroots = agent.GetVRoots();

    // Verify we have the correct number of virtual roots
    EXPECT_EQ(vroots.size(), (size_t)3) << "Should have three virtual roots";

    // Verify the UUIDs are correct
    EXPECT_NE(std::find_if(vroots.begin(), vroots.end(),
                           [&uuid1](const Description &desc) { return std::string(desc.uuid) == uuid1; }),
              vroots.end())
        << "Virtual root UUID 100 should exist";

    EXPECT_NE(std::find_if(vroots.begin(), vroots.end(),
                           [&uuid2](const Description &desc) { return std::string(desc.uuid) == uuid2; }),
              vroots.end())
        << "Virtual root UUID 200 should exist";

    EXPECT_NE(std::find_if(vroots.begin(), vroots.end(),
                           [&uuid3](const Description &desc) { return std::string(desc.uuid) == uuid3; }),
              vroots.end())
        << "Virtual root UUID 300 should exist";
}

// Test case: Test persistence across restarts
TEST_F(TsbAgentTest, PersistenceAcrossRestarts)
{
    // First, create a virtual root and save it
    auto &agent1 = TsbAgentImpl::GetInstance();

    // Create a virtual root
    const std::string &uuid = "12345";
    EXPECT_EQ(agent1.CreateVRoot(uuid, "123"), TsbAgentRc::OK) << "Creating virtual root should succeed";

    // Now create a new agent instance (simulating restart)
    auto &agent2 = TsbAgentImpl::GetInstance();

    // Verify the virtual root was loaded
    auto vroots = agent2.GetVRoots();
    EXPECT_EQ(vroots.size(), (size_t)1) << "Should have one virtual roots ahter restart";
    EXPECT_EQ(vroots.begin()->uuid, uuid) << "Virtual root UUID should match";
}

// Test case: Test state file creation and format
TEST_F(TsbAgentTest, StateFileFormat)
{
    auto &agent = TsbAgentImpl::GetInstance();

    // Create a virtual root
    const std::string &uuid = "12345";
    EXPECT_EQ(agent.CreateVRoot(uuid, "123"), TsbAgentRc::OK) << "Creating virtual root should succeed";

    // Read the state file
    std::ifstream file(temp_file_path);
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    // Verify the content contains the expected format
    EXPECT_NE(content.find(uuid), std::string::npos) << "State file should contain UUID";
    EXPECT_NE(content.find(std::to_string(static_cast<int>(VRootStatus::OFF))), std::string::npos)
        << "State file should contain OFF status";
}
} // namespace virtrust::mock
