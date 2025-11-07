/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include <gtest/gtest.h>

#include <cstring>
#include <memory>

// Include the TSB agent interface header
#include "securec.h"
#include "tsb_agent/mock/tsb_agent_impl.h"

namespace virtrust::mock {

// Test fixture for TSB agent interface tests
class TsbAgentItfTest : public ::testing::Test {
protected:
    // Helper method to verify that a function returns OK
    static void VerifyOK(int result, const char *function_name)
    {
        EXPECT_EQ(result, 0) << "Function " << function_name << " should return OK";
    }

    // Helper method to verify that a function returns error
    static void VerifyError(int result, const char *function_name)
    {
        EXPECT_NE(result, 0) << "Function " << function_name << " should return error";
    }

    // Helper method to verify that a function returns OK when it should
    static void VerifyOK(int result, const char *function_name, const char *expected_msg)
    {
        EXPECT_EQ(result, 0) << "Function " << function_name << " should return OK: " << expected_msg;
    }

    // Helper method to verify that a function returns error when it should
    static void VerifyError(int result, const char *function_name, const char *expected_msg)
    {
        EXPECT_NE(result, 0) << "Function " << function_name << " should return error: " << expected_msg;
    }
};

// Test case: Test GetVRoots function
TEST_F(TsbAgentItfTest, GetVRoots)
{
    int vtpcmNums = 0;
    struct Description *vtpcmInfo = nullptr;

    // Call GetVRoots
    int result = GetVRoots(&vtpcmNums, &vtpcmInfo);

    // Verify the function returns OK
    VerifyOK(result, "GetVRoots");

    // Verify the output parameters are set correctly
    EXPECT_EQ(vtpcmNums, 0) << "Number of virtual roots should be 0";
    EXPECT_EQ(vtpcmInfo, nullptr) << "Description pointer should be nullptr";

    // Clean up
    if (vtpcmInfo != nullptr) {
        free(vtpcmInfo);
    }
}

// Test case: Test CreateVRoots function
TEST_F(TsbAgentItfTest, CreateVRoot)
{
    struct Description desc = {};
    strcpy_sp(desc.name, 255, "test-vm");
    strcpy_sp(desc.uuid, 255, "12345678-1234-5678-1234-567812345678");

    // Call CreateVRoot
    int result = CreateVRoot(&desc);

    // Verify the function returns OK
    VerifyOK(result, "CreateVRoot");

    // Not Ok
    strcpy_sp(desc.uuid, 255, "12345678-1234-5678-1234-567812345678");
    result = CreateVRoot(&desc);
    VerifyError(result, "CreateVRoot");
}

// Test case: Test StartVRoot function
TEST_F(TsbAgentItfTest, StartVRoot)
{
    char uuid[37] = "12345678-1234-5678-1234-567812345678";

    // Call StartVRoot
    int result = StartVRoot(uuid);

    // Verify the function returns OK
    VerifyOK(result, "StartVRoot");
}

// Test case: Test StopVRoot function
TEST_F(TsbAgentItfTest, StopVRoot)
{
    char uuid[37] = "12345678-1234-5678-1234-567812345678";

    // Call StopVRoot
    int result = StopVRoot(uuid);

    // Verify the function returns OK
    VerifyOK(result, "StopVRoot");
}

// Test case: Test RemoveVRoot function
TEST_F(TsbAgentItfTest, RemoveVRoot)
{
    char uuid[37] = "12345678-1234-5678-1234-567812345678";

    // Call RemoveVRoot
    int result = RemoveVRoot(uuid);

    // Verify the function returns OK
    VerifyOK(result, "RemoveVRoot");
}

// Test case: Test UpdateMeasure function
TEST_F(TsbAgentItfTest, DISABLED_UpdateMeasure)
{
    char uuid[37] = "12345678-1234-5678-1234-567812345678";

    struct MeasureInfo bios = {};
    struct MeasureInfo shim = {};
    struct MeasureInfo grub = {};
    struct MeasureInfo grubCfg = {};
    struct MeasureInfo kernel = {};
    struct MeasureInfo initrd = {};

    // Call UpdateMeasure
    int result = UpdateMeasure(uuid, &bios, &shim, &grub, &grubCfg, &kernel, &initrd);

    // Verify the function returns OK
    VerifyOK(result, "UpdateMeasure");
}

// Test case: Test CheckMeasure function
TEST_F(TsbAgentItfTest, DISABLED_CheckMeasure)
{
    char uuid[37] = "12345678-1234-5678-1234-567812345678";

    struct MeasureInfo bios = {};
    struct MeasureInfo shim = {};
    struct MeasureInfo grub = {};
    struct MeasureInfo grubCfg = {};
    struct MeasureInfo kernel = {};
    struct MeasureInfo initrd = {};

    // Call CheckMeasure
    int result = CheckMeasure(uuid, &bios, &shim, &grub, &grubCfg, &kernel, &initrd);

    // Verify the function returns OK
    VerifyOK(result, "CheckMeasure");
}

// Test case: Test MigrationGetCert function
TEST_F(TsbAgentItfTest, DISABLED_MigrationGetCert)
{
    // char pUuid[37] = "12345678-1234-5678-1234-567812345678";
    // char vUuid[37] = "12345678-1234-5678-1234-567812345678";

    // char cert[1024] = {};
    // char pubkey[1024] = {};

    // // Call MigrationGetCert
    // int result = MigrationGetCert(pUuid, vUuid, cert, pubkey);

    // // Verify the function returns OK
    // VerifyOK(result, "MigrationGetCert");
}

// Test case: Test MigrationCheckPeerPk function
TEST_F(TsbAgentItfTest, DISABLED_MigrationCheckPeerPk)
{
    // char pUuid[37] = "12345678-1234-5678-1234-567812345678";
    char vUuid[37] = "12345678-1234-5678-1234-567812345678";

    char pk1[1024] = {};
    char pk2[1024] = {};

    // Call MigrationCheckPeerPk
    int result = MigrationCheckPeerPk(/* pUuid, */ vUuid, pk1, pk2);

    // Verify the function returns OK
    VerifyOK(result, "MigrationCheckPeerPk");
}

// Test case: Test MigrationGetVRootCipher function
TEST_F(TsbAgentItfTest, DISABLED_MigrationGetVRootCipher)
{
    // char pUuid[37] = "12345678-1234-5678-1234-567812345678";
    char vUuid[37] = "12345678-1234-5678-1234-567812345678";

    char *cipher = nullptr;

    // Call MigrationGetVRootCipher
    int result = MigrationGetVRootCipher(/* pUuid, */ vUuid, &cipher);

    // Verify the function returns OK
    VerifyOK(result, "MigrationGetVRootCipher");

    // Clean up
    if (cipher != nullptr) {
        free(cipher);
    }
}

// Test case: Test MigrationImportVRootCipher function
TEST_F(TsbAgentItfTest, DISABLED_MigrationImportVRootCipher)
{
    // char pUuid[37] = "12345678-1234-5678-1234-567812345678";
    char vUuid[37] = "12345678-1234-5678-1234-567812345678";

    char cipher[1024] = "test-cipher-data";

    // Call MigrationImportVRootCipher
    int result = MigrationImportVRootCipher(/* pUuid, */ vUuid, cipher);

    // Verify the function returns OK
    VerifyOK(result, "MigrationImportVRootCipher");
}

// Test case: Test MigrationNotify function
TEST_F(TsbAgentItfTest, DISABLED_MigrationNotify)
{
    // char pUuid[37] = "12345678-1234-5678-1234-567812345678";
    char vUuid[37] = "12345678-1234-5678-1234-567812345678";

    // Call MigrationNotify
    int result = MigrationNotify(/* pUuid, */ vUuid, 1);

    // Verify the function returns OK
    VerifyOK(result, "MigrationNotify");
}
} // namespace virtrust::mock
