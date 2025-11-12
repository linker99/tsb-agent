/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <cstring>
#include <string>

#include "gtest/gtest.h"
#include "tsb_agent/tsb_agent.h"

#include "virtrust/link/proto/proto_tools.h"

#include "virtrust/link/proto/migrate.pb.h"

namespace virtrust {

class ProtoToolsTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        // Initialize a test trust report
        memset(&testReport_, 0, sizeof(testReport_));

        // Set basic fields
        testReport_.content.be_host_report_time = 1234567890L;
        testReport_.content.be_host_startup_time = 1234567880L;
        testReport_.content.be_eval = 100;
        testReport_.content.be_host_ip = 0x01020304; // 4.3.2.1
        testReport_.content.be_illegal_program_load = 0;
        testReport_.content.be_illegal_lib_load = 0;
        testReport_.content.be_illegal_kernel_module_load = 0;
        testReport_.content.be_illegal_file_access = 0;
        testReport_.content.be_illegal_device_access = 0;
        testReport_.content.be_illegal_network_inreq = 0;
        testReport_.content.be_illegal_network_outreq = 0;
        testReport_.content.be_process_code_measure_fail = 0;
        testReport_.content.be_process_data_measure_fail = 0;
        testReport_.content.be_notify_fail = 0;
        testReport_.content.be_boot_measure_result = 1;
        testReport_.content.be_boot_times = 5;
        testReport_.content.be_tpcm_time = 1234567891L;
        testReport_.content.be_tpcm_report_time = 1234567892L;
        testReport_.content.be_log_number = 100;
        testReport_.content.be_nonce = 12345;

        // Set global control policy
        testReport_.content.global_control_policy.be_size = 1024;
        testReport_.content.global_control_policy.be_boot_measure_on = 1;
        testReport_.content.global_control_policy.be_program_measure_on = 1;
        testReport_.content.global_control_policy.be_dynamic_measure_on = 0;
        testReport_.content.global_control_policy.be_boot_control = 1;
        testReport_.content.global_control_policy.be_program_control = 1;
        testReport_.content.global_control_policy.be_tsb_flag1 = 1;
        testReport_.content.global_control_policy.be_tsb_flag2 = 0;
        testReport_.content.global_control_policy.be_tsb_flag3 = 1;
        testReport_.content.global_control_policy.be_program_measure_mode = 2;
        testReport_.content.global_control_policy.be_program_use_cache = 1;
        testReport_.content.global_control_policy.be_dmeasure_use_cache = 0;
        testReport_.content.global_control_policy.be_dmeasure_max_busy_delay = 100;
        testReport_.content.global_control_policy.be_process_dmeasure_ref_mode = 1;
        testReport_.content.global_control_policy.be_process_dmeasure_match_mode = 2;
        testReport_.content.global_control_policy.be_process_measure_match_mode = 3;
        testReport_.content.global_control_policy.be_process_dmeasure_lib_mode = 1;
        testReport_.content.global_control_policy.be_process_verify_lib_mode = 2;
        testReport_.content.global_control_policy.be_process_dmeasure_sub_process_mode = 1;
        testReport_.content.global_control_policy.be_process_dmeasure_old_process_mode = 0;
        testReport_.content.global_control_policy.be_process_dmeasure_interval = 60;

        // Set byte arrays with test data
        const char *hostId = "test_host_id_12345";
        const char *tpcmId = "test_tpcm_id_67890";
        const char *logHash = "test_log_hash_abcdef1234567890";
        const char *biosPcr = "test_bios_pcr_1234567890abcdef";
        const char *bootLoaderPcr = "test_boot_loader_pcr_1234567890abcdef";
        const char *kernelPcr = "test_kernel_pcr_1234567890abcdef";
        const char *tsbPcr = "test_tsb_pcr_1234567890abcdef";
        const char *bootPcr = "test_boot_pcr_1234567890abcdef";
        const char *appendData = "test_append_data_for_trust_report_12345";

        size_t hostIdLen = std::min(strlen(hostId), static_cast<size_t>(MAX_HOST_ID_SIZE));
        size_t tpcmIdLen = std::min(strlen(tpcmId), static_cast<size_t>(MAX_TPCM_ID_SIZE));
        size_t logHashLen = std::min(strlen(logHash), static_cast<size_t>(DEFAULT_HASH_SIZE));
        size_t biosPcrLen = std::min(strlen(biosPcr), static_cast<size_t>(DEFAULT_PCR_SIZE));
        size_t bootLoaderPcrLen = std::min(strlen(bootLoaderPcr), static_cast<size_t>(DEFAULT_PCR_SIZE));
        size_t kernelPcrLen = std::min(strlen(kernelPcr), static_cast<size_t>(DEFAULT_PCR_SIZE));
        size_t tsbPcrLen = std::min(strlen(tsbPcr), static_cast<size_t>(DEFAULT_PCR_SIZE));
        size_t bootPcrLen = std::min(strlen(bootPcr), static_cast<size_t>(DEFAULT_PCR_SIZE));
        size_t appendDataLen = std::min(strlen(appendData), static_cast<size_t>(MAX_TRUST_REPORT_APPENDDATA));

        memcpy(testReport_.content.host_id, hostId, hostIdLen);
        memcpy(testReport_.content.tpcm_id, tpcmId, tpcmIdLen);
        memcpy(testReport_.content.log_hash, logHash, logHashLen);
        memcpy(testReport_.content.bios_pcr, biosPcr, biosPcrLen);
        memcpy(testReport_.content.boot_loader_pcr, bootLoaderPcr, bootLoaderPcrLen);
        memcpy(testReport_.content.kernel_pcr, kernelPcr, kernelPcrLen);
        memcpy(testReport_.content.tsb_pcr, tsbPcr, tsbPcrLen);
        memcpy(testReport_.content.boot_pcr, bootPcr, bootPcrLen);
        memcpy(testReport_.append_data, appendData, appendDataLen);
    }

    trust_report_new testReport_;
};

TEST_F(ProtoToolsTest, ReportToProtoBasicFields)
{
    protos::TrustReportNew protoReport;
    ReportToProto(testReport_, &protoReport);

    // Verify basic fields
    EXPECT_EQ(protoReport.content().be_host_report_time(), testReport_.content.be_host_report_time);
    EXPECT_EQ(protoReport.content().be_host_startup_time(), testReport_.content.be_host_startup_time);
    EXPECT_EQ(protoReport.content().be_eval(), testReport_.content.be_eval);
    EXPECT_EQ(protoReport.content().be_host_ip(), testReport_.content.be_host_ip);
    EXPECT_EQ(protoReport.content().be_illegal_program_load(), testReport_.content.be_illegal_program_load);
    EXPECT_EQ(protoReport.content().be_illegal_lib_load(), testReport_.content.be_illegal_lib_load);
    EXPECT_EQ(protoReport.content().be_boot_measure_result(), testReport_.content.be_boot_measure_result);
    EXPECT_EQ(protoReport.content().be_boot_times(), testReport_.content.be_boot_times);
    EXPECT_EQ(protoReport.content().be_tpcm_time(), testReport_.content.be_tpcm_time);
    EXPECT_EQ(protoReport.content().be_tpcm_report_time(), testReport_.content.be_tpcm_report_time);
    EXPECT_EQ(protoReport.content().be_log_number(), testReport_.content.be_log_number);
    EXPECT_EQ(protoReport.content().be_nonce(), testReport_.content.be_nonce);
}

TEST_F(ProtoToolsTest, ReportToProtoGlobalControlPolicy)
{
    protos::TrustReportNew protoReport;
    ReportToProto(testReport_, &protoReport);

    const auto &policy = protoReport.content().global_control_policy();
    EXPECT_EQ(policy.be_size(), testReport_.content.global_control_policy.be_size);
    EXPECT_EQ(policy.be_boot_measure_on(), testReport_.content.global_control_policy.be_boot_measure_on);
    EXPECT_EQ(policy.be_program_measure_on(), testReport_.content.global_control_policy.be_program_measure_on);
    EXPECT_EQ(policy.be_dynamic_measure_on(), testReport_.content.global_control_policy.be_dynamic_measure_on);
    EXPECT_EQ(policy.be_boot_control(), testReport_.content.global_control_policy.be_boot_control);
    EXPECT_EQ(policy.be_program_control(), testReport_.content.global_control_policy.be_program_control);
    EXPECT_EQ(policy.be_tsb_flag1(), testReport_.content.global_control_policy.be_tsb_flag1);
    EXPECT_EQ(policy.be_tsb_flag2(), testReport_.content.global_control_policy.be_tsb_flag2);
    EXPECT_EQ(policy.be_tsb_flag3(), testReport_.content.global_control_policy.be_tsb_flag3);
    EXPECT_EQ(policy.be_program_measure_mode(), testReport_.content.global_control_policy.be_program_measure_mode);
    EXPECT_EQ(policy.be_program_use_cache(), testReport_.content.global_control_policy.be_program_use_cache);
    EXPECT_EQ(policy.be_dmeasure_use_cache(), testReport_.content.global_control_policy.be_dmeasure_use_cache);
    EXPECT_EQ(policy.be_dmeasure_max_busy_delay(),
              testReport_.content.global_control_policy.be_dmeasure_max_busy_delay);
    EXPECT_EQ(policy.be_process_dmeasure_ref_mode(),
              testReport_.content.global_control_policy.be_process_dmeasure_ref_mode);
    EXPECT_EQ(policy.be_process_dmeasure_match_mode(),
              testReport_.content.global_control_policy.be_process_dmeasure_match_mode);
    EXPECT_EQ(policy.be_process_measure_match_mode(),
              testReport_.content.global_control_policy.be_process_measure_match_mode);
    EXPECT_EQ(policy.be_process_dmeasure_lib_mode(),
              testReport_.content.global_control_policy.be_process_dmeasure_lib_mode);
    EXPECT_EQ(policy.be_process_verify_lib_mode(),
              testReport_.content.global_control_policy.be_process_verify_lib_mode);
    EXPECT_EQ(policy.be_process_dmeasure_sub_process_mode(),
              testReport_.content.global_control_policy.be_process_dmeasure_sub_process_mode);
    EXPECT_EQ(policy.be_process_dmeasure_old_process_mode(),
              testReport_.content.global_control_policy.be_process_dmeasure_old_process_mode);
    EXPECT_EQ(policy.be_process_dmeasure_interval(),
              testReport_.content.global_control_policy.be_process_dmeasure_interval);
}

TEST_F(ProtoToolsTest, ReportToProtoByteArrays)
{
    protos::TrustReportNew protoReport;
    ReportToProto(testReport_, &protoReport);

    // Verify byte arrays
    EXPECT_EQ(protoReport.content().host_id(),
              std::string(reinterpret_cast<const char *>(testReport_.content.host_id),
                          strnlen(reinterpret_cast<const char *>(testReport_.content.host_id), MAX_HOST_ID_SIZE)));
    EXPECT_EQ(protoReport.content().tpcm_id(),
              std::string(reinterpret_cast<const char *>(testReport_.content.tpcm_id),
                          strnlen(reinterpret_cast<const char *>(testReport_.content.tpcm_id), MAX_TPCM_ID_SIZE)));
    EXPECT_EQ(protoReport.content().log_hash(),
              std::string(reinterpret_cast<const char *>(testReport_.content.log_hash),
                          strnlen(reinterpret_cast<const char *>(testReport_.content.log_hash), DEFAULT_HASH_SIZE)));
    EXPECT_EQ(protoReport.content().bios_pcr(),
              std::string(reinterpret_cast<const char *>(testReport_.content.bios_pcr),
                          strnlen(reinterpret_cast<const char *>(testReport_.content.bios_pcr), DEFAULT_PCR_SIZE)));
    EXPECT_EQ(
        protoReport.content().boot_loader_pcr(),
        std::string(reinterpret_cast<const char *>(testReport_.content.boot_loader_pcr),
                    strnlen(reinterpret_cast<const char *>(testReport_.content.boot_loader_pcr), DEFAULT_PCR_SIZE)));
    EXPECT_EQ(protoReport.content().kernel_pcr(),
              std::string(reinterpret_cast<const char *>(testReport_.content.kernel_pcr),
                          strnlen(reinterpret_cast<const char *>(testReport_.content.kernel_pcr), DEFAULT_PCR_SIZE)));
    EXPECT_EQ(protoReport.content().tsb_pcr(),
              std::string(reinterpret_cast<const char *>(testReport_.content.tsb_pcr),
                          strnlen(reinterpret_cast<const char *>(testReport_.content.tsb_pcr), DEFAULT_PCR_SIZE)));
    EXPECT_EQ(protoReport.content().boot_pcr(),
              std::string(reinterpret_cast<const char *>(testReport_.content.boot_pcr),
                          strnlen(reinterpret_cast<const char *>(testReport_.content.boot_pcr), DEFAULT_PCR_SIZE)));
    EXPECT_EQ(protoReport.append_data(), std::string(reinterpret_cast<const char *>(testReport_.append_data),
                                                     strnlen(reinterpret_cast<const char *>(testReport_.append_data),
                                                             MAX_TRUST_REPORT_APPENDDATA)));
}

TEST_F(ProtoToolsTest, ReportFromProtoBasicFields)
{
    protos::TrustReportNew protoReport;
    ReportToProto(testReport_, &protoReport);

    trust_report_new convertedReport = ReportFromProto(protoReport);

    // Verify basic fields
    EXPECT_EQ(convertedReport.content.be_host_report_time, testReport_.content.be_host_report_time);
    EXPECT_EQ(convertedReport.content.be_host_startup_time, testReport_.content.be_host_startup_time);
    EXPECT_EQ(convertedReport.content.be_eval, testReport_.content.be_eval);
    EXPECT_EQ(convertedReport.content.be_host_ip, testReport_.content.be_host_ip);
    EXPECT_EQ(convertedReport.content.be_illegal_program_load, testReport_.content.be_illegal_program_load);
    EXPECT_EQ(convertedReport.content.be_illegal_lib_load, testReport_.content.be_illegal_lib_load);
    EXPECT_EQ(convertedReport.content.be_boot_measure_result, testReport_.content.be_boot_measure_result);
    EXPECT_EQ(convertedReport.content.be_boot_times, testReport_.content.be_boot_times);
    EXPECT_EQ(convertedReport.content.be_tpcm_time, testReport_.content.be_tpcm_time);
    EXPECT_EQ(convertedReport.content.be_tpcm_report_time, testReport_.content.be_tpcm_report_time);
    EXPECT_EQ(convertedReport.content.be_log_number, testReport_.content.be_log_number);
    EXPECT_EQ(convertedReport.content.be_nonce, testReport_.content.be_nonce);
}

TEST_F(ProtoToolsTest, ReportFromProtoGlobalControlPolicy)
{
    protos::TrustReportNew protoReport;
    ReportToProto(testReport_, &protoReport);

    trust_report_new convertedReport = ReportFromProto(protoReport);

    const auto &policy = protoReport.content().global_control_policy();
    EXPECT_EQ(convertedReport.content.global_control_policy.be_size, policy.be_size());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_boot_measure_on, policy.be_boot_measure_on());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_program_measure_on, policy.be_program_measure_on());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_dynamic_measure_on, policy.be_dynamic_measure_on());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_boot_control, policy.be_boot_control());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_program_control, policy.be_program_control());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_tsb_flag1, policy.be_tsb_flag1());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_tsb_flag2, policy.be_tsb_flag2());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_tsb_flag3, policy.be_tsb_flag3());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_program_measure_mode, policy.be_program_measure_mode());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_program_use_cache, policy.be_program_use_cache());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_dmeasure_use_cache, policy.be_dmeasure_use_cache());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_dmeasure_max_busy_delay,
              policy.be_dmeasure_max_busy_delay());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_process_dmeasure_ref_mode,
              policy.be_process_dmeasure_ref_mode());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_process_dmeasure_match_mode,
              policy.be_process_dmeasure_match_mode());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_process_measure_match_mode,
              policy.be_process_measure_match_mode());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_process_dmeasure_lib_mode,
              policy.be_process_dmeasure_lib_mode());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_process_verify_lib_mode,
              policy.be_process_verify_lib_mode());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_process_dmeasure_sub_process_mode,
              policy.be_process_dmeasure_sub_process_mode());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_process_dmeasure_old_process_mode,
              policy.be_process_dmeasure_old_process_mode());
    EXPECT_EQ(convertedReport.content.global_control_policy.be_process_dmeasure_interval,
              policy.be_process_dmeasure_interval());
}

TEST_F(ProtoToolsTest, ReportFromProtoByteArrays)
{
    protos::TrustReportNew protoReport;
    ReportToProto(testReport_, &protoReport);

    trust_report_new convertedReport = ReportFromProto(protoReport);

    // Verify byte arrays
    EXPECT_EQ(memcmp(convertedReport.content.host_id, testReport_.content.host_id, MAX_HOST_ID_SIZE), 0);
    EXPECT_EQ(memcmp(convertedReport.content.tpcm_id, testReport_.content.tpcm_id, MAX_TPCM_ID_SIZE), 0);
    EXPECT_EQ(memcmp(convertedReport.content.log_hash, testReport_.content.log_hash, DEFAULT_HASH_SIZE), 0);
    EXPECT_EQ(memcmp(convertedReport.content.bios_pcr, testReport_.content.bios_pcr, DEFAULT_PCR_SIZE), 0);
    EXPECT_EQ(memcmp(convertedReport.content.boot_loader_pcr, testReport_.content.boot_loader_pcr, DEFAULT_PCR_SIZE),
              0);
    EXPECT_EQ(memcmp(convertedReport.content.kernel_pcr, testReport_.content.kernel_pcr, DEFAULT_PCR_SIZE), 0);
    EXPECT_EQ(memcmp(convertedReport.content.tsb_pcr, testReport_.content.tsb_pcr, DEFAULT_PCR_SIZE), 0);
    EXPECT_EQ(memcmp(convertedReport.content.boot_pcr, testReport_.content.boot_pcr, DEFAULT_PCR_SIZE), 0);
    EXPECT_EQ(memcmp(convertedReport.append_data, testReport_.append_data, MAX_TRUST_REPORT_APPENDDATA), 0);
}

TEST_F(ProtoToolsTest, RoundTripConversion)
{
    // Convert to proto and back to verify data integrity
    protos::TrustReportNew protoReport;
    ReportToProto(testReport_, &protoReport);

    trust_report_new convertedReport = ReportFromProto(protoReport);

    // Verify all basic fields match
    EXPECT_EQ(convertedReport.content.be_host_report_time, testReport_.content.be_host_report_time);
    EXPECT_EQ(convertedReport.content.be_host_startup_time, testReport_.content.be_host_startup_time);
    EXPECT_EQ(convertedReport.content.be_eval, testReport_.content.be_eval);
    EXPECT_EQ(convertedReport.content.be_host_ip, testReport_.content.be_host_ip);
    EXPECT_EQ(convertedReport.content.be_boot_measure_result, testReport_.content.be_boot_measure_result);
    EXPECT_EQ(convertedReport.content.be_boot_times, testReport_.content.be_boot_times);
    EXPECT_EQ(convertedReport.content.be_tpcm_time, testReport_.content.be_tpcm_time);
    EXPECT_EQ(convertedReport.content.be_tpcm_report_time, testReport_.content.be_tpcm_report_time);
    EXPECT_EQ(convertedReport.content.be_log_number, testReport_.content.be_log_number);
    EXPECT_EQ(convertedReport.content.be_nonce, testReport_.content.be_nonce);

    // Verify byte arrays match
    EXPECT_EQ(memcmp(convertedReport.content.host_id, testReport_.content.host_id, MAX_HOST_ID_SIZE), 0);
    EXPECT_EQ(memcmp(convertedReport.content.tpcm_id, testReport_.content.tpcm_id, MAX_TPCM_ID_SIZE), 0);
    EXPECT_EQ(memcmp(convertedReport.content.log_hash, testReport_.content.log_hash, DEFAULT_HASH_SIZE), 0);
    EXPECT_EQ(memcmp(convertedReport.append_data, testReport_.append_data, MAX_TRUST_REPORT_APPENDDATA), 0);
}

TEST_F(ProtoToolsTest, EmptyReportConversion)
{
    trust_report_new emptyReport;
    memset(&emptyReport, 0, sizeof(emptyReport));

    protos::TrustReportNew protoReport;
    ReportToProto(emptyReport, &protoReport);

    trust_report_new convertedReport = ReportFromProto(protoReport);

    // Verify all fields are zero
    EXPECT_EQ(convertedReport.content.be_host_report_time, 0u);
    EXPECT_EQ(convertedReport.content.be_host_startup_time, 0u);
    EXPECT_EQ(convertedReport.content.be_eval, 0u);
    EXPECT_EQ(convertedReport.content.be_host_ip, 0u);
    EXPECT_EQ(convertedReport.content.be_boot_measure_result, 0u);
    EXPECT_EQ(convertedReport.content.be_boot_times, 0u);
    EXPECT_EQ(convertedReport.content.be_tpcm_time, 0u);
    EXPECT_EQ(convertedReport.content.be_tpcm_report_time, 0u);
    EXPECT_EQ(convertedReport.content.be_log_number, 0u);
    EXPECT_EQ(convertedReport.content.be_nonce, 0u);

    // Verify byte arrays are empty
    for (int i = 0; i < MAX_HOST_ID_SIZE; i++) {
        EXPECT_EQ(convertedReport.content.host_id[i], 0);
    }
    for (int i = 0; i < MAX_TPCM_ID_SIZE; i++) {
        EXPECT_EQ(convertedReport.content.tpcm_id[i], 0);
    }
    for (int i = 0; i < DEFAULT_HASH_SIZE; i++) {
        EXPECT_EQ(convertedReport.content.log_hash[i], 0);
    }
}

TEST_F(ProtoToolsTest, DescriptionToProtoBasicFields)
{
    // Initialize a test Description
    Description testDesc;
    memset(&testDesc, 0, sizeof(testDesc));
    testDesc.state = 1; // Running state

    protos::Description protoDesc;
    DescriptionToProto(testDesc, &protoDesc);

    // Verify basic fields
    EXPECT_EQ(protoDesc.state(), testDesc.state);
}

TEST_F(ProtoToolsTest, DescriptionToProtoNameField)
{
    // Initialize a test Description
    Description testDesc;
    memset(&testDesc, 0, sizeof(testDesc));
    testDesc.state = 1;

    // Set name field with test data
    const char *testName = "test_vm_instance_001";
    size_t nameLen = std::min(strlen(testName), static_cast<size_t>(MAX_NAME_SIZE));
    memcpy(testDesc.name, testName, nameLen);

    protos::Description protoDesc;
    DescriptionToProto(testDesc, &protoDesc);

    // Verify name field - should match the actual string length (ignoring null padding)
    size_t expectedNameLen = strnlen(testDesc.name, MAX_NAME_SIZE);
    EXPECT_EQ(protoDesc.name(),
              std::string(testDesc.name, expectedNameLen));
}

TEST_F(ProtoToolsTest, DescriptionToProtoUuidField)
{
    // Initialize a test Description
    Description testDesc;
    memset(&testDesc, 0, sizeof(testDesc));
    testDesc.state = 1;

    // Set uuid field with test data (36 chars + null terminator)
    const char *testUuid = "123e4567-e89b-12d3-a456-426614174000";
    memcpy(testDesc.uuid, testUuid, 37);

    protos::Description protoDesc;
    DescriptionToProto(testDesc, &protoDesc);

    // Verify uuid field - should be full 37 bytes (including null terminator)
    EXPECT_EQ(protoDesc.uuid(),
              std::string(testDesc.uuid, 37));
}

TEST_F(ProtoToolsTest, DescriptionFromProtoBasicFields)
{
    // Initialize a test Description
    Description testDesc;
    memset(&testDesc, 0, sizeof(testDesc));
    testDesc.state = 1;

    protos::Description protoDesc;
    DescriptionToProto(testDesc, &protoDesc);

    Description convertedDesc = DescriptionFromProto(protoDesc);

    // Verify basic fields
    EXPECT_EQ(convertedDesc.state, testDesc.state);
}

TEST_F(ProtoToolsTest, DescriptionFromProtoNameField)
{
    // Initialize a test Description
    Description testDesc;
    memset(&testDesc, 0, sizeof(testDesc));
    testDesc.state = 1;

    // Set name field with test data
    const char *testName = "test_vm_instance_001";
    size_t nameLen = std::min(strlen(testName), static_cast<size_t>(MAX_NAME_SIZE));
    memcpy(testDesc.name, testName, nameLen);

    protos::Description protoDesc;
    DescriptionToProto(testDesc, &protoDesc);

    Description convertedDesc = DescriptionFromProto(protoDesc);

    // Verify name field
    EXPECT_EQ(memcmp(convertedDesc.name, testDesc.name, MAX_NAME_SIZE), 0);
}

TEST_F(ProtoToolsTest, DescriptionFromProtoUuidField)
{
    // Initialize a test Description
    Description testDesc;
    memset(&testDesc, 0, sizeof(testDesc));
    testDesc.state = 1;

    // Set uuid field with test data
    const char *testUuid = "123e4567-e89b-12d3-a456-426614174000";
    memcpy(testDesc.uuid, testUuid, 37);

    protos::Description protoDesc;
    DescriptionToProto(testDesc, &protoDesc);

    Description convertedDesc = DescriptionFromProto(protoDesc);

    // Verify uuid field
    EXPECT_EQ(memcmp(convertedDesc.uuid, testDesc.uuid, 37), 0);
}

TEST_F(ProtoToolsTest, DescriptionRoundTripConversion)
{
    // Initialize a test Description
    Description testDesc;
    memset(&testDesc, 0, sizeof(testDesc));
    testDesc.state = 1;

    // Set name field with test data
    const char *testName = "test_vm_instance_001";
    size_t nameLen = std::min(strlen(testName), static_cast<size_t>(MAX_NAME_SIZE));
    memcpy(testDesc.name, testName, nameLen);

    // Set uuid field with test data
    const char *testUuid = "123e4567-e89b-12d3-a456-426614174000";
    memcpy(testDesc.uuid, testUuid, 37);

    // Convert to proto and back to verify data integrity
    protos::Description protoDesc;
    DescriptionToProto(testDesc, &protoDesc);

    Description convertedDesc = DescriptionFromProto(protoDesc);

    // Verify all fields match
    EXPECT_EQ(convertedDesc.state, testDesc.state);
    EXPECT_EQ(memcmp(convertedDesc.name, testDesc.name, MAX_NAME_SIZE), 0);
    EXPECT_EQ(memcmp(convertedDesc.uuid, testDesc.uuid, 37), 0);
}

TEST_F(ProtoToolsTest, EmptyDescriptionConversion)
{
    Description emptyDesc;
    memset(&emptyDesc, 0, sizeof(emptyDesc));

    protos::Description protoDesc;
    DescriptionToProto(emptyDesc, &protoDesc);

    Description convertedDesc = DescriptionFromProto(protoDesc);

    // Verify all fields are zero
    EXPECT_EQ(convertedDesc.state, 0);

    // Verify name field is empty
    for (int i = 0; i < MAX_NAME_SIZE; i++) {
        EXPECT_EQ(convertedDesc.name[i], 0);
    }

    // Verify uuid field is empty
    for (int i = 0; i < 37; i++) {
        EXPECT_EQ(convertedDesc.uuid[i], 0);
    }
}

TEST_F(ProtoToolsTest, DescriptionWithPartialName)
{
    Description partialDesc;
    memset(&partialDesc, 0, sizeof(partialDesc));

    // Set only first part of name field
    const char *partialName = "partial";
    memcpy(partialDesc.name, partialName, strlen(partialName));
    partialDesc.state = 2;

    protos::Description protoDesc;
    DescriptionToProto(partialDesc, &protoDesc);

    Description convertedDesc = DescriptionFromProto(protoDesc);

    // Verify state field
    EXPECT_EQ(convertedDesc.state, 2);

    // Verify name field is preserved correctly
    EXPECT_EQ(memcmp(convertedDesc.name, partialName, strlen(partialName)), 0);

    // Verify remaining part of name field is still zero
    for (size_t i = strlen(partialName); i < MAX_NAME_SIZE; i++) {
        EXPECT_EQ(convertedDesc.name[i], 0);
    }
}

} // namespace virtrust
