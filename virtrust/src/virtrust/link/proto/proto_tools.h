#pragma once

#include <securec.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <ostream>

#include "virtrust/link/proto/migrate.pb.h"

namespace virtrust {
static void ReportToProto(const trust_report_new &report, protos::TrustReportNew *protoReport)
{
    if (protoReport == nullptr) {
        return;
    }
    // 转换 content
    auto *content = protoReport->mutable_content();
    content->set_be_host_report_time(report.content.be_host_report_time);
    content->set_be_host_startup_time(report.content.be_host_startup_time);

    // Convert byte arrays to strings, only copying actual data length (ignoring null padding)
    size_t host_id_len = strnlen(reinterpret_cast<const char *>(report.content.host_id), MAX_HOST_ID_SIZE);
    content->set_host_id(reinterpret_cast<const char *>(report.content.host_id), host_id_len);

    size_t tpcm_id_len = strnlen(reinterpret_cast<const char *>(report.content.tpcm_id), MAX_TPCM_ID_SIZE);
    content->set_tpcm_id(reinterpret_cast<const char *>(report.content.tpcm_id), tpcm_id_len);

    // 转换 global_control_policy
    auto *policy = content->mutable_global_control_policy();
    policy->set_be_size(report.content.global_control_policy.be_size);
    policy->set_be_boot_measure_on(report.content.global_control_policy.be_boot_measure_on);
    policy->set_be_program_measure_on(report.content.global_control_policy.be_program_measure_on);
    policy->set_be_dynamic_measure_on(report.content.global_control_policy.be_dynamic_measure_on);
    policy->set_be_boot_control(report.content.global_control_policy.be_boot_control);
    policy->set_be_program_control(report.content.global_control_policy.be_program_control);
    policy->set_be_tsb_flag1(report.content.global_control_policy.be_tsb_flag1);
    policy->set_be_tsb_flag2(report.content.global_control_policy.be_tsb_flag2);
    policy->set_be_tsb_flag3(report.content.global_control_policy.be_tsb_flag3);
    policy->set_be_program_measure_mode(report.content.global_control_policy.be_program_measure_mode);
    policy->set_be_program_use_cache(report.content.global_control_policy.be_program_use_cache);
    policy->set_be_dmeasure_use_cache(report.content.global_control_policy.be_dmeasure_use_cache);
    policy->set_be_dmeasure_max_busy_delay(report.content.global_control_policy.be_dmeasure_max_busy_delay);
    policy->set_be_process_dmeasure_ref_mode(report.content.global_control_policy.be_process_dmeasure_ref_mode);
    policy->set_be_process_dmeasure_match_mode(report.content.global_control_policy.be_process_dmeasure_match_mode);
    policy->set_be_process_measure_match_mode(report.content.global_control_policy.be_process_measure_match_mode);
    policy->set_be_process_dmeasure_lib_mode(report.content.global_control_policy.be_process_dmeasure_lib_mode);
    policy->set_be_process_verify_lib_mode(report.content.global_control_policy.be_process_verify_lib_mode);
    policy->set_be_process_dmeasure_sub_process_mode(
        report.content.global_control_policy.be_process_dmeasure_sub_process_mode);
    policy->set_be_process_dmeasure_old_process_mode(
        report.content.global_control_policy.be_process_dmeasure_old_process_mode);
    policy->set_be_process_dmeasure_interval(report.content.global_control_policy.be_process_dmeasure_interval);

    // 转换其他字段
    content->set_be_eval(report.content.be_eval);
    content->set_be_host_ip(report.content.be_host_ip);
    content->set_be_illegal_program_load(report.content.be_illegal_program_load);
    content->set_be_illegal_lib_load(report.content.be_illegal_lib_load);
    content->set_be_illegal_kernel_module_load(report.content.be_illegal_kernel_module_load);
    content->set_be_illegal_file_access(report.content.be_illegal_file_access);
    content->set_be_illegal_device_access(report.content.be_illegal_device_access);
    content->set_be_illegal_network_inreq(report.content.be_illegal_network_inreq);
    content->set_be_illegal_network_outreq(report.content.be_illegal_network_outreq);
    content->set_be_process_code_measure_fail(report.content.be_process_code_measure_fail);
    content->set_be_process_data_measure_fail(report.content.be_process_data_measure_fail);
    content->set_be_notify_fail(report.content.be_notify_fail);
    content->set_be_boot_measure_result(report.content.be_boot_measure_result);
    content->set_be_boot_times(report.content.be_boot_times);
    content->set_be_tpcm_time(report.content.be_tpcm_time);
    content->set_be_tpcm_report_time(report.content.be_tpcm_report_time);
    content->set_be_log_number(report.content.be_log_number);

    // Convert PCR and hash byte arrays, only copying actual data length
    size_t log_hash_len = strnlen(reinterpret_cast<const char *>(report.content.log_hash), DEFAULT_HASH_SIZE);
    content->set_log_hash(reinterpret_cast<const char *>(report.content.log_hash), log_hash_len);

    size_t bios_pcr_len = strnlen(reinterpret_cast<const char *>(report.content.bios_pcr), DEFAULT_PCR_SIZE);
    content->set_bios_pcr(reinterpret_cast<const char *>(report.content.bios_pcr), bios_pcr_len);

    size_t boot_loader_pcr_len =
        strnlen(reinterpret_cast<const char *>(report.content.boot_loader_pcr), DEFAULT_PCR_SIZE);
    content->set_boot_loader_pcr(reinterpret_cast<const char *>(report.content.boot_loader_pcr), boot_loader_pcr_len);

    size_t kernel_pcr_len = strnlen(reinterpret_cast<const char *>(report.content.kernel_pcr), DEFAULT_PCR_SIZE);
    content->set_kernel_pcr(reinterpret_cast<const char *>(report.content.kernel_pcr), kernel_pcr_len);

    size_t tsb_pcr_len = strnlen(reinterpret_cast<const char *>(report.content.tsb_pcr), DEFAULT_PCR_SIZE);
    content->set_tsb_pcr(reinterpret_cast<const char *>(report.content.tsb_pcr), tsb_pcr_len);

    size_t boot_pcr_len = strnlen(reinterpret_cast<const char *>(report.content.boot_pcr), DEFAULT_PCR_SIZE);
    content->set_boot_pcr(reinterpret_cast<const char *>(report.content.boot_pcr), boot_pcr_len);

    content->set_be_nonce(report.content.be_nonce);

    // 转换 append_data
    size_t append_data_len = strnlen(reinterpret_cast<const char *>(report.append_data), MAX_TRUST_REPORT_APPENDDATA);
    protoReport->set_append_data(reinterpret_cast<const char *>(report.append_data), append_data_len);
}

static bool ReportFromProto(const protos::TrustReportNew &protoReport, trust_report_new &report)
{
    (void)memset_s(&report, sizeof(report), 0, sizeof(report));
    const auto &content = protoReport.content();

    // 转换基本字段
    report.content.be_host_report_time = content.be_host_report_time();
    report.content.be_host_startup_time = content.be_host_startup_time();

    // 转换字节数组
    const std::string &host_id = content.host_id();
    size_t host_id_len = std::min(host_id.size(), static_cast<size_t>(MAX_HOST_ID_SIZE));
    if (memcpy_s(report.content.host_id, MAX_HOST_ID_SIZE, host_id.data(), host_id_len) != EOK) {
        return false;
    }

    const std::string &tpcm_id = content.tpcm_id();
    size_t tpcm_id_len = std::min(tpcm_id.size(), static_cast<size_t>(MAX_TPCM_ID_SIZE));
    if (memcpy_s(report.content.tpcm_id, MAX_TPCM_ID_SIZE, tpcm_id.data(), tpcm_id_len) != EOK) {
        return false;
    }

    // 转换 global_control_policy
    const auto &policy = content.global_control_policy();
    report.content.global_control_policy.be_size = policy.be_size();
    report.content.global_control_policy.be_boot_measure_on = policy.be_boot_measure_on();
    report.content.global_control_policy.be_program_measure_on = policy.be_program_measure_on();
    report.content.global_control_policy.be_dynamic_measure_on = policy.be_dynamic_measure_on();
    report.content.global_control_policy.be_boot_control = policy.be_boot_control();
    report.content.global_control_policy.be_program_control = policy.be_program_control();
    report.content.global_control_policy.be_tsb_flag1 = policy.be_tsb_flag1();
    report.content.global_control_policy.be_tsb_flag2 = policy.be_tsb_flag2();
    report.content.global_control_policy.be_tsb_flag3 = policy.be_tsb_flag3();
    report.content.global_control_policy.be_program_measure_mode = policy.be_program_measure_mode();
    report.content.global_control_policy.be_program_use_cache = policy.be_program_use_cache();
    report.content.global_control_policy.be_dmeasure_use_cache = policy.be_dmeasure_use_cache();
    report.content.global_control_policy.be_dmeasure_max_busy_delay = policy.be_dmeasure_max_busy_delay();
    report.content.global_control_policy.be_process_dmeasure_ref_mode = policy.be_process_dmeasure_ref_mode();
    report.content.global_control_policy.be_process_dmeasure_match_mode = policy.be_process_dmeasure_match_mode();
    report.content.global_control_policy.be_process_measure_match_mode = policy.be_process_measure_match_mode();
    report.content.global_control_policy.be_process_dmeasure_lib_mode = policy.be_process_dmeasure_lib_mode();
    report.content.global_control_policy.be_process_verify_lib_mode = policy.be_process_verify_lib_mode();
    report.content.global_control_policy.be_process_dmeasure_sub_process_mode =
        policy.be_process_dmeasure_sub_process_mode();
    report.content.global_control_policy.be_process_dmeasure_old_process_mode =
        policy.be_process_dmeasure_old_process_mode();
    report.content.global_control_policy.be_process_dmeasure_interval = policy.be_process_dmeasure_interval();

    // 转换其他字段
    report.content.be_eval = content.be_eval();
    report.content.be_host_ip = content.be_host_ip();
    report.content.be_illegal_program_load = content.be_illegal_program_load();
    report.content.be_illegal_lib_load = content.be_illegal_lib_load();
    report.content.be_illegal_kernel_module_load = content.be_illegal_kernel_module_load();
    report.content.be_illegal_file_access = content.be_illegal_file_access();
    report.content.be_illegal_device_access = content.be_illegal_device_access();
    report.content.be_illegal_network_inreq = content.be_illegal_network_inreq();
    report.content.be_illegal_network_outreq = content.be_illegal_network_outreq();
    report.content.be_process_code_measure_fail = content.be_process_code_measure_fail();
    report.content.be_process_data_measure_fail = content.be_process_data_measure_fail();
    report.content.be_notify_fail = content.be_notify_fail();
    report.content.be_boot_measure_result = content.be_boot_measure_result();
    report.content.be_boot_times = content.be_boot_times();
    report.content.be_tpcm_time = content.be_tpcm_time();
    report.content.be_tpcm_report_time = content.be_tpcm_report_time();
    report.content.be_log_number = content.be_log_number();

    const std::string &log_hash = content.log_hash();
    size_t log_hash_len = std::min(log_hash.size(), static_cast<size_t>(DEFAULT_HASH_SIZE));
    if (memcpy_s(report.content.log_hash, DEFAULT_HASH_SIZE, log_hash.data(), log_hash_len) != EOK) {
        return false;
    }

    const std::string &bios_pcr = content.bios_pcr();
    size_t bios_pcr_len = std::min(bios_pcr.size(), static_cast<size_t>(DEFAULT_PCR_SIZE));
    if (memcpy_s(report.content.bios_pcr, DEFAULT_PCR_SIZE, bios_pcr.data(), bios_pcr_len) != EOK) {
        return false;
    }

    const std::string &boot_loader_pcr = content.boot_loader_pcr();
    size_t boot_loader_pcr_len = std::min(boot_loader_pcr.size(), static_cast<size_t>(DEFAULT_PCR_SIZE));
    if (memcpy_s(report.content.boot_loader_pcr, DEFAULT_PCR_SIZE, boot_loader_pcr.data(), boot_loader_pcr_len) !=
        EOK) {
        return false;
    }

    const std::string &kernel_pcr = content.kernel_pcr();
    size_t kernel_pcr_len = std::min(kernel_pcr.size(), static_cast<size_t>(DEFAULT_PCR_SIZE));
    if (memcpy_s(report.content.kernel_pcr, DEFAULT_PCR_SIZE, kernel_pcr.data(), kernel_pcr_len) != EOK) {
        return false;
    }

    const std::string &tsb_pcr = content.tsb_pcr();
    size_t tsb_pcr_len = std::min(tsb_pcr.size(), static_cast<size_t>(DEFAULT_PCR_SIZE));
    if (memcpy_s(report.content.tsb_pcr, DEFAULT_PCR_SIZE, tsb_pcr.data(), tsb_pcr_len) != EOK) {
        return false;
    }

    const std::string &boot_pcr = content.boot_pcr();
    size_t boot_pcr_len = std::min(boot_pcr.size(), static_cast<size_t>(DEFAULT_PCR_SIZE));
    if (memcpy_s(report.content.boot_pcr, DEFAULT_PCR_SIZE, boot_pcr.data(), boot_pcr_len) != EOK) {
        return false;
    }

    report.content.be_nonce = content.be_nonce();

    // 转换 append_data
    const std::string &append_data = protoReport.append_data();
    size_t append_data_len = std::min(append_data.size(), static_cast<size_t>(MAX_TRUST_REPORT_APPENDDATA));
    if (memcpy_s(report.append_data, MAX_TRUST_REPORT_APPENDDATA, append_data.data(), append_data_len) != EOK) {
        return false;
    }

    return true;
}

static void DescriptionToProto(const Description &desc, protos::Description *protoDesc)
{
    if (protoDesc == nullptr) {
        return;
    }
    protoDesc->set_state(desc.state);

    // Convert name to string, only copying actual data length (ignoring null padding)
    size_t name_len = strnlen(desc.name, MAX_NAME_SIZE);
    protoDesc->set_name(desc.name, name_len);

    // Convert uuid to string (no length truncation for UUID)
    protoDesc->set_uuid(desc.uuid, 37);
}

static bool DescriptionFromProto(const protos::Description &protoDesc, Description &desc)
{
    (void)memset_s(&desc, sizeof(desc), 0, sizeof(desc));

    desc.state = protoDesc.state();

    // Convert name from string
    const std::string &name = protoDesc.name();
    size_t name_len = std::min(name.size(), static_cast<size_t>(MAX_NAME_SIZE));
    if (memcpy_s(desc.name, 255, name.data(), name_len) != EOK) {
        return false;
    }

    // Convert uuid from string (no length truncation for UUID)
    const std::string &uuid = protoDesc.uuid();
    if (memcpy_s(desc.uuid, 37, uuid.data(), uuid.size()) != EOK) {
        return false;
    }

    return true;
}

} // namespace virtrust
