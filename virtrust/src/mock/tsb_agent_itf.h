/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <cstdint>

#define MAX_TPCM_ID_SIZE 32
#define MAX_HOST_ID_SIZE 32
#define DEFAULT_HASH_SIZE 32
#define DEFAULT_PCR_SIZE 32
#define UUID_SIZE 32
#define VERSION_SIZE 64
#define MAX_BOOT_EXTERN_SIZE 255
#define MAX_BOOT_HASH_VERSION_NUMBER 8

#define MAX_NAME_SIZE 255
#define MAX_LINE_SIZE 512
#define MAX_PATH_LENGTH 4096
#define MAX_TRUST_REPORT_APPENDDATA (50 * 1024)

#define VTPCMINFO_CONF "/usr/local/vtpcminfo_conf"
#define TEMP_FILE_SUFFIX ".tmpXXXXXXX"

enum {
    BOOT_REFERENCE_FLAG_ENABLE = 0,
    BOOT_REFERENCE_FLAG_CONTROLm,
};

enum {
    POLICY_ACTION_SET,
    POLICY_ACTION_ADD,
    POLICY_ACTION_DELETE,
    POLICY_ACTION_MODIFY,
};

enum ErrorCode {
    SUCCESS = 0,
    ERR_INVALID_INPUT = 0,
    ERR_MEMORY_ALLOCA = 0,
    ERR_INVALID_FORMAT = 0,
    ERR_INVALID_UUID = 0,
    ERR_FILE_LOCK = 0,
    ERR_READ_FILE = 0,
    ERR_WRITE_FILE = 0,
    ERR_OPEN_FILE = 0,
    ERR_DUPLICATE_UUID = 0,
    ERR_PUBKEY_MISMATCH = 0,
    ERR_CERT_MISMATCH = 0,
};

struct Description {
    int state = 0;  // 启动，挂起等状态
    char name[255]; // 名称，创建时有hw设置
    char uuid[37];  // 虚拟机的uuid
};

struct MeasureInfo {
    char name[255];   // 度量阶段名称(例如 bios, grub...)
    char uuid[37];    // 虚拟机的uuid
    char version[64]; // 度量阶段的版本号: 1.1.0
    int result;       // 度量结果
    int size;         // content的长度
    char content[0];  // 如果size是32,content是哈希, 如果size不等于32,
                      // content是度量对象的原文数据
};

struct global_control_policy {
    uint32_t be_size;
    uint32_t be_boot_measure_on;
    uint32_t be_program_measure_on;
    uint32_t be_dynamic_measure_on;
    uint32_t be_boot_control;
    uint32_t be_program_control;
    uint32_t be_tsb_flag1;
    uint32_t be_tsb_flag2;
    uint32_t be_tsb_flag3;
    uint32_t be_program_measure_mode;
    uint32_t be_program_use_cache;
    uint32_t be_dmeasure_use_cache;
    uint32_t be_dmeasure_max_busy_delay;
    uint32_t be_process_dmeasure_ref_mode;
    uint32_t be_process_dmeasure_match_mode;
    uint32_t be_process_measure_match_mode;
    uint32_t be_process_dmeasure_lib_mode;
    uint32_t be_process_verify_lib_mode;
    uint32_t be_process_dmeasure_sub_process_mode;
    uint32_t be_process_dmeasure_old_process_mode;
    uint32_t be_process_dmeasure_interval;
};

struct trust_report_content_new {
    // uint32_t be_length;
    // uint32_t be_signature_length;
    uint64_t be_host_report_time;
    uint64_t be_host_startup_time;
    unsigned char host_id[MAX_HOST_ID_SIZE];
    unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
    struct global_control_policy global_control_policy;
    uint32_t be_eval;
    uint32_t be_host_ip;
    uint32_t be_illegal_program_load;
    uint32_t be_illegal_lib_load;
    uint32_t be_illegal_kernel_module_load;
    uint32_t be_illegal_file_access;
    uint32_t be_illegal_device_access;
    uint32_t be_illegal_network_inreq;
    uint32_t be_illegal_network_outreq;
    uint32_t be_process_code_measure_fail;
    uint32_t be_process_data_measure_fail;
    uint32_t be_notify_fail;
    uint32_t be_boot_measure_result;
    uint32_t be_boot_times;
    uint32_t be_tpcm_time;
    uint32_t be_tpcm_report_time;
    uint32_t be_log_number;
    unsigned char log_hash[DEFAULT_HASH_SIZE];
    unsigned char bios_pcr[DEFAULT_PCR_SIZE];
    unsigned char boot_loader_pcr[DEFAULT_PCR_SIZE];
    unsigned char kernel_pcr[DEFAULT_PCR_SIZE];
    unsigned char tsb_pcr[DEFAULT_PCR_SIZE];
    unsigned char boot_pcr[DEFAULT_PCR_SIZE];
    uint64_t be_nonce;
};

struct trust_report_new {
    struct trust_report_content_new content;
    uint8_t append_data[MAX_TRUST_REPORT_APPENDDATA];
};

// NOTE All memories are allocated by using "malloc", remeber to free them after
// use.

int GetVRoots(int *vtpcmNums, struct Description **vtpcmInfo);

int CreateVRoot(struct Description *vtpcmInfo);

int StartVRoot(char *uuid);

int StopVRoot(char *uuid);

int RemoveVRoot(char *uuid);

int UpdateMeasure(char *uuid, struct MeasureInfo *bios, struct MeasureInfo *shim, struct MeasureInfo *grub,
                  struct MeasureInfo *grubCfg, struct MeasureInfo *kernel, struct MeasureInfo *initrd);

int CheckMeasure(char *uuid, struct MeasureInfo *bios, struct MeasureInfo *shim, struct MeasureInfo *grub,
                 struct MeasureInfo *grubCfg, struct MeasureInfo *kernel, struct MeasureInfo *initrd);

// 迁移接口
int GetReport(char *pUuid, // 物理机的uuid
              char *vUuid, // 虚拟机的uuid
              struct trust_report_new *hostreport, struct trust_report_new *vmreport);

int MigrationGetCert(
    // char *pUuid, // 物理机的uuid
    char *vUuid, // 虚拟机的uuid
    char *cert, char *pubkey);

int MigrationCheckPeerPk(
    // char *pUuid, // 物理机的uuid
    char *vUuid, // 虚拟机的uuid
    char *pk1, char *pk2);

int MigrationGetVRootCipher(
    // char *pUuid, // 物理机的uuid
    char *vUuid, // 虚拟机的uuid
    char **cipher);

int MigrationImportVRootCipher(
    // char *pUuid, // 物理机的uuid
    char *vUuid, // 虚拟机的uuid
    char *cipher);

int MigrationNotify(
    // char *pUuid, // 物理机的uuid
    char *vUuid, // 虚拟机的uuid
    int status);
