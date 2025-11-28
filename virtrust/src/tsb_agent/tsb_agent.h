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
    ERR_INVALID_INPUT,
    ERR_MEMORY_ALLOCA,
    ERR_INVALID_FORMAT,
    ERR_INVALID_UUID,
    ERR_CREATE_KEY,
    ERR_SIGN_CERT,
    ERR_FILE_LOCK,
    ERR_READ_FILE,
    ERR_WRITE_FILE,
    ERR_OPEN_FILE,
    ERR_DUPLICATE_UUID,
    ERR_PUBKEY_MISMATCH,
    ERR_CERT_MISMATCH,
    ERR_HUUID_MISMATCH,
    ERR_VUUID_MISMATCH,
};

enum EnDirection {
    EN_IMPORT = 0,
    EN_EXPORT,
    EN_DIRECTION_MAX,
};

enum EN_STATE {
    VM_SHUTUP = 0,      // 虚机停止状态，Description.state状态码
    VM_RUNNING,         // 虚机运行状态
    VM_MIGRATION,       // 虚机迁移状态

    IMPORT_BM_SUCCESS,  // 基线值设置成功，CheckMeasure返回值
    CHECK_BM_SUCCESS,   // 基线值校验成功，CheckMeasure返回值
    IMPORT_BM_FAILURE,  // 基线值设置失败，CheckMeasure返回值
    CHECK_BM_FAILURE,   // 基线值校验失败，CheckMeasure返回值

    ERR_VM_NOT_STARTED, // 虚机未启动错误，MigrationGetVrootCipher 返回值
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
#ifdef __cplusplus
extern "C" {
#endif

int GetVRoots(int *vtpcmNums, struct Description **vtpcmInfo);

int CreateVRoot(struct Description *vtpcmInfo);

int StartVRoot(char *uuid);

int StopVRoot(char *uuid);

int RemoveVRoot(char *uuid);

int UpdateMeasure(char *uuid, struct MeasureInfo *bios, struct MeasureInfo *shim, struct MeasureInfo *grub,
                  struct MeasureInfo *grubCfg, struct MeasureInfo *kernel, struct MeasureInfo *initrd);

int CheckMeasure(char *uuid, struct MeasureInfo *bios, struct MeasureInfo *shim, struct MeasureInfo *grub,
                 struct MeasureInfo *grubCfg, struct MeasureInfo *kernel, struct MeasureInfo *initrd);

/**
 * 迁移接口
 */
int GetReport(char *pUuid,                         // 物理机的uuid
              char *vUuid,                         // 虚拟机的uuid
              struct trust_report_new *hostreport, // 输出：host report
              struct trust_report_new *vmreport    // 输出：virtual machine report
);

int VerifyTrustReport(char *pUuid,                         // 物理机的uuid
                      char *vUuid,                         // 虚拟机的uuid
                      struct trust_report_new *hostreport, // host report
                      struct trust_report_new *vmreport    // virtual machine report
);

int MigrationGetCert(char *vUuid,   // 虚拟机的uuid
                     char **cert,   // 输出：对 pubkey 签名的证书（BMC可验证）
                     int *certLen,  // 输出：证书长度
                     char **pubkey, // 输出：临时生成的随机密钥对的公钥
                     int *pubkeyLen // 输出：公钥长度
);

int MigrationCheckPeerPk(char *vUuid, // 虚拟机的uuid
                         char *cert,  // peer cert 公钥 (REVIEW: 改成 cert?)
                         char *pk2    // peer 临时生成的随机密钥对的公钥, a.k.a. pubkey
);

int MigrationGetVrootCipher(char *pUuid,
                            char *vUuid,   // 虚拟机的uuid
                            char **cipher, // 输出：加密后的密码资源
                            int *cipherLen // 输出：密文长度
);

int MigrationImportVrootCipher(char *pUuid,
                               char *vUuid, // 虚拟机的uuid
                               char *cipher, // 加密后的密码资源
                               int cipherLen // 密文长度
);

int MigrationNotify(char *vUuid, // 虚拟机的uuid
                    int status);

// 迁移时目的端调用以导出tcm2密钥，再在源端导入该密钥
int TransDupPub(int type,         // 输入/输入，对应EnDirection中的枚举
                char *vUuid,      // 虚拟机的uuid，仅type=EN_IMPORT时需要
                char **tcm2bOut,  // 导出tcm2秘钥，仅type=EN_EXPORT时需要
                int *tcm2bLenOut, // 导出tcm2秘钥长度，仅type=EN_EXPORT时需要
                char *tcm2bIn,    // 导入tcm2秘钥，仅type=EN_IMPORT时需要
                int tcm2bLenIn    // 导入tcm2秘钥长度，仅type=EN_IMPORT时需要
);

#ifdef __cplusplus
}
#endif
