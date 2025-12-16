/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <securec.h>

#include <cstdlib>
#include <cstring>

#include "tsb_agent/mock/mock_vm_infos.h"
#include "tsb_agent/tsb_agent.h"

// NOTE ALL memories are allocated inside APIs by using "malloc", remember to free after use.

int GetVRoots(int *vtpcmNums, struct Description **vtpcmInfo)
{
    if (vtpcmNums == nullptr || vtpcmInfo == nullptr) {
        return -1;
    }
    *vtpcmNums = MOCK_DOMAIN_COUNT;
    *vtpcmInfo = static_cast<Description*>(malloc(*vtpcmNums * sizeof(Description)));

    if (*vtpcmInfo == nullptr) {
        return -1;
    }

    for (int i = 0; i < MOCK_DOMAIN_COUNT; ++i) {
        if (strncpy_s((*vtpcmInfo)[i].uuid, sizeof((*vtpcmInfo)[i].uuid), MOCK_DOMAINS[i].uuid, strlen(MOCK_DOMAINS[i].uuid)) != EOK) {
            return 1;
        }
        (*vtpcmInfo)[i].uuid[sizeof((*vtpcmInfo)[i].uuid) - 1] = '\0'; // 确保字符串终止

        if (strncpy_s((*vtpcmInfo)[i].name, sizeof((*vtpcmInfo)[i].name), MOCK_DOMAINS[i].name, strlen(MOCK_DOMAINS[i].name)) != EOK) {
            return 1;
        }
        (*vtpcmInfo)[i].name[sizeof((*vtpcmInfo)[i].name) - 1] = '\0'; // 确保字符串终止
        (*vtpcmInfo)[i].state = MOCK_DOMAINS[i].state;
    }

    return 0; // success
}

int CreateVRoot(struct Description *vtpcmInfo)
{
    if (vtpcmInfo == nullptr || vtpcmInfo->uuid[0] == '\0' || vtpcmInfo->name[0] == '\0') {
        return -1;
    }

    // Always succeed for stable unit testing - removed random failure logic

    // Check if UUID already exists (simple string comparison)
    for (int i = 0; i < MOCK_DOMAIN_COUNT; ++i) {
        if (strcmp(MOCK_DOMAINS[i].uuid, vtpcmInfo->uuid) == 0) {
            return -1; // duplicate UUID
        }
    }

    return 0; // Success
}

int StartVRoot(char *uuid)
{
    if (uuid == nullptr || uuid[0] == '\0') {
        return -1;
    }

    // Always succeed for stable unit testing - removed random failure logic

    // Check if it's a known UUID
    for (int i = 0; i < MOCK_DOMAIN_COUNT; ++i) {
        if (strcmp(MOCK_DOMAINS[i].uuid, uuid) == 0) {
            return SUCCESS;
        }
    }

    return -1; // can't find uuid
}

int StopVRoot(char *uuid)
{
    if (uuid == nullptr || uuid[0] == '\0') {
        return -1;
    }

    // Always succeed for stable unit testing - removed random failure logic

    // Check if it's a known UUID
    for (int i = 0; i < MOCK_DOMAIN_COUNT; ++i) {
        if (strcmp(MOCK_DOMAINS[i].uuid, uuid) == 0) {
            return MOCK_DOMAINS[i].state == VM_RUNNING ? SUCCESS : -1; // fail if already stopped
        }
    }

    return 0; // Always succeed for mock
}

int RemoveVRoot(char *uuid)
{
    if (uuid == nullptr || uuid[0] == '\0') {
        return -1;
    }

    // Always succeed for stable unit testing - removed random failure logic

    // Can't remove running domains
    for (int i = 0; i < MOCK_DOMAIN_COUNT; ++i) {
        if (strcmp(MOCK_DOMAINS[i].uuid, uuid) == 0) {
            return MOCK_DOMAINS[i].state == 0 ? 0 : -1; // fail if running
        }
    }

    return 0; // Always succeed for mock
}

int UpdateMeasure(char *uuid, struct MeasureInfo *bios, struct MeasureInfo *shim, struct MeasureInfo *grub,
                  struct MeasureInfo *grubCfg, struct MeasureInfo *kernel, struct MeasureInfo *initrd)
{
    if (uuid == nullptr || uuid[0] == '\0') {
        return -1;
    }

    // Always succeed for stable unit testing - removed random failure logic

    return 0; // Success
}

int CheckMeasure(char *uuid, struct MeasureInfo *bios, struct MeasureInfo *shim, struct MeasureInfo *grub,
                 struct MeasureInfo *grubCfg, struct MeasureInfo *kernel, struct MeasureInfo *initrd)
{
    if (uuid == nullptr || uuid[0] == '\0') {
        return -1;
    }

    // Always succeed for stable unit testing - removed random failure logic

    return 0; // Success
}

/**
 * 迁移接口
 */

int GetReport(char *pUuid,                         // 物理机的uuid
              char *vUuid,                         // 虚拟机的uuid
              struct trust_report_new *hostreport, // 输出：host report
              struct trust_report_new *vmreport    // 输出：virtual machine report
)
{
    if (vUuid == nullptr || vUuid[0] == '\0') {
        return -1;
    }

    // Always succeed for stable unit testing - removed random failure logic

    // Allocate reports if null
    if (hostreport != nullptr) {
        memset(hostreport, 0, sizeof(*hostreport));
    }

    if (vmreport != nullptr) {
        memset(vmreport, 0, sizeof(*vmreport));
    }

    return 0; // Success
}

int VerifyTrustReport(char *pUuid,                         // 物理机的uuid
                      char *vUuid,                         // 虚拟机的uuid
                      struct trust_report_new *hostreport, // host report
                      struct trust_report_new *vmreport    // virtual machine report
)
{
    if (vUuid == nullptr || vUuid[0] == '\0' || hostreport == nullptr || vmreport == nullptr) {
        return -1;
    }

    // Always succeed for stable unit testing - removed random failure logic

    return 0; // Success
}

int MigrationGetCert(char *vUuid,   // 虚拟机的uuid
                     char **cert,   // 输出：对 pubkey 签名的证书（BMC可验证）
                     int *certLen,  // 输出：证书长度
                     char **pubkey, // 输出：临时生成的随机密钥对的公钥
                     int *pubkeyLen // 输出：公钥长度
)
{
    if (vUuid == nullptr || vUuid[0] == '\0' || cert == nullptr || pubkey == nullptr ||
        certLen == nullptr || pubkeyLen == nullptr || *cert != nullptr || *pubkey != nullptr) {
        return -1;
    }

    // Always succeed for stable unit testing - removed random failure logic

    const char* mock_cert = "mock-certificate";
    const char* mock_pubkey = "mock-public-key";

    *certLen = strlen(mock_cert) + 1;
    *cert = static_cast<char*>(malloc(*certLen));
    if (*cert == nullptr) return -1;
    if (strncpy_s(*cert, *certLen, mock_cert, strlen(mock_cert)) != EOK) {
        return ERR_MEMORY_ALLOCA;
    }
    (*cert)[*certLen - 1] = '\0'; // 确保字符串终止

    *pubkeyLen = strlen(mock_pubkey) + 1;
    *pubkey = static_cast<char*>(malloc(*pubkeyLen));
    if (*pubkey == nullptr) {
        free(*cert);
        return -1;
    }
    if (strncpy_s(*pubkey, *pubkeyLen, mock_pubkey, strlen(mock_pubkey)) != EOK) {
        return ERR_MEMORY_ALLOCA;
    }
    (*pubkey)[*pubkeyLen - 1] = '\0'; // 确保字符串终止

    return 0;
}

int MigrationCheckPeerPk(char *vUuid, // 虚拟机的uuid
                         char *cert,  // peer cert 公钥 (REVIEW: 改成 cert?)
                         char *pk2    // peer 临时生成的随机密钥对的公钥, a.k.a. pubkey
)
{
    if (vUuid == nullptr || vUuid[0] == '\0' || cert == nullptr || pk2 == nullptr) {
        return -1;
    }

    return 0; // Always succeed for mock
}

int MigrationGetVrootCipher(char *pUuid,
                            char *vUuid,   // 虚拟机的uuid
                            char **cipher, // 输出：加密后的密码资源
                            int *cipherLen // 输出：密文长度
)
{
    if (vUuid == nullptr || vUuid[0] == '\0' || cipher == nullptr || cipherLen == nullptr || *cipher != nullptr) {
        return -1;
    }

    // Always succeed for stable unit testing - removed random failure logic

    const char* mock_cipher = "mock-encrypted-data";
    *cipherLen = strlen(mock_cipher) + 1;
    *cipher = static_cast<char*>(malloc(*cipherLen));
    if (*cipher == nullptr) return -1;
    if (strncpy_s(*cipher, *cipherLen, mock_cipher, strlen(mock_cipher)) != EOK) {
        return ERR_MEMORY_ALLOCA;
    }
    (*cipher)[*cipherLen - 1] = '\0'; // 确保字符串终止

    return 0;
}

int MigrationImportVrootCipher(char *pUuid,
                               char *vUuid, // 虚拟机的uuid
                               char *cipher, // 加密后的密码资源
                               int cipherLen // 密文长度
)
{
    if (vUuid == nullptr || vUuid[0] == '\0' || cipher == nullptr || cipherLen <= 0) {
        return -1;
    }

    return 0; // Always succeed for mock
}

int MigrationNotify(char *vUuid, // 虚拟机的uuid
                    int status)
{
    if (vUuid == nullptr || vUuid[0] == '\0') {
        return -1;
    }

    return 0; // Always succeed for mock
}

int TransDupPub(int type,         // 输入/输入，对应EnDirection中的枚举
                char *vUuid,      // 虚拟机的uuid，仅type=EN_IMPORT时需要
                char **tcm2bOut,  // 导出tcm2秘钥，仅type=EN_EXPORT时需要
                int *tcm2bLenOut, // 导出tcm2秘钥长度，仅type=EN_EXPORT时需要
                char *tcm2bIn,    // 导入tcm2秘钥，仅type=EN_IMPORT时需要
                int tcm2bLenIn    // 导入tcm2秘钥长度，仅type=EN_IMPORT时需要
)
{
    // Input validation using proper enum values
    if (type == EN_IMPORT) {
        if (vUuid == nullptr || tcm2bIn == nullptr || tcm2bLenIn <= 0) {
            return -1;
        }
    } else if (type == EN_EXPORT) {
        if (tcm2bOut == nullptr || tcm2bLenOut == nullptr) {
            return -1;
        }
    } else {
        return -1;
    }

    // Always succeed for stable unit testing - removed random failure logic

    if (type == EN_EXPORT) {
        const char* mock_key = "mock-tcm2-key";
        *tcm2bLenOut = strlen(mock_key) + 1;
        *tcm2bOut = static_cast<char*>(malloc(*tcm2bLenOut));
        if (*tcm2bOut == nullptr) return -1;
        if (strncpy_s(*tcm2bOut, *tcm2bLenOut, mock_key, strlen(mock_key)) != EOK) {
        return ERR_MEMORY_ALLOCA;
    }
    (*tcm2bOut)[*tcm2bLenOut - 1] = '\0'; // 确保字符串终止
    }

    return 0;
}