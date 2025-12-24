/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <climits>

#include "tsb_agent/mock/tsb_agent_impl.h"
#include "tsb_agent/mock/mock_vm_infos.h"
#include "tsb_agent/tsb_agent.h"

using namespace virtrust::mock;

namespace {
int ParseTsbAgentRc(TsbAgentRc rc)
{
    switch (rc) {
        case TsbAgentRc::OK:
            return 0;
        case TsbAgentRc::ERROR:
            return -1;

        default:
            return -1;
    }
}

bool CheckVRootExists(const char *vUuid)
{
    if (vUuid == nullptr) {
        return false;
    }

#ifdef VIRTRUST_MOCK
    // 使用 MOCK_DOMAINS 判断 uuid 是否存在
    for (int i = 0; i < MOCK_DOMAIN_COUNT; ++i) {
        if (strcmp(MOCK_DOMAINS[i].uuid, vUuid) == 0) {
            return true;
        }
    }
    return false;
#else
    auto &tsbAgent = TsbAgentImpl::GetInstance();
    auto instances = tsbAgent.GetVRoots();

    // 校验vUuid是否存在
    for (const auto &instance : instances) {
        if (strcmp(instance.uuid, vUuid) == 0) {
            return true; // 找到对应的vUuid
        }
    }

    return false; // vUuid不存在
#endif
}

bool CheckVRootStarted(const char *vUuid)
{
    if (vUuid == nullptr) {
        return false;
    }
    
#ifdef VIRTRUST_MOCK
    return true;
#else
    auto &tsbAgent = TsbAgentImpl::GetInstance();
    return tsbAgent.HasVRootStarted(std::string(vUuid));
#endif
}
} // namespace

// NOTE ALL memories are allocated inside APIs by using "mallloc", remeber to
// free the pointer after use.

int GetVRoots(int *vtpcmNums, struct Description **vtpcmInfo)
{
#ifdef VIRTRUST_MOCK
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
#else
    auto &tsbAgent = TsbAgentImpl::GetInstance();

    auto instances = tsbAgent.GetVRoots(); // get virt roots from mock tsb agent
    *vtpcmNums = static_cast<int>(instances.size());

    // 分配内存
    if (*vtpcmNums > 0) {
        *vtpcmInfo = static_cast<Description *>(malloc(*vtpcmNums * sizeof(Description)));
        if (vtpcmInfo == nullptr) {
            return -1;
        }
        // 将 instances 中的数据复制到 *vtpcmInfo中
        for (int i = 0; i < *vtpcmNums; i++) {
            (*vtpcmInfo)[i] = instances[i];
        }
    } else {
        *vtpcmInfo = nullptr;
    }

    return 0; // success
#endif
}

int CreateVRoot(struct Description *vtpcmInfo)
{
#ifdef VIRTRUST_MOCK
    if (vtpcmInfo == nullptr || vtpcmInfo->uuid[0] == '\0' || vtpcmInfo->name[0] == '\0') {
        return -1;
    }

    // Check if UUID already exists (simple string comparison)
    for (int i = 0; i < MOCK_DOMAIN_COUNT; ++i) {
        if (strcmp(MOCK_DOMAINS[i].uuid, vtpcmInfo->uuid) == 0) {
            return -1; // duplicate UUID
        }
    }

    return 0; // Success
#else
    auto &tsbAgent = TsbAgentImpl::GetInstance();
    return ParseTsbAgentRc(tsbAgent.CreateVRoot(vtpcmInfo->uuid, vtpcmInfo->name));
#endif
}

int StartVRoot(char *uuid)
{
#ifdef VIRTRUST_MOCK
    if (uuid == nullptr || uuid[0] == '\0') {
        return -1;
    }

    // Check if it's a known UUID
    for (int i = 0; i < MOCK_DOMAIN_COUNT; ++i) {
        if (strcmp(MOCK_DOMAINS[i].uuid, uuid) == 0) {
            return SUCCESS;
        }
    }

    return -1; // can't find uuid
#else
    auto &tsbAgent = TsbAgentImpl::GetInstance();
    return ParseTsbAgentRc(tsbAgent.StartVRoot(uuid));
#endif
}

int StopVRoot(char *uuid)
{
#ifdef VIRTRUST_MOCK
    if (uuid == nullptr || uuid[0] == '\0') {
        return -1;
    }

    // Check if it's a known UUID
    for (int i = 0; i < MOCK_DOMAIN_COUNT; ++i) {
        if (strcmp(MOCK_DOMAINS[i].uuid, uuid) == 0) {
            return MOCK_DOMAINS[i].state == VM_RUNNING ? SUCCESS : -1; // fail if already stopped
        }
    }

    return 0; // Always succeed for mock
#else
    auto &tsbAgent = TsbAgentImpl::GetInstance();
    return ParseTsbAgentRc(tsbAgent.StopVRoot(uuid));
#endif
}

int RemoveVRoot(char *uuid)
{
#ifdef VIRTRUST_MOCK
    if (uuid == nullptr || uuid[0] == '\0') {
        return -1;
    }

    // Can't remove running domains
    for (int i = 0; i < MOCK_DOMAIN_COUNT; ++i) {
        if (strcmp(MOCK_DOMAINS[i].uuid, uuid) == 0) {
            return MOCK_DOMAINS[i].state == 0 ? 0 : -1; // fail if running
        }
    }

    return 0; // Always succeed for mock
#else
    auto &tsbAgent = TsbAgentImpl::GetInstance();
    return ParseTsbAgentRc(tsbAgent.RemoveVRoot(uuid));
#endif
}

int UpdateMeasure(char *uuid, struct MeasureInfo *bios, struct MeasureInfo *shim, struct MeasureInfo *grub,
                  struct MeasureInfo *grubCfg, struct MeasureInfo *kernel, struct MeasureInfo *initrd)
{
    auto &tsbAgent = TsbAgentImpl::GetInstance();
    return ParseTsbAgentRc(tsbAgent.UpdateMeasure(uuid, *bios, *shim, *grub, *grubCfg, *kernel, *initrd));
}

int CheckMeasure(char *uuid, struct MeasureInfo *bios, struct MeasureInfo *shim, struct MeasureInfo *grub,
                 struct MeasureInfo *grubCfg, struct MeasureInfo *kernel, struct MeasureInfo *initrd)
{
    auto &tsbAgent = TsbAgentImpl::GetInstance();
    return ParseTsbAgentRc(tsbAgent.CheckMeasure(uuid, *bios, *shim, *grub, *grubCfg, *kernel, *initrd));
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
    if (pUuid == nullptr || vUuid == nullptr) {
        return -1;
    }
    (void)hostreport;
    (void)vmreport;
    return 0;
}

int VerifyTrustReport(char *pUuid,                         // 物理机的uuid
                      char *vUuid,                         // 虚拟机的uuid
                      struct trust_report_new *hostreport, // 输入：host report
                      struct trust_report_new *vmreport    // 输入：virtual machine report
)
{
    if (pUuid == nullptr || vUuid == nullptr) {
        return -1;
    }
    (void)hostreport;
    (void)vmreport;
    return 0;
}

// 无需调用 tsbAgent.MigrationGetCert；先判断vUUid是否存在，然后分配内存，返回固定cert和pubkey
int MigrationGetCert(char *vUuid,   // 虚拟机的uuid
                     char **cert,   // 输出：对 pubkey 签名的证书（BMC可验证）
                     int *certLen,  // 输出：证书长度
                     char **pubkey, // 输出：临时生成的随机密钥对的公钥
                     int *pubkeyLen // 输出：公钥长度
)
{
    // 目的端没有vUuid，此处不判断vUuid是否存在
    if (vUuid == nullptr) {
        return -1;
    }

    // 检查输出参数有效性
    if (cert == nullptr || certLen == nullptr || pubkey == nullptr || pubkeyLen == nullptr) {
        return -1;
    }

    // 返回固定的证书内容
    const char *mockCert = "mock_migration_cert_data";
    const char *mockPubkey = "mock_migration_pubkey_data";

    int certDataLen = strlen(mockCert);
    int pubkeyDataLen = strlen(mockPubkey);

    // 分配证书内存
    *cert = static_cast<char *>(malloc(certDataLen));
    if (*cert == nullptr) {
        return -1;
    }

    // 复制证书数据
    if (memcpy_s(*cert, certDataLen, mockCert, certDataLen) != EOK) {
        free(*cert);
        *cert = nullptr;
        return -1;
    }
    *certLen = certDataLen;

    // 分配公钥内存
    *pubkey = static_cast<char *>(malloc(pubkeyDataLen));
    if (*pubkey == nullptr) {
        free(*cert);
        *cert = nullptr;
        return -1;
    }

    // 复制公钥数据
    if (memcpy_s(*pubkey, pubkeyDataLen, mockPubkey, pubkeyDataLen) != EOK) {
        free(*cert);
        *cert = nullptr;
        free(*pubkey);
        *pubkey = nullptr;
        return -1;
    }
    *pubkeyLen = pubkeyDataLen;

    return 0;
}

// 两端都调用，但目的端还未导入vRoot资源，仅校验vUuid是否为nullptr
int MigrationCheckPeerPk(char *vUuid, // 虚拟机的uuid
                         char *pk1,   // peer cert 公钥 (REVIEW: 改成 cert?)
                         char *pk2    // peer 临时生成的随机密钥对的公钥, a.k.a. pubkey
)
{
    return vUuid != nullptr ? 0 : -1;
}

// 两端都调用，最后通知时，目的端已经导入了vRoot资源，仅校验vUuid是否存在
int MigrationNotify(char *vUuid, // 虚拟机的uuid
                    int status)
{
    return CheckVRootExists(vUuid) ? 0 : -1;
}

// 仅源端调用
// pUuid不作处理，但需判断vUuid是否存在，然后再判断虚机是否启动过，若未启动则返回EN_STATE::ERR_VM_NOT_STARTED；
// 然后给cipher分配内存，cipher和cipherLen赋值固定内容
int MigrationGetVrootCipher(char *pUuid,
                            char *vUuid,   // 虚拟机的uuid
                            char **cipher, // 输出：加密后的密码资源
                            int *cipherLen // 输出：密文长度
)
{
    // 判断vUuid是否存在
    if (!CheckVRootExists(vUuid)) {
        return -1;
    }
    (void)pUuid;

    // 判断虚机是否启动过，若未启动则返回EN_STATE::ERR_VM_NOT_STARTED
    if (!CheckVRootStarted(vUuid)) {
        return ERR_VM_NOT_STARTED;
    }

    // 给cipher分配内存，cipher和cipherLen赋值固定内容
    if (cipher != nullptr && cipherLen != nullptr) {
        const char *mockCipher = "mock_vroot_cipher_data";
        int cipherDataLen = strlen(mockCipher);

        *cipher = static_cast<char *>(malloc(cipherDataLen));
        if (*cipher == nullptr) {
            return -1;
        }

        if (memcpy_s(*cipher, cipherDataLen, mockCipher, cipherDataLen) != EOK) {
            free(*cipher);
            *cipher = nullptr;
            return -1;
        }

        *cipherLen = cipherDataLen;
    }

    return 0;
}

// 仅目的端调用，仅校验pUuid和vUuid是否为空
int MigrationImportVrootCipher(char *pUuid,
                               char *vUuid,  // 虚拟机的uuid
                               char *cipher, // 加密后的密码资源
                               int cipherLen // 密文长度
)
{
    if (pUuid == nullptr || vUuid == nullptr) {
        return -1;
    }
    return 0;
}

// 两端都调用
// 先判断vUuid是否为空；当导出时，为tcm2bOut分配内存，tcm2bOut和tcm2bLenOut赋值固定内容；导入时不做任何操作。
int TransDupPub(int type,         // 输入/输入，对应EnDirection中的枚举
                char *vUuid,      // 虚拟机的uuid，仅type=EN_IMPORT时需要
                char **tcm2bOut,  // 导出tcm2秘钥，仅type=EN_EXPORT时需要
                int *tcm2bLenOut, // 导出tcm2秘钥长度，仅type=EN_EXPORT时需要
                char *tcm2bIn,    // 导入tcm2秘钥，仅type=EN_IMPORT时需要
                int tcm2bLenIn    // 导入tcm2秘钥长度，仅type=EN_IMPORT时需要
)
{
    // 目的端导出时，为tcm2bOut分配内存，赋值固定内容
    if (type == EN_EXPORT) {
        // vUuid为nullptr，无需检查
        if (tcm2bOut == nullptr || tcm2bLenOut == nullptr) {
            return -1;
        }

        const char *mockKey = "mock_tcm2_key_data";
        int keyLen = strlen(mockKey);

        *tcm2bOut = static_cast<char *>(malloc(keyLen));
        if (*tcm2bOut == nullptr) {
            return -1;
        }

        if (memcpy_s(*tcm2bOut, keyLen, mockKey, keyLen) != EOK) {
            free(*tcm2bOut);
            *tcm2bOut = nullptr;
            return -1;
        }

        *tcm2bLenOut = keyLen;
    } else {
        // 源端导入时仅检查vUuid是否存在
        if (!CheckVRootExists(vUuid)) {
            return -1;
        }
        (void)tcm2bIn;
        (void)tcm2bLenIn;
    }


    return 0;
}