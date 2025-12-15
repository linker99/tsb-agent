/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <climits>

#include "tsb_agent/mock/tsb_agent_impl.h"
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
} // namespace

// NOTE ALL memories are allocated inside APIs by using "mallloc", remeber to
// free the pointer after use.

int GetVRoots(int *vtpcmNums, struct Description **vtpcmInfo)
{
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
}

int CreateVRoot(struct Description *vtpcmInfo)
{
    auto &tsbAgent = TsbAgentImpl::GetInstance();
    return ParseTsbAgentRc(tsbAgent.CreateVRoot(vtpcmInfo->uuid, vtpcmInfo->name));
}

int StartVRoot(char *uuid)
{
    auto &tsbAgent = TsbAgentImpl::GetInstance();
    return ParseTsbAgentRc(tsbAgent.StartVRoot(uuid));
}

int StopVRoot(char *uuid)
{
    auto &tsbAgent = TsbAgentImpl::GetInstance();
    return ParseTsbAgentRc(tsbAgent.StopVRoot(uuid));
}

int RemoveVRoot(char *uuid)
{
    auto &tsbAgent = TsbAgentImpl::GetInstance();
    return ParseTsbAgentRc(tsbAgent.RemoveVRoot(uuid));
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
    auto &tsbAgent = TsbAgentImpl::GetInstance();
    return ParseTsbAgentRc(tsbAgent.GetReport(pUuid, vUuid, hostreport, vmreport));
}

int VerifyTrustReport(char *pUuid,                         // 物理机的uuid
                      char *vUuid,                         // 虚拟机的uuid
                      struct trust_report_new *hostreport, // 输出：host report
                      struct trust_report_new *vmreport    // 输出：virtual machine report
)
{
    auto &tsbAgent = TsbAgentImpl::GetInstance();
    return ParseTsbAgentRc(tsbAgent.VerifyReport(pUuid, vUuid, hostreport, vmreport));
}

int MigrationGetCert(char *vUuid,   // 虚拟机的uuid
                     char **cert,   // 输出：对 pubkey 签名的证书（BMC可验证）
                     int *certLen,  // 输出：证书长度
                     char **pubkey, // 输出：临时生成的随机密钥对的公钥
                     int *pubkeyLen // 输出：公钥长度
)
{
    auto &tsbAgent = TsbAgentImpl::GetInstance();
    std::vector<uint8_t> out_cert;
    std::vector<uint8_t> out_pubkey;
    auto rc = tsbAgent.MigrationGetCert(vUuid, out_cert, out_pubkey);

    if (cert == nullptr || pubkey == nullptr || rc != TsbAgentRc::OK || *cert != nullptr || *pubkey != nullptr) {
        return ParseTsbAgentRc(TsbAgentRc::ERROR);
    }
    if (out_cert.size() > static_cast<size_t>(INT_MAX)) {
        return ParseTsbAgentRc(TsbAgentRc::ERROR);
    }
    *certLen = static_cast<int>(out_cert.size());
    *cert = static_cast<char *>(malloc(*certLen));
    if (memcpy_s(*cert, *certLen, out_cert.data(), out_cert.size()) != EOK) {
        free(*cert);
        *cert = nullptr;
        return ParseTsbAgentRc(TsbAgentRc::ERROR);
    }
    if (out_pubkey.size() > static_cast<size_t>(INT_MAX)) {
        free(*cert);
        *cert = nullptr;
        return ParseTsbAgentRc(TsbAgentRc::ERROR);
    }
    *pubkeyLen = out_pubkey.size();
    *pubkey = static_cast<char *>(malloc(out_pubkey.size()));
    memcpy(*pubkey, out_pubkey.data(), out_pubkey.size());

    return ParseTsbAgentRc(rc);
}

int MigrationCheckPeerPk(char *vUuid, // 虚拟机的uuid
                         char *pk1,   // peer cert 公钥 (REVIEW: 改成 cert?)
                         char *pk2    // peer 临时生成的随机密钥对的公钥, a.k.a. pubkey
)
{
    return 0;
}

int MigrationNotify(char *vUuid, // 虚拟机的uuid
                    int status)
{
    return 0;
}

int MigrationImportVrootCipher(char *pUuid,
                               char *vUuid,  // 虚拟机的uuid
                               char *cipher, // 加密后的密码资源
                               int cipherLen // 密文长度
)
{
    return 0;
}

int TransDupPub(int type,         // 输入/输入，对应EnDirection中的枚举
                char *vUuid,      // 虚拟机的uuid，仅type=EN_IMPORT时需要
                char **tcm2bOut,  // 导出tcm2秘钥，仅type=EN_EXPORT时需要
                int *tcm2bLenOut, // 导出tcm2秘钥长度，仅type=EN_EXPORT时需要
                char *tcm2bIn,    // 导入tcm2秘钥，仅type=EN_IMPORT时需要
                int tcm2bLenIn    // 导入tcm2秘钥长度，仅type=EN_IMPORT时需要
)
{
    return 0;
}

int MigrationGetVrootCipher(char *pUuid,
                            char *vUuid,   // 虚拟机的uuid
                            char **cipher, // 输出：加密后的密码资源
                            int *cipherLen // 输出：密文长度
)
{
    return 0;
}