/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

// 适配器：对外保持 C 接口不变，内部通过 TsbAgent 封装进行 dlopen 调用

#include "tsb_agent/tsb_agent.h"
#include "virtrust/dllib/tsb_agent.h"

namespace {
bool CheckTsbAgentDlopen()
{
    auto &ta = virtrust::TsbAgent::GetInstance();
    return ta.CheckOk() == virtrust::DllibRc::OK;
}
}

// NOTE ALL memories are allocated inside APIs by using "malloc", remember to free after use.

int GetVRoots(int *vtpcmNums, struct Description **vtpcmInfo)
{
    if (!CheckTsbAgentDlopen()) {
        return -1;
    }
    return virtrust::TsbAgent::GetInstance().GetVRoots(vtpcmNums, vtpcmInfo);
}

int CreateVRoot(struct Description *vtpcmInfo)
{
    if (!CheckTsbAgentDlopen()) {
        return -1;
    }
    return virtrust::TsbAgent::GetInstance().CreateVRoot(vtpcmInfo);
}

int StartVRoot(char *uuid)
{
    if (!CheckTsbAgentDlopen()) {
        return -1;
    }
    return virtrust::TsbAgent::GetInstance().StartVRoot(uuid);
}

int StopVRoot(char *uuid)
{
    if (!CheckTsbAgentDlopen()) {
        return -1;
    }
    return virtrust::TsbAgent::GetInstance().StopVRoot(uuid);
}

int RemoveVRoot(char *uuid)
{
    if (!CheckTsbAgentDlopen()) {
        return -1;
    }
    return virtrust::TsbAgent::GetInstance().RemoveVRoot(uuid);
}

int UpdateMeasure(char *uuid, struct MeasureInfo *bios, struct MeasureInfo *shim, struct MeasureInfo *grub,
                  struct MeasureInfo *grubCfg, struct MeasureInfo *kernel, struct MeasureInfo *initrd)
{
    if (!CheckTsbAgentDlopen()) {
        return -1;
    }
    return virtrust::TsbAgent::GetInstance().UpdateMeasure(uuid, bios, shim, grub, grubCfg, kernel, initrd);
}

int CheckMeasure(char *uuid, struct MeasureInfo *bios, struct MeasureInfo *shim, struct MeasureInfo *grub,
                 struct MeasureInfo *grubCfg, struct MeasureInfo *kernel, struct MeasureInfo *initrd)
{
    if (!CheckTsbAgentDlopen()) {
        return -1;
    }
    return virtrust::TsbAgent::GetInstance().CheckMeasure(uuid, bios, shim, grub, grubCfg, kernel, initrd);
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
    if (!CheckTsbAgentDlopen()) {
        return -1;
    }
    return virtrust::TsbAgent::GetInstance().GetReport(pUuid, vUuid, hostreport, vmreport);
}

int VerifyTrustReport(char *pUuid,                         // 物理机的uuid
                      char *vUuid,                         // 虚拟机的uuid
                      struct trust_report_new *hostreport, // 输出：host report
                      struct trust_report_new *vmreport    // 输出：virtual machine report
)
{
    if (!CheckTsbAgentDlopen()) {
        return -1;
    }
    return virtrust::TsbAgent::GetInstance().VerifyTrustReport(pUuid, vUuid, hostreport, vmreport);
}

int MigrationGetCert(char *vUuid,   // 虚拟机的uuid
                     char **cert,   // 输出：对 pubkey 签名的证书（BMC可验证）
                     int *certLen,  // 输出：证书长度
                     char **pubkey, // 输出：临时生成的随机密钥对的公钥
                     int *pubkeyLen // 输出：公钥长度
)
{
    if (!CheckTsbAgentDlopen()) {
        return -1;
    }
    return virtrust::TsbAgent::GetInstance().MigrationGetCert(vUuid, cert, certLen, pubkey, pubkeyLen);
}

int MigrationCheckPeerPk(char *vUuid, // 虚拟机的uuid
                         char *pk1,   // peer cert 公钥 (REVIEW: 改成 cert?)
                         char *pk2    // peer 临时生成的随机密钥对的公钥, a.k.a. pubkey
)
{
    if (!CheckTsbAgentDlopen()) {
        return -1;
    }
    return virtrust::TsbAgent::GetInstance().MigrationCheckPeerPk(vUuid, pk1, pk2);
}

int MigrationGetVrootCipher(char *pUuid,
                            char *vUuid,   // 虚拟机的uuid
                            char **cipher, // 输出：加密后的密码资源
                            int *cipherLen // 输出：密文长度
)
{
    if (!CheckTsbAgentDlopen()) {
        return -1;
    }
    return virtrust::TsbAgent::GetInstance().MigrationGetVrootCipher(pUuid, vUuid, cipher, cipherLen);
}

int MigrationImportVrootCipher(char *pUuid,
                               char *vUuid, // 虚拟机的uuid
                               char *cipher, // 加密后的密码资源
                               int cipherLen // 密文长度
)
{
    if (!CheckTsbAgentDlopen()) {
        return -1;
    }
    return virtrust::TsbAgent::GetInstance().MigrationImportVrootCipher(pUuid, vUuid, cipher, cipherLen);
}

int MigrationNotify(char *vUuid, // 虚拟机的uuid
                    int status)
{
    if (!CheckTsbAgentDlopen()) {
        return -1;
    }
    return virtrust::TsbAgent::GetInstance().MigrationNotify(vUuid, status);
}
