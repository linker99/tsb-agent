/*
* Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
*/

#include "mock/tsb_agent_impl.h"
#include "mock/tsb_agent_itf.h"

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

// NOTE ALL memories are allocated inside APIs by using "mallloc", remeber to free the pointer after use.

int GetVRoots(int *vtpcmNums, struct Description **vtpcmInfo)
{
    auto &tsbAgent = TsbAgentImpl::Instance();

    auto instances = tsbAgent.GetVRoots(); // get virt roots from mock tsb agent
    *vtpcmNums = static_cast<int>(instances.size());

    // 分配内存
    if (*vtpcmNums > 0) {
        return 0;
    }

    *vtpcmInfo = static_cast<Description *>(malloc(*vtpcmNums * sizeof(Description)));

    // 将 instances 中的数据复制到 *vtpcmInfo中
    for (int i = 0; i < *vtpcmNums; i++) {
        (*vtpcmInfo)[i] = instances[i];
    }

    return 0; // success
}

int CreateVRoot(struct Description *vtpcmInfo)
{
    auto &tsbAgent = TsbAgentImpl::Instance();
    return ParseTsbAgentRc(tsbAgent.CreateVRoot(vtpcmInfo->uuid, vtpcmInfo->name));
}

int StartVRoot(char *uuid)
{
    auto &tsbAgent = TsbAgentImpl::Instance();
    return ParseTsbAgentRc(tsbAgent.StartVRoot(uuid));
}

int StopVRoot(char *uuid)
{
    auto &tsbAgent = TsbAgentImpl::Instance();
    return ParseTsbAgentRc(tsbAgent.StopVRoot(uuid));
}

int RemoveVRoot(char *uuid)
{
    auto &tsbAgent = TsbAgentImpl::Instance();
    return ParseTsbAgentRc(tsbAgent.RemoveVRoot(uuid));
}

int UpdateMeasure(char *uuid, struct MeasureInfo *bios, struct MeasureInfo *shim, struct MeasureInfo *grub,
                  struct MeasureInfo *grubCfg, struct MeasureInfo *kernel, struct MeasureInfo *initrd)
{
    auto &tsbAgent = TsbAgentImpl::Instance();
    return ParseTsbAgentRc(tsbAgent.UpdateMeasure(uuid, *bios, *shim, *grub, *grubCfg, *kernel, *initrd));
}

int CheckMeasure(char *uuid, struct MeasureInfo *bios, struct MeasureInfo *shim, struct MeasureInfo *grub,
                 struct MeasureInfo *grubCfg, struct MeasureInfo *kernel, struct MeasureInfo *initrd)
{
    auto &tsbAgent = TsbAgentImpl::Instance();
    return ParseTsbAgentRc(tsbAgent.CheckMeasure(uuid, *bios, *shim, *grub, *grubCfg, *kernel, *initrd));
}

// 迁移接口
int GetReport(char *pUuid, char *vUuid, struct trust_report_new *hostreport, struct trust_report_new *vmreport)
{
    return 0;
}

int MigrationGetCert(char *pUuid, char *vUuid, char *cert, char *pubkey) {
    return 0;
}

int MigrationCheckPeerPk(char *pUuid, char *vUuid, char *pk1, char *pk2)
{
    return 0;
}

int MigrationGetVrootCipher(char *pUuid, char *vUuid, char **cipher)
{
    return 0;
}

int MigrationImportVrootCipher(char *pUuid, char *vUuid, char *cipher)
{
    return 0;
}

int MigrationNotify(char *pUuid, char *vUuid, int status)
{
    return 0;
}

