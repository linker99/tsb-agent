/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

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

int MigrationGetCert(char *pUuid, // 物理机的uuid
                     char *vUuid, // 虚拟机的uuid
                     char *cert, char *pubkey);

int MigrationCheckPeerPk(char *pUuid, // 物理机的uuid
                         char *vUuid, // 虚拟机的uuid
                         char *pk1, char *pk2);

int MigrationGetVrootCipher(char *pUuid, // 物理机的uuid
                            char *vUuid, // 虚拟机的uuid
                            char **cipher);

int MigrationImportVrootCipher(char *pUuid, // 物理机的uuid
                               char *vUuid, // 虚拟机的uuid
                               char *cipher);

int MigrationNotify(char *pUuid, // 物理机的uuid
                    char *vUuid, // 虚拟机的uuid
                    int status);
