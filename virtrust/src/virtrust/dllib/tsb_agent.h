/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <dlfcn.h>

#include <cstdint>
#include <string_view>

#include "tsb_agent/tsb_agent.h" // for structs and function prototypes
#include "virtrust/dllib/common.h"

namespace virtrust {

// TSB Agent 接口的 dlopen 封装
class TsbAgent : public DlLibBase {
public:
    ~TsbAgent() = default;
    TsbAgent(const TsbAgent &) = delete;
    void operator=(const TsbAgent &) = delete;

    // Singleton instance
    static TsbAgent &GetInstance()
    {
        static TsbAgent instance;
        return instance;
    }

    // Reload all functions
    DllibRc Reload()
    {
        SelfDlClose();
        LoadAll();
        return CheckOk();
    }

    // API 函数指针（签名与 tsb_agent.h 中一致）
    DlFun<int, int *, struct Description **> GetVRoots;
    DlFun<int, struct Description *> CreateVRoot;
    DlFun<int, char *> StartVRoot;
    DlFun<int, char *> StopVRoot;
    DlFun<int, char *> RemoveVRoot;

    DlFun<int, char *, struct MeasureInfo *, struct MeasureInfo *, struct MeasureInfo *, struct MeasureInfo *,
          struct MeasureInfo *, struct MeasureInfo *>
        UpdateMeasure;

    DlFun<int, char *, struct MeasureInfo *, struct MeasureInfo *, struct MeasureInfo *, struct MeasureInfo *,
          struct MeasureInfo *, struct MeasureInfo *>
        CheckMeasure;

    DlFun<int, char *, char *, struct trust_report_new *, struct trust_report_new *> GetReport;
    DlFun<int, char *, char *, struct trust_report_new *, struct trust_report_new *> VerifyTrustReport;

    DlFun<int, char *, char **, int *, char **, int *> MigrationGetCert;
    DlFun<int, char *, char *, char *> MigrationCheckPeerPk;
    DlFun<int, char *, char *, char **, int *> MigrationGetVrootCipher;
    DlFun<int, char *, char *, char *, int> MigrationImportVrootCipher;
    DlFun<int, char *, int> MigrationNotify;
    DlFun<int, int, char *, char **, int *, char *, int> TransDupPub;

private:
    void LoadAll()
    {
        // 显式 dlopen 共享库
        SelfDlOpen();

        // dlsym 全部函数
        DLLIB_SELF_DLSYM(GetVRoots);
        DLLIB_SELF_DLSYM(CreateVRoot);
        DLLIB_SELF_DLSYM(StartVRoot);
        DLLIB_SELF_DLSYM(StopVRoot);
        DLLIB_SELF_DLSYM(RemoveVRoot);

        DLLIB_SELF_DLSYM(UpdateMeasure);
        DLLIB_SELF_DLSYM(CheckMeasure);

        DLLIB_SELF_DLSYM(GetReport);
        DLLIB_SELF_DLSYM(VerifyTrustReport);

        DLLIB_SELF_DLSYM(MigrationGetCert);
        DLLIB_SELF_DLSYM(MigrationCheckPeerPk);
        DLLIB_SELF_DLSYM(MigrationGetVrootCipher);
        DLLIB_SELF_DLSYM(MigrationGetVrootCipher);
        DLLIB_SELF_DLSYM(MigrationGetVrootCipher);
        DLLIB_SELF_DLSYM(MigrationImportVrootCipher);
        DLLIB_SELF_DLSYM(MigrationNotify);
        DLLIB_SELF_DLSYM(TransDupPub);
    }

    TsbAgent() : DlLibBase(LIB_NAME)
    {
        LoadAll();
    }

    static constexpr std::string_view LIB_NAME = "libinterfac.so";
};

} // namespace virtrust
