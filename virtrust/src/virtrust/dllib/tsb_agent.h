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
    DllibRc LoadAll()
    {
        // 显式 dlopen 共享库
        auto ret = SelfDlOpen();
        if (ret != DllibRc::OK) {
            return ret;
        }

        // dlsym 全部函数
        if (DLLIB_SELF_DLSYM(GetVRoots) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(CreateVRoot) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(StartVRoot) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(StopVRoot) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(RemoveVRoot) != DllibRc::OK) {
            return DllibRc::ERROR;
        }

        if (DLLIB_SELF_DLSYM(UpdateMeasure) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(CheckMeasure) != DllibRc::OK) {
            return DllibRc::ERROR;
        }

        if (DLLIB_SELF_DLSYM(GetReport) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(VerifyTrustReport) != DllibRc::OK) {
            return DllibRc::ERROR;
        }

        if (DLLIB_SELF_DLSYM(MigrationGetCert) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(MigrationCheckPeerPk) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(MigrationGetVrootCipher) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(MigrationGetVrootCipher) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(MigrationGetVrootCipher) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(MigrationImportVrootCipher) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(MigrationNotify) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        if (DLLIB_SELF_DLSYM(TransDupPub) != DllibRc::OK) {
            return DllibRc::ERROR;
        }
        return DllibRc::OK;
    }

    TsbAgent() : DlLibBase(LIB_NAME)
    {
        LoadAll();
    }

    static constexpr std::string_view LIB_NAME = "libinterfac.so";
};

} // namespace virtrust
