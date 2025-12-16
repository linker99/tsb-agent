/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include "tsb_agent/tsb_agent.h"

#ifdef VIRTRUST_MOCK
// Simple Mock data for fuzzing
struct MockDomain {
    char uuid[37];
    char name[255];
    int state; // 0=off, 1=running
};

constexpr MockDomain MOCK_DOMAINS[] = {
    {"12345678-1234-1234-1234-123456789001", "test-domain-1", VM_SHUTUP}, // shut off
    {"12345678-1234-1234-1234-123456789002", "test-domain-2", VM_SHUTUP}, // shut off
    {"12345678-1234-1234-1234-123456789003", "running-domain", VM_RUNNING},  // running
    {"12345678-1234-1234-1234-123456789004", "another-shut-off-domain", VM_SHUTUP}  // shut off
};

constexpr int MOCK_DOMAIN_COUNT = 4;
#endif