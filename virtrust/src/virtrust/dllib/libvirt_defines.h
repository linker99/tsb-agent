/*
* Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
*/

#pragma once

#include <string>

#include "virtrust/base/custom_logger.h"

namespace virtrust {

using virConnectPtr = int *;
using virDomainPtr = int *;
using virNetworkPtr = int *;
using virTypedParameterPtr = int *;

/**
 * virDomainState:
 *
 * A domain may be in different states at a given point in time
 *
 * Since: 0.0.1
 */
typedef enum {
    VIR_DOMAIN_NOSTATE = 0,     /* no state (Since: 0.0.1) */
    VIR_DOMAIN_RUNNING = 1,     /* the domain is running (Since: 0.0.1) */
    VIR_DOMAIN_BLOCKED = 2,     /* the domain is blocked on resource (Since: 0.0.1) */
    VIR_DOMAIN_PAUSED = 3,      /* the domain is paused by user (Since: 0.0.1) */
    VIR_DOMAIN_SHUTDOWN = 4,    /* the domain is being shut down (Since: 0.0.1) */
    VIR_DOMAIN_SHUTOFF = 5,     /* the domain is shut off (Since: 0.0.1) */
    VIR_DOMAIN_CRASHED = 6,     /* the domain is crashed (Since: 0.0.2) */
    VIR_DOMAIN_PMSUSPENDED = 7, /* the domain is suspended by guest
                                   power management (Since: 0.9.11) */
} virDomainState;

/**
 * virDomainInfo:
 *
 * a virDomainInfo is a structure filled by virDomainGetInfo() and extracting
 * runtime information for a given active Domain
 *
 * Since: 0.0.1
 */
using virDomainInfo = struct _virDomainInfo;

struct _virDomainInfo {
    unsigned char state;        /* the running state, one of virDomainState */
    unsigned long maxMem;       /* the maximum memory in KBytes allowed */
    unsigned long memory;       /* the memory in KBytes used by the domain */
    unsigned short nrVirtCpu;   /* the number of virtual CPUs for the domain */
    unsigned long long cpuTime; /* the CPU time used in nanoseconds */
};

/**
 * virConnectListAllDomainsFlags:
 *
 * Flags used to tune which domains are listed by virConnectListAllDomains().
 * Note that these flags come in groups; if all bits from a group are 0,
 * then that group is not used to filter results.
 *
 * Since: 0.9.13
 */
typedef enum {
    VIR_CONNECT_LIST_DOMAINS_ACTIVE         = 1 << 0, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_INACTIVE       = 1 << 1, /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_PERSISTENT     = 1 << 2, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_TRANSIENT      = 1 << 3, /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_RUNNING        = 1 << 4, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_PAUSED         = 1 << 5, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_SHUTOFF        = 1 << 6, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_OTHER          = 1 << 7, /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE    = 1 << 8, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE = 1 << 9, /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_AUTOSTART      = 1 << 10, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART   = 1 << 11, /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT   = 1 << 12, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT    = 1 << 13, /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_HAS_CHECKPOINT = 1 << 14, /* (Since: 5.6.0) */
    VIR_CONNECT_LIST_DOMAINS_NO_CHECKPOINT  = 1 << 15, /* (Since: 5.6.0) */
} virConnectListAllDomainsFlags;

/**
 * virDomainCreateFlags:
 *
 * Flags OR'ed together to provide specific behaviour when creating a
 * Domain.
 *
 * Since: 0.0.1
 */
typedef enum {
    VIR_DOMAIN_NONE               = 0,      /* Default behavior (Since: 0.0.1) */
    VIR_DOMAIN_START_PAUSED       = 1 << 0, /* Launch guest in paused state (Since: 0.8.2) */
    VIR_DOMAIN_START_AUTODESTROY  = 1 << 1, /* Automatically kill guest when virConnectPtr is closed (Since: 0.9.3) */
    VIR_DOMAIN_START_BYPASS_CACHE = 1 << 2, /* Avoid file system cache pollution (Since: 0.9.4) */
    VIR_DOMAIN_START_FORCE_BOOT   = 1 << 3, /* Boot, discarding any managed save (Since: 0.9.5) */
    VIR_DOMAIN_START_VALIDATE     = 1 << 4, /* Validate the XML document against schema (Since: 1.2.12) */
    VIR_DOMAIN_START_RESET_NVRAM  = 1 << 5, /* Re-initialize NVRAM from template (Since: 8.1.0) */
} virDomainCreateFlags;

/**
 * virDomainDestroyFlagsValues:
 *
 * Flags used to provide specific behaviour to the
 * virDomainDestroyFlags() function
 *
 * Since: 0.9.4
 */
typedef enum {
    VIR_DOMAIN_DESTROY_DEFAULT   = 0,      /* Default behavior - could lead to data loss!! (Since: 0.9.10) */
    VIR_DOMAIN_DESTROY_GRACEFUL  = 1 << 0, /* only SIGTERM, no SIGKILL (Since: 0.9.10) */
    VIR_DOMAIN_DESTROY_REMOVE_LOGS = 1 << 1, /* remove VM logs on destroy (Since: 8.3.0) */
} virDomainDestroyFlagsValues;

/**
 * virDomainUndefineFlagsValues:
 *
 * Since: 0.9.4
 */
typedef enum {
    VIR_DOMAIN_UNDEFINE_MANAGED_SAVE       = (1 << 0), /* Also remove any
                                                          managed save (Since: 0.9.4) */
    VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA = (1 << 1), /* If last use of domain,
                                                          then also remove any
                                                          snapshot metadata (Since: 0.9.5) */
    VIR_DOMAIN_UNDEFINE_NVRAM              = (1 << 2), /* Also remove any
                                                          nvram file (Since: 1.2.9) */
    VIR_DOMAIN_UNDEFINE_KEEP_NVRAM         = (1 << 3), /* Keep nvram file (Since: 2.3.0) */
    VIR_DOMAIN_UNDEFINE_CHECKPOINTS_METADATA = (1 << 4), /* If last use of domain,
                                                            then also remove any
                                                            checkpoint metadata (Since: 5.6.0) */
    VIR_DOMAIN_UNDEFINE_TPM                = (1 << 5), /* Also remove any
                                                          TPM state (Since: 8.9.0) */
    VIR_DOMAIN_UNDEFINE_KEEP_TPM           = (1 << 6), /* Keep TPM state (Since: 8.9.0) */
    /* Future undefine control flags should come here. */
} virDomainUndefineFlagsValues;

/**
 * virErrorLevel:
 *
 * Indicates the level of an error
 *
 * Since: 0.1.0
 */
typedef enum {
    VIR_ERR_NONE = 0, /* (Since: 0.1.0) */
    VIR_ERR_WARNING = 1,        /* A simple warning (Since: 0.1.0) */
    VIR_ERR_ERROR = 2           /* An error (Since: 0.1.0) */
} virErrorLevel;

inline LogLevel virErrorLevelToLogLevel(virErrorLevel level)
{
    switch (level) {
        case VIR_ERR_WARNING: {
            return LogLevel::WARN;
        }
        case VIR_ERR_ERROR: {
            return LogLevel::ERROR;
        }
        default:
            return LogLevel::UNKNOWN;
    }
}

/**
 * virError:
 *
 * A libvirt Error instance.
 *
 * The conn, dom and net fields should be used with extreme care.
 * Reference counts are not incremented so the underlying objects
 * may be deleted without notice after the error has been delivered.
 *
 * Since: 0.1.0
 */
using virError = struct _virError;

/**
 * virErrorPtr:
 *
 * Since: 0.1.0
 */
using virErrorPtr = virError *;

struct _virError {
    int code;            /* The error code, a virErrorNumber */
    int domain;          /* What part of the library raised this error */
    char *message;       /* human-readable informative error message */
    virErrorLevel level; /* how consequent is the error */
    virConnectPtr conn;  /* connection if available, deprecated
                                          see note above */
    virDomainPtr dom;    /* domain if available, deprecated
                                        see note above */
    char *str1;          /* extra string information */
    char *str2;          /* extra string information */
    char *str3;          /* extra string information */
    int int1;            /* extra number information */
    int int2;            /* extra number information */
    virNetworkPtr net;   /* network if available, deprecated
                                         see note above */
};

using virErrorFunc = void (*)(void *userData, virErrorPtr error);

} // namespace virtrust