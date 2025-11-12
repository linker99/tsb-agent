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
    VIR_CONNECT_LIST_DOMAINS_ACTIVE = 1 << 0,   /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_INACTIVE = 1 << 1, /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_PERSISTENT = 1 << 2, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_TRANSIENT = 1 << 3,  /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_RUNNING = 1 << 4, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_PAUSED = 1 << 5,  /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_SHUTOFF = 1 << 6, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_OTHER = 1 << 7,   /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE = 1 << 8,    /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE = 1 << 9, /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_AUTOSTART = 1 << 10,    /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART = 1 << 11, /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT = 1 << 12, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT = 1 << 13,  /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_HAS_CHECKPOINT = 1 << 14, /* (Since: 5.6.0) */
    VIR_CONNECT_LIST_DOMAINS_NO_CHECKPOINT = 1 << 15,  /* (Since: 5.6.0) */
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
    VIR_DOMAIN_NONE = 0,                    /* Default behavior (Since: 0.0.1) */
    VIR_DOMAIN_START_PAUSED = 1 << 0,       /* Launch guest in paused state (Since: 0.8.2) */
    VIR_DOMAIN_START_AUTODESTROY = 1 << 1,  /* Automatically kill guest when virConnectPtr is closed (Since:
                                               0.9.3) */
    VIR_DOMAIN_START_BYPASS_CACHE = 1 << 2, /* Avoid file system cache pollution (Since: 0.9.4) */
    VIR_DOMAIN_START_FORCE_BOOT = 1 << 3,   /* Boot, discarding any managed save (Since: 0.9.5) */
    VIR_DOMAIN_START_VALIDATE = 1 << 4,     /* Validate the XML document against schema (Since: 1.2.12) */
    VIR_DOMAIN_START_RESET_NVRAM = 1 << 5,  /* Re-initialize NVRAM from template (Since: 8.1.0) */
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
    VIR_DOMAIN_DESTROY_DEFAULT = 0,          /* Default behavior - could lead to data loss!! (Since: 0.9.10) */
    VIR_DOMAIN_DESTROY_GRACEFUL = 1 << 0,    /* only SIGTERM, no SIGKILL (Since: 0.9.10) */
    VIR_DOMAIN_DESTROY_REMOVE_LOGS = 1 << 1, /* remove VM logs on destroy (Since: 8.3.0) */
} virDomainDestroyFlagsValues;

/**
 * virDomainUndefineFlagsValues:
 *
 * Since: 0.9.4
 */
typedef enum {
    VIR_DOMAIN_UNDEFINE_MANAGED_SAVE = (1 << 0),         /* Also remove any
                                                            managed save (Since: 0.9.4) */
    VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA = (1 << 1),   /* If last use of domain,
                                                            then also remove any
                                                            snapshot metadata (Since: 0.9.5) */
    VIR_DOMAIN_UNDEFINE_NVRAM = (1 << 2),                /* Also remove any
                                                            nvram file (Since: 1.2.9) */
    VIR_DOMAIN_UNDEFINE_KEEP_NVRAM = (1 << 3),           /* Keep nvram file (Since: 2.3.0) */
    VIR_DOMAIN_UNDEFINE_CHECKPOINTS_METADATA = (1 << 4), /* If last use of domain,
                                                            then also remove any
                                                            checkpoint metadata (Since: 5.6.0) */
    VIR_DOMAIN_UNDEFINE_TPM = (1 << 5),                  /* Also remove any
                                                            TPM state (Since: 8.9.0) */
    VIR_DOMAIN_UNDEFINE_KEEP_TPM = (1 << 6),             /* Keep TPM state (Since: 8.9.0) */
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
    VIR_ERR_NONE = 0,    /* (Since: 0.1.0) */
    VIR_ERR_WARNING = 1, /* A simple warning (Since: 0.1.0) */
    VIR_ERR_ERROR = 2    /* An error (Since: 0.1.0) */
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

/**
 * virDomainMigrateFlags:
 *
 * Domain migration flags.
 *
 * Since: 0.3.2
 */
typedef enum {
    /* Do not pause the domain during migration. The domain's memory will
     * be transferred to the destination host while the domain is running.
     * The migration may never converge if the domain is changing its memory
     * faster then it can be transferred. The domain can be manually paused
     * anytime during migration using virDomainSuspend.
     *
     * Since: 0.3.2
     */
    VIR_MIGRATE_LIVE = (1 << 0),

    /* Tell the source libvirtd to connect directly to the destination host.
     * Without this flag the client (e.g., virsh) connects to both hosts and
     * controls the migration process. In peer-to-peer mode, the source
     * libvirtd controls the migration by calling the destination daemon
     * directly.
     *
     * Since: 0.7.2
     */
    VIR_MIGRATE_PEER2PEER = (1 << 1),

    /* Tunnel migration data over libvirtd connection. Without this flag the
     * source hypervisor sends migration data directly to the destination
     * hypervisor. This flag can only be used when VIR_MIGRATE_PEER2PEER is
     * set as well.
     *
     * Note the less-common spelling that we're stuck with:
     * VIR_MIGRATE_TUNNELLED should be VIR_MIGRATE_TUNNELED.
     *
     * Since: 0.7.2
     */
    VIR_MIGRATE_TUNNELLED = (1 << 2),

    /* Define the domain as persistent on the destination host after successful
     * migration. If the domain was persistent on the source host and
     * VIR_MIGRATE_UNDEFINE_SOURCE is not used, it will end up persistent on
     * both hosts.
     *
     * Since: 0.7.3
     */
    VIR_MIGRATE_PERSIST_DEST = (1 << 3),

    /* Undefine the domain on the source host once migration successfully
     * finishes.
     *
     * Since: 0.7.3
     */
    VIR_MIGRATE_UNDEFINE_SOURCE = (1 << 4),

    /* Leave the domain suspended on the destination host. virDomainResume (on
     * the virDomainPtr returned by the migration API) has to be called
     * explicitly to resume domain's virtual CPUs.
     *
     * Since: 0.7.5
     */
    VIR_MIGRATE_PAUSED = (1 << 5),

    /* Migrate full disk images in addition to domain's memory. By default
     * only non-shared non-readonly disk images are transferred. The
     * VIR_MIGRATE_PARAM_MIGRATE_DISKS parameter can be used to specify which
     * disks should be migrated.
     *
     * This flag and VIR_MIGRATE_NON_SHARED_INC are mutually exclusive.
     *
     * Since: 0.8.2
     */
    VIR_MIGRATE_NON_SHARED_DISK = (1 << 6),

    /* Migrate disk images in addition to domain's memory. This is similar to
     * VIR_MIGRATE_NON_SHARED_DISK, but only the top level of each disk's
     * backing chain is copied. That is, the rest of the backing chain is
     * expected to be present on the destination and to be exactly the same as
     * on the source host.
     *
     * This flag and VIR_MIGRATE_NON_SHARED_DISK are mutually exclusive.
     *
     * Since: 0.8.2
     */
    VIR_MIGRATE_NON_SHARED_INC = (1 << 7),

    /* Protect against domain configuration changes during the migration
     * process. This flag is used automatically when both sides support it.
     * Explicitly setting this flag will cause migration to fail if either the
     * source or the destination does not support it.
     *
     * Since: 0.9.4
     */
    VIR_MIGRATE_CHANGE_PROTECTION = (1 << 8),

    /* Force migration even if it is considered unsafe. In some cases libvirt
     * may refuse to migrate the domain because doing so may lead to potential
     * problems such as data corruption, and thus the migration is considered
     * unsafe. For a QEMU domain this may happen if the domain uses disks
     * without explicitly setting cache mode to "none". Migrating such domains
     * is unsafe unless the disk images are stored on coherent clustered
     * filesystem, such as GFS2 or GPFS.
     *
     * Since: 0.9.11
     */
    VIR_MIGRATE_UNSAFE = (1 << 9),

    /* Migrate a domain definition without starting the domain on the
     * destination and without stopping it on the source host. Offline
     * migration requires VIR_MIGRATE_PERSIST_DEST to be set.
     *
     * Offline migration may not copy disk storage or any other file based
     * storage (such as UEFI variables).
     *
     * Since: 1.0.1
     */
    VIR_MIGRATE_OFFLINE = (1 << 10),

    /* Compress migration data. The compression methods can be specified using
     * VIR_MIGRATE_PARAM_COMPRESSION. A hypervisor default method will be used
     * if this parameter is omitted. Individual compression methods can be
     * tuned via their specific VIR_MIGRATE_PARAM_COMPRESSION_* parameters.
     *
     * Since: 1.0.3
     */
    VIR_MIGRATE_COMPRESSED = (1 << 11),

    /* Cancel migration if a soft error (such as I/O error) happens during
     * migration.
     *
     * Since: 1.1.0
     */
    VIR_MIGRATE_ABORT_ON_ERROR = (1 << 12),

    /* Enable algorithms that ensure a live migration will eventually converge.
     * This usually means the domain will be slowed down to make sure it does
     * not change its memory faster than a hypervisor can transfer the changed
     * memory to the destination host. VIR_MIGRATE_PARAM_AUTO_CONVERGE_*
     * parameters can be used to tune the algorithm.
     *
     * Since: 1.2.3
     */
    VIR_MIGRATE_AUTO_CONVERGE = (1 << 13),

    /* This flag can be used with RDMA migration (i.e., when
     * VIR_MIGRATE_PARAM_URI starts with "rdma://") to tell the hypervisor
     * to pin all domain's memory at once before migration starts rather then
     * letting it pin memory pages as needed. This means that all memory pages
     * belonging to the domain will be locked in host's memory and the host
     * will not be allowed to swap them out.
     *
     * For QEMU/KVM this requires hard_limit memory tuning element (in the
     * domain XML) to be used and set to the maximum memory configured for the
     * domain plus any memory consumed by the QEMU process itself. Beware of
     * setting the memory limit too high (and thus allowing the domain to lock
     * most of the host's memory). Doing so may be dangerous to both the
     * domain and the host itself since the host's kernel may run out of
     * memory.
     *
     * Since: 1.2.9
     */
    VIR_MIGRATE_RDMA_PIN_ALL = (1 << 14),

    /* Setting the VIR_MIGRATE_POSTCOPY flag tells libvirt to enable post-copy
     * migration. However, the migration will start normally and
     * virDomainMigrateStartPostCopy needs to be called to switch it into the
     * post-copy mode. See virDomainMigrateStartPostCopy for more details.
     *
     * Since: 1.3.3
     */
    VIR_MIGRATE_POSTCOPY = (1 << 15),

    /* Setting the VIR_MIGRATE_TLS flag will cause the migration to attempt
     * to use the TLS environment configured by the hypervisor in order to
     * perform the migration. If incorrectly configured on either source or
     * destination, the migration will fail.
     *
     * Since: 3.2.0
     */
    VIR_MIGRATE_TLS = (1 << 16),

    /* Send memory pages to the destination host through several network
     * connections. See VIR_MIGRATE_PARAM_PARALLEL_* parameters for
     * configuring the parallel migration.
     *
     * Since: 5.2.0
     */
    VIR_MIGRATE_PARALLEL = (1 << 17),

    /* Force the guest writes which happen when copying disk images for
     * non-shared storage migration to be synchronously written to the
     * destination. This ensures the storage migration converges for VMs
     * doing heavy I/O on fast local storage and slow mirror.
     *
     * Requires one of VIR_MIGRATE_NON_SHARED_DISK, VIR_MIGRATE_NON_SHARED_INC
     * to be present as well.
     *
     * Since: 8.0.0
     */
    VIR_MIGRATE_NON_SHARED_SYNCHRONOUS_WRITES = (1 << 18),

    /* Resume migration which failed in post-copy phase.
     *
     * Since: 8.5.0
     */
    VIR_MIGRATE_POSTCOPY_RESUME = (1 << 19),

    /* Use zero-copy mechanism for migrating memory pages. For QEMU/KVM this
     * means QEMU will be temporarily allowed to lock all guest pages in host's
     * memory, although only those that are queued for transfer will be locked
     * at the same time.
     *
     * Since: 8.5.0
     */
    VIR_MIGRATE_ZEROCOPY = (1 << 20),
} virDomainMigrateFlags;

} // namespace virtrust