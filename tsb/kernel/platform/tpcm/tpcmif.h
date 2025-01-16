#ifndef __TPCMIF_H
#define __TPCMIF_H

#include <linux/stddef.h>
#include <linux/module.h>
//#include <linux/skbuff.h>
//#include <net/sock.h>
#include "function_types.h"
#include "tcsapi/tcs_kernel.h"
//#include "tcsapi/tcs_file_integrity.h"
#include "tcsapi/tcs_process_def.h"
#include "tcsapi/tcs_policy_def.h"
#include "tcsapi/tcs_dmeasure_def.h"
#include "tcsapi/tcs_protect_def.h"
#include "tcsapi/tcs_attest_def.h"
#include "tcsapi/tcs_license_def.h"


#define IMT_PROCESS_EXEC			1
#define IMT_DYNAMIC_LIBRARY_LOAD	2
#define IMT_KERNEL_MODULE_LOAD		3

#define OP_CTX_DM_INIT_COLLECT	0	/** Dynamic measure init data collect */



void smeasure_credential_count_init(void);
void accessctl_credential_count_init(void);
void ProcessCodeFailureCount_add(void);
void ProcessExecCount_add(void);
void DynamicLibLoadCount_add(void);
void KernelModuleCount_add(void);
void FileAccessCount_add(void);

void dmeasure_credential_count_init(void);
void SectionFailureCount_add(void);
void CriticalDataFailureCount_add(void);
void ProcessCodeFailureCount_add(void);

int tpcm_log_init(void);
int tpcm_log_exit(void);

int set_measure_zone_to_tpcm(char *name, void *address, int length);

static inline int is_allowed_send_log(int type)
{
	switch (type) {
	case RESULT_SUCCESS:
#ifdef TPCM_REAL
		return false;
#else
		return true;
#endif
	case RESULT_FAIL:
		return true;
	default:
		return true;
	}
}

int measure_digest_by_tpcm(	uint32_t path_len, void *path_addr, uint32_t type,
					uint32_t num_block,struct physical_memory_block *blocks,
					uint32_t *tpcmRes,
					uint32_t *mrLen,	unsigned char *mresult);
int measure_digest_by_tpcm_simple(int path_len, void *path_addr,
					uint32_t type, int hash_length,
					unsigned char *hash, uint32_t *tpcmRes);
unsigned long tpcm_virt_to_phys(void *buffer);
int convert_intercept_type_for_tpcm(int type);

//process_identity
int get_process_ids(struct process_identity **ids,int *num,int *length);
int get_process_roles(struct process_role **roles,int *num,int *length);
int register_process_identity_callback(struct process_identity_callback *process_identity_callback);
int unregister_process_identity_callback(struct process_identity_callback *process_identity_callback);

int get_global_control_policy(struct global_control_policy *policy);
int get_dmeasure_policy(struct dmeasure_policy_item **policy,int *item_count,int *length);
int get_dmeasure_process_policy(struct dmeasure_process_item **policy,int *item_count,int *length);

int get_ptrace_policy(struct ptrace_protect **policy, int *length);

int get_tpcm_features(uint32_t *features);

#ifndef LICENSE_21_VER
int get_license_info(int *status, uint64_t *deadline);
int get_tsb_license_info(uint64_t *deadline);
#else
int get_license_info(int *status, uint64_t *deadline, struct license_arg iParam);
#endif
int register_tsb_measure_env_callback(tsb_measure_env callback);
int unregister_tsb_measure_env_callback(tsb_measure_env callback);

int sync_trust_status(uint32_t type);

int get_file_integrity_digest(unsigned char *digest ,unsigned int *digest_len);
int get_critical_file_integrity_digest(unsigned char *digest ,unsigned int *digest_len);

void jump_entry_check_func_register(void *func);
void jump_entry_check_func_unregister(void *func);

#endif
