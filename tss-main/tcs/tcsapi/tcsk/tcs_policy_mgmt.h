#ifndef _TCS_POLICY_MANAGEMENT_H__
#define _TCS_POLICY_MANAGEMENT_H__

#include "tcs_tnc_def.h"
#include "tcs_auth_def.h"
#include "tcs_process.h"

struct tcs_policy_management{
	struct mutex mutex;
	struct global_control_policy *global_ctrl_policy;
	
	int admin_auth_policy_num;
	struct admin_auth_policy *admin_auth_policy_list;
	
	int process_id_num;
	int process_id_size;
	struct process_identity *process_ids;

	int process_role_num;
	int process_role_size;
	struct process_role *process_roles;

	int dmeasure_policy_num;
	int dmeasure_policy_size;	
	struct dmeasure_policy_item *dmeasure_policy_list;

    int dmeasure_process_policy_num;
    int dmeasure_process_policy_size;
    struct dmeasure_process_item *dmeasure_process_policy_list;

	int ptrace_protect_policy_size;
	struct ptrace_protect *ptrace_protect_policy;
	
	int tnc_policy_size;
	struct tnc_policy *tnc_policy;
};

extern struct tcs_policy_management *gst_policy_mgmt;

int tcs_policy_management_init (void);
int tcs_policy_management_reload (void);
int tcs_util_get_admin_auth_policies (struct admin_auth_policy **list, int *list_size);
int tcs_util_set_admin_auth_policies (struct admin_auth_policy *list, int list_size);
int tcs_util_set_process_ids (struct process_identity *ids, int num, int length);
int tcs_util_set_process_roles (struct process_role *roles, int num, int length);
int tcs_util_set_global_control_policy (struct global_control_policy *policy);
int tcs_util_set_dmeasure_policy (struct dmeasure_policy_item *policy, int item_count, int length);
int tcs_util_set_dmeasure_process_policy (struct dmeasure_process_item *policy, int item_count, int length);
int tcs_util_set_ptrace_protect_policy (struct ptrace_protect *policy, int length);
int tcs_util_set_tnc_policy (struct tnc_policy *policy, int length);

int tcs_util_get_process_identity (unsigned char *process_name, int *process_name_length);
int tcs_util_is_role_member (const unsigned char *role_name);
int tcs_util_calc_policy_hash (uint32_t object_id, uint8_t *hash, int *hash_len);
int tcs_util_tsb_measure_env (void);
int tcs_util_set_tpcm_id(void);

int tcs_util_read_policy (const char* path, void **policy, int *size, int *num);
int tcs_util_write_policy (const char* path, void *policy, int size, int num);

#endif	/** _TCS_POLICY_MANAGEMENT_H__ */

