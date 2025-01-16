#ifndef __TCS_TPCM_H__
#define __TCS_TPCM_H__

#include "tcs_kernel.h"

/** Reference type */
enum{
	RT_BOOT_MEASURE = 1,
	RT_WHILELIST,
};

int tpcm_ioctl_sm3 (void *ucmd, int ucmdLen, void *rsp, int *rspLen);
int tpcm_ioctl_sm3_update (void *ucmd, int ucmdLen, void *rsp, int *rspLen);
int tpcm_ioctl_sm3_finish (void *ucmd, int ucmdLen, void *rsp, int *rspLen);
int tpcm_ioctl_sm4_encrypt (void *ucmd, int ucmdLen, void *rsp, int *rspLen);
int tpcm_ioctl_sm4_decrypt (void *ucmd, int ucmdLen, void *rsp, int *rspLen);
int tpcm_ioctl_sm2_sign_e (void *ucmd, int ucmdLen, void *rsp, int *rspLen);
int tpcm_ioctl_sm2_verify_e (void *ucmd, int ucmdLen, void *rsp, int *rspLen);
int tpcm_ioctl_read_file_integrity (void *ucmd, int ucmdLen, void *rsp, int *rspLen);
int tpcm_ioctl_firmware_upgrade (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
int tcs_ioctl_update_dynamic_policy (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
int tcs_ioctl_update_dynamic_process_policy (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
int tcs_ioctl_update_process_ids (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
int tcs_ioctl_update_process_roles (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
int tcs_ioctl_set_control_policy (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
int tcs_ioctl_set_admin_auth_policies (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
int tcs_ioctl_update_ptrace_protect_policy (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
int tcs_ioctl_set_measure_control_switch (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
int tcs_ioctl_update_tnc_policy(uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
int tpcm_ioctl_integrity_measure (void *ucmd, int ucmdLen, void *rsp, int *rspLen);
int tpcm_ioctl_sync_trust_status(uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
int tpcm_ioctl_get_trusted_status(uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
int tpcm_ioctl_get_dmeasure_trusted_status(uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
int tpcm_ioctl_get_intercept_trusted_status(uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
int tpcm_ioctl_update_reference_increment (void *ucmd, int ucmdLen, void *rsp, int *rspLen);
int tcs_ioctl_reset_license (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
int tpcm_ioctl_generate_trust_report(uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
int	tcs_ioctl_update_cert_root (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);
/** 获取 tpcm id */
int tcs_ioctl_get_tpcm_id(uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen);

int tpcm_pm_callbacks_register (void);
void tpcm_pm_callbacks_unregister (void);
void tpcm_notifier(unsigned int pnotify_type,unsigned long param);

int tpcm_get_trust_status(uint32_t *status);
int tcsk_set_system_time(uint64_t nowtime, uint32_t *tpcmRes);
int tcsk_boot_measure (uint32_t stage, uint32_t num,
			struct physical_memory_block *block, uint64_t objAddr, uint32_t objLen, uint32_t *tpcmRes);
int tcsk_simple_boot_measure (uint32_t stage, uint8_t* digest, uint8_t *obj, uint32_t objLen, uint32_t *tpcmRes);
int tcs_get_tsb_trust_info(struct tsb_runtime_info * info);

#endif	/** __TCS_TPCM_H__ */

