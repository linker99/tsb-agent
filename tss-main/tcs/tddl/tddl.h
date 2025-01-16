#ifndef __TDDL_H__
#define __TDDL_H__

#define S3_ON 	0
#define S3_OFF 	1
#define S4_OFF 	2
#define S4_ON 	3

typedef int (*TDDL_IOCTL_PROC) (void *cmd, int cmdLen, void *rsp, int *rspLen);
typedef int (*pm_call_back)(void);

int tpcm_pm_callback_register(pm_call_back call_back_fun,int pm_type);
int tpcm_pm_callback_unregister(pm_call_back call_back_fun, int pm_type);

int tpcm_ioctl_proc_register (TDDL_IOCTL_PROC func);
int tpcm_ioctl_proc_unregister (TDDL_IOCTL_PROC func);

int tcm_tddl_transmit_cmd (void *command, int length, void *result, int *rlength);
int tpcm_tddl_transmit_cmd (void *command, int length, void *result, int *rlength);


#endif	/** __TDDL_H__ */

