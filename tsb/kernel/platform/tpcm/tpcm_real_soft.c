#include <linux/version.h>
//#include <linux/kernel.h>
//#include <linux/module.h>
//#include <linux/slab.h>
//#include <linux/rtc.h>
//#include <linux/random.h>
//#include <linux/kthread.h>
//#include <linux/sched.h>
//#include <linux/freezer.h>

#include <linux/cred.h>

#include "../utils/debug.h"
#include "common.h"
#include "function_types.h"
#include "tpcm_def.h"
//#include "tcsapi/tcs_kernel.h"
#include "tcsapi/tcs_kernel_policy.h"
#include "tpcm/tdd.h"
#include "../log/log.h"
#include "../notify/notify.h"
#include "tpcmif.h"

/**
 * Digest by tpcm
 **/
int measure_digest_by_tpcm(
	uint32_t path_len, void *path_addr, uint32_t type,
	uint32_t num_block,struct physical_memory_block *blocks,
	uint32_t *tpcmRes,
	uint32_t *mrLen,	unsigned char *mresult)
{
	return 0;
}
EXPORT_SYMBOL(measure_digest_by_tpcm);

/**
 * Digest by tpcm simple
 **/
int measure_digest_by_tpcm_simple(
	int path_len, void *path_addr,
	uint32_t type, int hash_length,
	unsigned char *hash, uint32_t *tpcmRes)
{
	return 0;
}
EXPORT_SYMBOL(measure_digest_by_tpcm_simple);

unsigned long tpcm_virt_to_phys(void *address)
{

	return 0;
}
EXPORT_SYMBOL(tpcm_virt_to_phys);

int convert_intercept_type_for_tpcm(int type)
{
	switch (type) {
	case EXEC_CTL:
	case SCRIPT_CTL:
		return IMT_PROCESS_EXEC;
	case DYN_CTL:
		return IMT_DYNAMIC_LIBRARY_LOAD;
	case MODULE_CTL:
		return IMT_KERNEL_MODULE_LOAD;
	default:
		return 0;
	}
}
EXPORT_SYMBOL(convert_intercept_type_for_tpcm);

/**
 * Collect measure zone
 **/
int set_measure_zone_to_tpcm(char *name, void *address, int length)
{
	return 0;
}
EXPORT_SYMBOL(set_measure_zone_to_tpcm);

/**
 * Credential report
 **/
// credential count
// Smeasure
atomic_t ProcessExecCount;
atomic_t DynamicLibLoadCount;
atomic_t KernelModuleCount;
atomic_t FileAccessCount;
// Dmeasure
atomic_t PorcessCodeFailureCount;
atomic_t CriticalDataFailureCount;
atomic_t SectionFailureCount;

void smeasure_credential_count_init(void)
{
	atomic_set(&ProcessExecCount, 0);
	atomic_set(&DynamicLibLoadCount, 0);
	atomic_set(&KernelModuleCount, 0);
//	atomic_set(&FileAccessCount, 0);
}
EXPORT_SYMBOL(smeasure_credential_count_init);

void accessctl_credential_count_init(void)
{
	atomic_set(&FileAccessCount, 0);
}
EXPORT_SYMBOL(accessctl_credential_count_init);

void dmeasure_credential_count_init(void)
{
	atomic_set(&SectionFailureCount, 0);
	atomic_set(&CriticalDataFailureCount, 0);
	atomic_set(&PorcessCodeFailureCount, 0);
}
EXPORT_SYMBOL(dmeasure_credential_count_init);



void ProcessExecCount_add(void)
{
	atomic_inc(&ProcessExecCount);
}
EXPORT_SYMBOL(ProcessExecCount_add);

void DynamicLibLoadCount_add(void)
{
	atomic_inc(&DynamicLibLoadCount);
}
EXPORT_SYMBOL(DynamicLibLoadCount_add);

void KernelModuleCount_add(void)
{
	atomic_inc(&KernelModuleCount);
}
EXPORT_SYMBOL(KernelModuleCount_add);

void FileAccessCount_add(void)
{
	atomic_inc(&FileAccessCount);
}
EXPORT_SYMBOL(FileAccessCount_add);

void SectionFailureCount_add(void)
{
	atomic_inc(&SectionFailureCount);
}
EXPORT_SYMBOL(SectionFailureCount_add);

void CriticalDataFailureCount_add(void)
{
	atomic_inc(&CriticalDataFailureCount);
}
EXPORT_SYMBOL(CriticalDataFailureCount_add);

void ProcessCodeFailureCount_add(void)
{
	atomic_inc(&PorcessCodeFailureCount);
}
EXPORT_SYMBOL(ProcessCodeFailureCount_add);


static void get_tsb_runtime_info(struct tsb_runtime_info *tsb_info)
{
	int p_count, d_count, k_count;	// smeasure count
	int d_p_count = 0, d_critical_data_count = 0, d_section_count = 0;	// dmeasure count

	p_count = atomic_read(&ProcessExecCount);
	d_count = atomic_read(&DynamicLibLoadCount);
	k_count = atomic_read(&KernelModuleCount);
	d_p_count = atomic_read(&PorcessCodeFailureCount);
	d_critical_data_count = atomic_read(&CriticalDataFailureCount);
	d_section_count = atomic_read(&SectionFailureCount);

	memset(tsb_info, 0, sizeof(struct tsb_runtime_info));
	tsb_info->illegalProcessExecCount = p_count;
	tsb_info->illegalDynamicLibLoadCount = d_count;
	tsb_info->illegalKernelModuleLoadCount = k_count;
	tsb_info->measureProcessCodeFailureCount = d_p_count;
	tsb_info->measureKcodeMeasureFailCount = d_critical_data_count;
	tsb_info->measureKdataMeasureFailCount = d_section_count;

//	DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get runtime_info ProcessExecCount[%d] DynamicLibLoadCount[%d] KernelModuleCount[%d] PorcessCodeFailureCount[%d] success\n",
//		__func__, p_count, d_count, k_count, d_p_count);

	DEBUG_MSG(HTTC_TSB_DEBUG, "[tpcm_real_soft.c] Enter:[%s], get runtime_info ProcessExecCount[%d] DynamicLibLoadCount[%d] KernelModuleCount[%d] PorcessCodeFailureCount[%d]  KcodeMeasureFailCount[%d] KdataMeasureFailCount[%d] success\n",__func__, p_count, d_count, k_count, d_p_count, d_critical_data_count, d_section_count);

	return;
}


static void tpcm_util_dump_hex(unsigned char *name, void *p, int bytes)
{
	int i = 0;
	int len = 0;
	uint8_t *data = p;
	uint8_t buf[64] = { 0 };

	DEBUG_MSG(HTTC_TSB_DEBUG,"%s length=%d:\n", name, bytes);

	for (i = 0; i < bytes; i++) {
		if (len && (0 == len % 16)) {
			DEBUG_MSG(HTTC_TSB_DEBUG,"%s\n", buf);
			memset(buf, 0, sizeof(buf));
			len = 0;
		}

		len += sprintf(&buf[len], " %02X", data[i]);
	}

	DEBUG_MSG(HTTC_TSB_DEBUG,"%s\n", buf);
}

static inline void dump_tpcm_dmeasure_info(struct tpcm_log *log)
{
	dmlog_st *dm = (dmlog_st *) log->log;
	//int length = NTOHL(dm->uiLength);

	/* tpcm_util_dump_hex("format_dmeasure_log", dm, length); */

	DEBUG_MSG(HTTC_TPCM_DEBUG,
		  "time: %ld, uiType: %d, uiLength: %d, uiRelativeSec: %d, uiRelativeMsec: %d, aucName: %s, uiResult: %d\n",
		  log->time.tv_sec, NTOHL(dm->uiType), NTOHL(dm->uiLength),
		  NTOHL(dm->uiRelativeSec), NTOHL(dm->uiRelativeMsec),
		  dm->aucName, NTOHL(dm->uiResult));

	tpcm_util_dump_hex("aucDigest", dm->aucDigest, 32);
}

static inline void dump_tpcm_bmeasure_info(struct tpcm_log *log)
{
	bmlog_st *bm = (bmlog_st *) log->log;
	//int length = NTOHL(bm->uiLength);

	/* tpcm_util_dump_hex("format_bmeasure_log", bm, length); */

	DEBUG_MSG(HTTC_TPCM_DEBUG,
		  "time: %ld, uiType: %d, uiLength: %d, uiRelativeSec: %d, uiRelativeMsec: %d, uiStage: %d, uiResult: %d, aucName: %s, uiNameLength: %d\n",
		  log->time.tv_sec, NTOHL(bm->uiType), NTOHL(bm->uiLength),
		  NTOHL(bm->uiRelativeSec), NTOHL(bm->uiRelativeMsec),
		  NTOHL(bm->uiStage), NTOHL(bm->uiResult), bm->aucName,
		  NTOHL(bm->uiNameLength));
	tpcm_util_dump_hex("aucDigest", bm->aucDigest, 32);
}

int format_bmeasure_log(struct tpcm_log *log)
{
	int ret = 0;
	uint32_t type, length = 0;
	uint32_t name_len = 0;
	bmlog_st *tpcm = NULL;
	struct sec_domain *sec_d;
	struct tpcm_audit_log tpcm_audit;
	unsigned int user = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	user = __kuid_val(current->cred->uid);
#else
	user = current->cred->uid;
#endif

	dump_tpcm_bmeasure_info(log);

	sec_d = kzalloc(sizeof(struct sec_domain), GFP_KERNEL);
	if (!sec_d) {
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], kzalloc error!\n", __func__);
		ret = -ENOMEM;
		goto out;
	}

	memcpy(sec_d->obj_name, "B_Measure", strlen("B_Measure"));

	memset(&tpcm_audit, 0, sizeof(tpcm_audit));

	tpcm = (bmlog_st *) log->log;
	type = NTOHL(tpcm->uiType);
	length = NTOHL(tpcm->uiLength);

	memset(sec_d->sub_hash, 0, LEN_HASH);
	memcpy(sec_d->sub_hash, tpcm->aucDigest, 32);

	memset(sec_d->sub_name, 0, LEN_NAME_MAX);
	name_len = NTOHL(tpcm->uiNameLength);
	if (name_len > 0) {
		if (name_len < LEN_NAME_MAX)
			memcpy(sec_d->sub_name, tpcm->aucName, name_len);
		else
			memcpy(sec_d->sub_name, tpcm->aucName,
			       LEN_NAME_MAX - 1);
	}

	switch (NTOHL(tpcm->uiResult)) {
	case 0:
		tpcm_audit.result = RESULT_SUCCESS;
		break;
	case 1:
		tpcm_audit.result = RESULT_FAIL;
		break;
	case 2:
		tpcm_audit.result = RESULT_UNMEASURED;
		break;
	default:
		break;
	}

	tpcm_audit.t_sec = log->time.tv_sec;
	tpcm_audit.type = TYPE_BMEASURE;
	tpcm_audit.operate = NTOHL(tpcm->uiStage);

	keraudit_log_from_tpcm(&tpcm_audit, sec_d, user,
			       current->pid);

out:
	return ret;
}

int format_dmeasure_log(struct tpcm_log *log)
{
	int ret = 0;
	uint32_t type, length, result = 0;
	dmlog_st *tpcm = NULL;
	struct sec_domain *sec_d;
	struct tpcm_audit_log tpcm_audit;
	unsigned int user = 0;

	dump_tpcm_dmeasure_info(log);

	sec_d = kzalloc(sizeof(struct sec_domain), GFP_KERNEL);
	if (!sec_d) {
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], kzalloc error!\n", __func__);
		ret = -ENOMEM;
		goto out;
	}

	tpcm_audit.t_sec = log->time.tv_sec;

	tpcm = (dmlog_st *) log->log;
	type = NTOHL(tpcm->uiType);
	length = NTOHL(tpcm->uiLength);

	//tpcm_util_dump_hex("format_dmeasure_log", tpcm, length);

	memcpy(sec_d->obj_name, tpcm->aucName, 32);
	memcpy(sec_d->sub_hash, tpcm->aucDigest, 32);

	result = NTOHL(tpcm->uiResult);

	tpcm_audit.operate = DMEASURE_OPERATE_PERIODICITY;
	tpcm_audit.result = (result) ? RESULT_FAIL : RESULT_SUCCESS;

	tpcm_audit.type = TYPE_DMEASURE;
	memcpy(sec_d->sub_name, tpcm->aucName, 32);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	user = __kuid_val(current->cred->uid);
#else
	user = current->cred->uid;
#endif
	keraudit_log_from_tpcm(&tpcm_audit, sec_d, user,
			       current->pid);

out:
	return ret;
}

static void tpcm_log_process(struct tpcm_log *log)
{
	int ret = 0;
	int type, len = 0;

	type = log->type;
	len = log->length;

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], type:[%d], len:[%d]\n", __func__, type, len);

	//tpcm_util_dump_hex ("tpcm_log dump", log, len);

	switch (type) {
	case TPCM_LOG_TYPE_BMEASURE:
		ret = format_bmeasure_log(log);
		break;
	case TPCM_LOG_TYPE_DMEASURE:
		ret = format_dmeasure_log(log);
		break;
	default:
		break;
	}

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], Done\n", __func__);
	return;
}

static void tpcm_notify_call(struct tpcm_notify *log)
{
	
	int len = 0;
	struct notify entry = {0};

	entry.type = log->type;
	entry.length = log->length;
	len = sizeof(entry.buf)>sizeof(log->notify) ? sizeof(log->notify):sizeof(entry.buf);
	memcpy(entry.buf, log->notify, len);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], added notice buf[%s] length[%d] type[%d]!\n", __func__, entry.buf, entry.length, entry.type);

	tsb_put_notify(&entry);

	return;
}

int tpcm_log_init(void)
{
	int ret = 0;

	return ret;
}

int tpcm_log_exit(void)
{

	return 0;

}



int get_process_ids(struct process_identity **ids,int *num,int *length)
{
	return 0;
}
EXPORT_SYMBOL(get_process_ids);

int get_process_roles(struct process_role **roles,int *num,int *length)
{
	return 0;
}
EXPORT_SYMBOL(get_process_roles);

int register_process_identity_callback(struct process_identity_callback *process_identity_callback)
{
	return 0;
}
EXPORT_SYMBOL(register_process_identity_callback);

int unregister_process_identity_callback(struct process_identity_callback *process_identity_callback)
{
	return 0;
}
EXPORT_SYMBOL(unregister_process_identity_callback);

int get_global_control_policy(struct global_control_policy *policy)
{
	return 0;
}
EXPORT_SYMBOL(get_global_control_policy);

int get_dmeasure_policy(struct dmeasure_policy_item **policy,int *item_count,int *length)
{
	return 0;
}
EXPORT_SYMBOL(get_dmeasure_policy);

int get_dmeasure_process_policy(struct dmeasure_process_item **policy,int *item_count,int *length)
{
	return 0;
}
EXPORT_SYMBOL(get_dmeasure_process_policy);

int get_ptrace_policy(struct ptrace_protect **policy, int *length)
{
	return 0;
}
EXPORT_SYMBOL(get_ptrace_policy);

int get_tpcm_features(uint32_t *features)
{
	int ret = 0;

	ret =0;
	
	return ret;
}


int register_tsb_measure_env_callback(tsb_measure_env callback)
{
	return 0;
}
EXPORT_SYMBOL(register_tsb_measure_env_callback);

int unregister_tsb_measure_env_callback(tsb_measure_env callback)
{
	return 0;
}
EXPORT_SYMBOL(unregister_tsb_measure_env_callback);
//0：动态度量 1：拦截度量   该接口各类型仅调用一次即可
static int trust_status_called[2] = {0};
int sync_trust_status(uint32_t type)
{
	return 0;
}
EXPORT_SYMBOL(sync_trust_status);

int get_file_integrity_digest(unsigned char *digest ,unsigned int *digest_len)
{
	return 123456;
}
EXPORT_SYMBOL(get_file_integrity_digest);

int get_critical_file_integrity_digest(unsigned char *digest ,unsigned int *digest_len)
{

	return 123456;
}
EXPORT_SYMBOL(get_critical_file_integrity_digest);
