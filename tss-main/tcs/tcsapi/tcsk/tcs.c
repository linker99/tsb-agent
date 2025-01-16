#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <asm/io.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include "memdebug.h"
#include "debug.h"
#include "kutils.h"
#include "version.h"
#include "tdd.h"
#include "tddl.h"
#include "tcs_error.h"
#include "tcs_tpcm_error.h"
#include "tcs_config.h"
#include "tpcm_command.h"
#include "tcs_policy_mgmt.h"
#include "tcs_kernel.h"
#include "tcs_constant.h"

#include "tcs_tcm.h"
#include "tcs_tpcm.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tpcm_measure");



uint32_t gui_trust_status = STATUS_TRUSTED;
uint32_t dmeasure_trust_status = STATUS_TRUSTED;
uint32_t intercept_trust_status = STATUS_TRUSTED;

struct tcs_mmap_mgmt_st{
	struct mutex lock;
	int seg_limit;
	int virt_addr_seg_num;			/** 虚拟地址段数目 */
	uint8_t **virt_addr_seg_list;	/** 虚拟地址段指针链表 */
};
struct tcs_mmap_mgmt_st tcs_mmap_mgmt;

uint8_t** tcs_util_get_tcs_mmap_addr_list (void){
	return tcs_mmap_mgmt.virt_addr_seg_list;
}
int tcs_util_get_tcs_mmap_addr_num (void){
	return tcs_mmap_mgmt.virt_addr_seg_num;
}
int tcs_util_get_tcs_mmap_seg_limit (void){
	return tcs_mmap_mgmt.seg_limit;
}

#pragma pack(push, 1)

typedef struct{
	COMMAND_HEADER;
	uint64_t udTime;
}set_system_time_st;

typedef struct tcs_req_inform_update{
	COMMAND_HEADER;
	unsigned int ord;
	int size;
	int num;
	uint8_t policy[0];
}tcs_req_inform_update_st;

#pragma pack(pop)

int tcsk_set_system_time(uint64_t nowtime, uint32_t *tpcmRes){
	int ret = 0;
	uint32_t cmdLen = 0;
	uint64_t settime = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	set_system_time_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if (NULL == (buffer = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	
	cmd = (set_system_time_st *)buffer;
	rsp = (tpcm_rsp_header_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof (set_system_time_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_SetSystemTime);	
	settime = htonll(nowtime);
	tpcm_memcpy ((char *)&cmd->udTime,(char *)&settime, 8);

	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)))	goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	*tpcmRes = tpcmRspRetCode (rsp);
out:	
	if (buffer) tdd_free_data_buffer (buffer);
	//DEBUG (ret);
	return ret;
	
}
EXPORT_SYMBOL_GPL (tcsk_set_system_time);

int tpcm_ioctl_inform_policy (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen)
{
	struct tcs_req_inform_update *cmd = (struct tcs_req_inform_update *)ucmd;

	httc_util_dump_hex ("Inform policy", ucmd, ucmdLen);
	//httc_util_dump_hex ("policy", (struct admin_auth_policy *)cmd->policy, cmd->size);

	switch (cmd->ord){
		case TPCM_ORD_SetAdminAuthPolicies:
			((tpcm_rsp_header_st*)rsp)->uiRspRet = tcs_util_set_admin_auth_policies ((struct admin_auth_policy *)cmd->policy, cmd->size/sizeof(struct admin_auth_policy));
			break;
		case TPCM_ORD_UpdateFileProtectPolicy:
			((tpcm_rsp_header_st*)rsp)->uiRspRet = 0;
			break;
//		case TPCM_ORD_GrantAdminRole:
//			((tpcm_rsp_header_st*)rsp)->uiRspRet = tcs_util_set_admin_cert ((struct admin_cert_item*)cmd->policy, cmd->size/sizeof(struct admin_cert_item));
//			break;
		case TPCM_ORD_UpdateProcessIdentity:
			((tpcm_rsp_header_st*)rsp)->uiRspRet = tcs_util_set_process_ids ((struct process_identity*)cmd->policy, cmd->num, cmd->size);
			break;
		case TPCM_ORD_UpdateProcessRoles:
			((tpcm_rsp_header_st*)rsp)->uiRspRet = tcs_util_set_process_roles ((struct process_role*)cmd->policy, cmd->num, cmd->size);
			break;
		case TPCM_ORD_SetGlobalControlPolicy:
			((tpcm_rsp_header_st*)rsp)->uiRspRet = tcs_util_set_global_control_policy ((struct global_control_policy*)cmd->policy);
			break;
		case TPCM_ORD_SetSignDMeasurePolicy:
			((tpcm_rsp_header_st*)rsp)->uiRspRet = tcs_util_set_dmeasure_policy ((struct dmeasure_policy_item*)cmd->policy, cmd->num, cmd->size);
			break;
		case TPCM_ORD_UpdateDmeasureProcessPolicy:
			((tpcm_rsp_header_st*)rsp)->uiRspRet = tcs_util_set_dmeasure_process_policy ((struct dmeasure_process_item*)cmd->policy, cmd->num, cmd->size);
			break;
		case TPCM_ORD_UpdatePtraceProtectsPolicy:
			((tpcm_rsp_header_st*)rsp)->uiRspRet = tcs_util_set_ptrace_protect_policy ((struct ptrace_protect*)cmd->policy, cmd->size);
			break;
		case TPCM_ORD_UpdateTncPolicy:
			((tpcm_rsp_header_st*)rsp)->uiRspRet = tcs_util_set_tnc_policy ((struct tnc_policy*)cmd->policy, cmd->size);
			break;
//		case TPCM_ORD_UpdateFileintergrityDigest:
//			((tpcm_rsp_header_st*)rsp)->uiRspRet = tcs_util_set_file_integrity_digest ((unsigned char*)cmd->policy, cmd->size);
//			break;
//		case TPCM_ORD_UpdateCriticalFileintergrityDigest:
//			((tpcm_rsp_header_st*)rsp)->uiRspRet = tcs_util_set_critical_file_integrity_digest ((unsigned char*)cmd->policy, cmd->size);
//			break;
		default:
			((tpcm_rsp_header_st*)rsp)->uiRspRet = TSS_ERR_ITEM_NOT_FOUND;
			httc_util_pr_error ("Inform policy(0x%08x) is not found\n", cmd->ord);
			break;
	}

	httc_util_dump_hex ("Inform policy rsp", rsp, *rspLen);
	return 0;
}


int tpcm_ioctl_process (void *cmd, int cmdLen, void *rsp, int *rspLen)
{
	switch (tpcmLocalReqCmd (cmd)){
		case TPCM_ORD_FirmwareUpgrade:
			return tpcm_ioctl_firmware_upgrade (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_InterceptMeasure:
			return tpcm_ioctl_integrity_measure (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_GetProgressReference:
			return tpcm_ioctl_read_file_integrity (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_SM3:
			return tpcm_ioctl_sm3 (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_SM3_UPDATE:
			return tpcm_ioctl_sm3_update (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_SM3_FINISH:
			return tpcm_ioctl_sm3_finish (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_SM2SignE:
			return  tpcm_ioctl_sm2_sign_e(cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_SM2VerifyE:
			return  tpcm_ioctl_sm2_verify_e(cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_SM4Encrypt:
			return tpcm_ioctl_sm4_encrypt (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_SM4Decrypt:
			return tpcm_ioctl_sm4_decrypt(cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_GetTrustedCredential:
			return tpcm_ioctl_generate_trust_report (cmd, cmdLen, rsp, rspLen);
		case TSS_ORD_InformPolicy:
			return tpcm_ioctl_inform_policy (cmd, cmdLen, rsp, rspLen);
	}

	switch (tpcmReqCmd (cmd)){
		case TPCM_ORD_SyncTrustedStatus:
			return tpcm_ioctl_sync_trust_status (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_GetTrustedStatus:
			return tpcm_ioctl_get_trusted_status(cmd, cmdLen, rsp, rspLen);
		case TSS_ORD_GetDmeasureTrustedStatus:
			return tpcm_ioctl_get_dmeasure_trusted_status(cmd, cmdLen, rsp, rspLen);
		case TSS_ORD_GetInterecpetTrustedStatus:
			return tpcm_ioctl_get_intercept_trusted_status(cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_UpdateSignedReferenceIncrement:
			return tpcm_ioctl_update_reference_increment (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_SetSignDMeasurePolicy:
			return tcs_ioctl_update_dynamic_policy (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_UpdateProcessIdentity:
			return tcs_ioctl_update_process_ids (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_UpdateProcessRoles:
			return tcs_ioctl_update_process_roles (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_SetGlobalControlPolicy:
			return tcs_ioctl_set_control_policy (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_SetAdminAuthPolicies:
			return tcs_ioctl_set_admin_auth_policies (cmd, cmdLen, rsp, rspLen);
        case TPCM_ORD_UpdateDmeasureProcessPolicy:
            return tcs_ioctl_update_dynamic_process_policy (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_UpdatePtraceProtectsPolicy:
			return tcs_ioctl_update_ptrace_protect_policy (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_SetSignMeasureSwitch:
			return tcs_ioctl_set_measure_control_switch (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_UpdateTncPolicy:
			return tcs_ioctl_update_tnc_policy (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_Reset:
			return tcs_ioctl_reset_license (cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_GetMark:
			return tcs_ioctl_get_tpcm_id(cmd, cmdLen, rsp, rspLen);
		case TPCM_ORD_UpdateRootCert_VIR:
			return tcs_ioctl_update_cert_root (cmd, cmdLen, rsp, rspLen);
	}

	httc_util_pr_error ("TPCM cmd(0x%08x) is not found\n", tpcmLocalReqCmd (cmd));
	return TSS_ERR_ITEM_NOT_FOUND;
}

int notify_start(void);
void notify_stop(void);

static void tss_mmap_addr_release (void)
{
	int i;
	if (tcs_mmap_mgmt.virt_addr_seg_list){
		for(i = 0; i < tcs_mmap_mgmt.virt_addr_seg_num; i++){
			if(tcs_mmap_mgmt.virt_addr_seg_list[i]){
			   httc_kfree (tcs_mmap_mgmt.virt_addr_seg_list[i]);
			}
		}
		httc_vfree (tcs_mmap_mgmt.virt_addr_seg_list);
		tcs_mmap_mgmt.virt_addr_seg_list = NULL;
		tcs_mmap_mgmt.virt_addr_seg_num = 0;
	}
}

int tss_open(struct inode *inode, struct file *filp)
{
	mutex_lock (&tcs_mmap_mgmt.lock);
	return 0;
}

int tss_release(struct inode *inode, struct file *filp)
{	
	tss_mmap_addr_release ();
	mutex_unlock (&tcs_mmap_mgmt.lock);
	return 0;
}

static int tss_mmap(struct file *file, struct vm_area_struct *vma)
{
	int  i, err = 0;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pfn_start =  0;
	unsigned long offset = 0;
	int seg_size = 0;
	
	int virt_addr_seg_num = size / tcs_mmap_mgmt.seg_limit + (((size % tcs_mmap_mgmt.seg_limit) != 0) ? 1 : 0);

	if ((NULL == tcs_mmap_mgmt.virt_addr_seg_list)
		&& (NULL == (tcs_mmap_mgmt.virt_addr_seg_list = httc_vzalloc (virt_addr_seg_num * sizeof(uint8_t *))))){
		httc_util_pr_error ("hter to do httc_vmalloc for tcs_mmap_mgmt.virt_addr_seg_list\n");
		return -ENOMEM;
	}

	for (i = 0; i < virt_addr_seg_num; i++){
		seg_size = (size < tcs_mmap_mgmt.seg_limit) ? size : tcs_mmap_mgmt.seg_limit;
		if (NULL == (tcs_mmap_mgmt.virt_addr_seg_list[i] =  (unsigned char *)httc_kmalloc(seg_size, GFP_KERNEL))){
			tss_mmap_addr_release ();
			httc_util_pr_error ("hter to do httc_kmalloc for tss_mmap_virt_addr[%d]\n", i);
			return -ENOMEM;
		}
		pfn_start = (virt_to_phys(tcs_mmap_mgmt.virt_addr_seg_list[i]) >> PAGE_SHIFT) + vma->vm_pgoff;
		//vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		err = remap_pfn_range (vma, vma->vm_start + offset, pfn_start, seg_size, vma->vm_page_prot);
		if (err){
			httc_util_pr_error("remap_pfn_range hter at [0x%llx  0x%llx]\n",
				(uint64_t)vma->vm_start + offset, (uint64_t)vma->vm_start + offset + seg_size);
			tss_mmap_addr_release ();
			return -1;
		}
		offset += seg_size;
		size -= seg_size;
	}

	tcs_mmap_mgmt.virt_addr_seg_num = virt_addr_seg_num;

    return 0;
}

static const struct file_operations tss_fops =
{
	.owner = THIS_MODULE,
	.open = tss_open,
	.release = tss_release,
	.mmap = tss_mmap,
};

#define TCS_TDDL_CDEV_MAJOR 500

struct cdev tcs_cdev;	
static int tcs_tddl_cdev_major = TCS_TDDL_CDEV_MAJOR;
struct class *tcs_tddl_cdev_class;
struct device *tcs_tddl_cdev_device;

int tcs_tddl_init(void)
{
	int ret = 0;
	dev_t devno;
	//struct file *filp = NULL;
	//struct inode *inode = NULL;

	devno = MKDEV (tcs_tddl_cdev_major, 0);
	ret = register_chrdev_region(devno, 1, "httctcs");
	if(ret){
		httc_util_pr_error ("register_chrdev_region hter!\n");
		return ret; 
	}

	cdev_init(&tcs_cdev, &tss_fops);
	tcs_cdev.owner = THIS_MODULE;

	ret = cdev_add(&tcs_cdev, devno, 1);
	if(ret){
		httc_util_pr_error ("cdev_add hter (%d)!\n", ret);
		unregister_chrdev(tcs_tddl_cdev_major, "httctcs");	 
		goto cdev_err;
		return ret; 
	}

	tcs_tddl_cdev_class = class_create (THIS_MODULE, "httctcs");
	if(IS_ERR (tcs_tddl_cdev_class)){  
		ret = PTR_ERR(tcs_tddl_cdev_class); 
		httc_util_pr_error ("class_create hter (%d)!\n", ret); 
		goto class_err; 
	}
	
	tcs_tddl_cdev_device = device_create(tcs_tddl_cdev_class, NULL, devno, NULL, "httctcs");
	if(IS_ERR (tcs_tddl_cdev_device)){	
		ret = PTR_ERR(tcs_tddl_cdev_device); 
		httc_util_pr_error("device_create hter (%d)!\n", ret); 
		goto device_err; 
	}
	printk("[%s:%d] success!\n", __func__, __LINE__);
	return 0;

device_err:   
	class_destroy (tcs_tddl_cdev_class);
class_err:
	cdev_del(&tcs_cdev);
cdev_err:
	unregister_chrdev_region(MKDEV(tcs_tddl_cdev_major, 0), 1);
	return ret;
}

void tcs_tddl_release(void)
{
	device_destroy(tcs_tddl_cdev_class, MKDEV(tcs_tddl_cdev_major, 0));
   	class_destroy(tcs_tddl_cdev_class);
   	cdev_del(&tcs_cdev);
   	unregister_chrdev_region(MKDEV(tcs_tddl_cdev_major, 0), 1);
    printk("[%s:%d] success!\n", __func__, __LINE__);
}

int tcs_init(void)
{
	int ret = 0;
	uint32_t tpcmRes = 0;
	struct timeval now;

	if(tpcm_ioctl_proc_register (tpcm_ioctl_process)){
		httc_util_pr_error ("tpcm_ioctl_proc_register hter!\n");
		return -1;
	}

	if (0 != (ret = tpcm_pm_callbacks_register ())){
		httc_util_pr_error ("tpcm_pm_callbacks_register hter\n");
		tpcm_ioctl_proc_unregister (tpcm_ioctl_process);
		return -1;
	}

	httc_gettimeofday(&now);
	ret = tcsk_set_system_time(now.tv_sec,&tpcmRes);
	if (ret || tpcmRes){
		httc_util_pr_error ("SetSystemTime hter: ret(0x%08x),tpcmRes(0x%08x)\n", ret, tpcmRes);
	}

	if(notify_start()){
		httc_util_pr_error ("notify_start hter!\n");
		tpcm_pm_callbacks_unregister ();
		tpcm_ioctl_proc_unregister (tpcm_ioctl_process);
		return -1;
	}

	ret = tpcm_get_trust_status(&gui_trust_status);
	if(ret) {
		httc_util_pr_error ("TPCM_GetTrustedStatusInternel ret: 0x%08x!\n", ret);
	}
	
	if(0 != (ret = tcm_init ())) httc_util_pr_error ("TCM_Init hter: 0x%08x\n", ret);
	if(0 != (ret = tcm_startup (TCM_ST_CLEAR))) httc_util_pr_error ("TCM_Startup hter: 0x%08x\n", ret);

	if (0 != (ret = tcs_tddl_init ()))	httc_util_pr_error ("tcs_tddl_init hter: %d\n", ret);

	if (0 != (ret = tcs_policy_management_init ())){
		httc_util_pr_error ("Tcs policy management init hter!\n");
		return ret;
	}

	memset (&tcs_mmap_mgmt, 0, sizeof (tcs_mmap_mgmt));
	mutex_init (&tcs_mmap_mgmt.lock);
	tcs_mmap_mgmt.seg_limit = 0x10000;	/** 64K */

	printk ("[%s:%d] finish!\n",  __func__, __LINE__);
	return 0;
}

void tcs_exit(void)
{
	tcs_tddl_release ();
	tpcm_pm_callbacks_unregister ();
    tpcm_ioctl_proc_unregister (tpcm_ioctl_process);
    notify_stop();
    printk ("[%s:%d] finish!\n",  __func__, __LINE__);
}

module_init(tcs_init);
module_exit(tcs_exit);

