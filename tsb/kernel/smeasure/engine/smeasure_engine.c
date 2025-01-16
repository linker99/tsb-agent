#include <linux/version.h>
#include <linux/binfmts.h>
#include <linux/elf.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/mman.h>
//#include <asm-generic/module.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/highmem.h>
#include <linux/ctype.h>
#include <linux/kallsyms.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/workqueue.h>
#include <linux/slab.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include <linux/mm.h>
#include <linux/kprobes.h>
#endif

//#include "intercept/intercept_module.h"
#include "engine/engine.h"
#include "smeasure_wqueue.h"
#include "function_types.h"
#include "sec_domain.h"
#include "utils/vfs.h"
#include "utils/debug.h"
#include "../policy/policy_whitelist_cache.h"
#include "../policy/hash_whitelist.h"
#include "../policy/hash_critical_confile.h"
#include "../protection/process_protect.h"
//#include "policy/global_policy.h"
#include "policy/feature_configure.h"
#include "tcsapi/tcs_policy_def.h"
#include "tsbapi/tsb_log_notice.h"
#include "log/log.h"
#include "tpcm/tpcmif.h"
#include "accessctl/accessctl.h"



//#define LSM_UNLINK 1

static unsigned long k_kallsyms_lookup_name = INVALID_DATA_FULL_FF;
module_param(k_kallsyms_lookup_name, ulong, 0644);
MODULE_PARM_DESC(k_kallsyms_lookup_name, "ulong kallsyms lookup name");
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
static unsigned long (*httc_kallsyms_lookup_name) (const char *name);
#endif

#define FILE_OPEN_MAGIC 0xab12ddef
#define RM_MAX_SIZE		4096	
struct whitelist_feature_conf whitelist_feature;

struct httcsec_intercept_module *global_old_hook = NULL;
struct httcsec_intercept_module *global_self_hook = NULL;

extern int file_integrity_valid;

static int prepare_sec_domain(struct sec_domain *sec_d, struct task_struct *tsk,
	void *obj, int type)
{
	int ret = 0;
	int path_len = 0;
	char *fullpath;
	char *taskpath = NULL;
	int task_type = 0;

	fullpath = vfs_get_fullpath(obj, type);
	if (!fullpath) {
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], fullpath is NULL!\n", __func__);
		ret = -EINVAL;
		goto pass;
	}

//???2700???3.0.8?汾????????get_mm_exe_file????
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	taskpath = vfs_get_fullpath(tsk, TYPE_TASK);
#endif
	if (!taskpath) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
		DEBUG_MSG(HTTC_TSB_DEBUG,"Enter:[%s], taskpath is current->comm[%s]!\n", __func__, tsk->comm);

#endif
		taskpath = tsk->comm;
		task_type = 1;
	}

	/*audit subject */
	path_len = strlen(taskpath);
	if (path_len < LEN_NAME_MAX) {
		memcpy(sec_d->sub_name, taskpath, path_len);
		sec_d->sub_len = path_len;
	} else {
		memcpy(sec_d->sub_name, taskpath, LEN_NAME_MAX);
		sec_d->sub_len = LEN_NAME_MAX;
	}
	/*audit object */
	path_len = strlen(fullpath);
	if (path_len < LEN_NAME_MAX) {
		memcpy(sec_d->obj_name, fullpath, path_len);
		sec_d->obj_len = path_len;
	} else {
		memcpy(sec_d->obj_name, fullpath, LEN_NAME_MAX);
		sec_d->obj_len = LEN_NAME_MAX;
	}

pass:
	if (task_type == 0)
		vfs_put_fullpath(taskpath);
	vfs_put_fullpath(fullpath);
	return ret;
}



#ifdef LSM_UNLINK
static struct workqueue_struct *my_workqueue;
static struct my_data *audit_data;
struct my_data *p_handle = NULL;

struct my_data
{	
	struct delayed_work my_work;
	int result;
	int inuse;
	struct sec_domain *sec_d ;
};


static void my_work_handler(struct work_struct *work) {
	int ret=0;
	unsigned int user = 0;
	unsigned char policy_digest[256] = { 0 };
	int len=0, hash_len=0;
	unsigned char file_digest[LEN_HASH] = { 0 };
	struct file *file_critical;
	struct sec_domain *sec_d;
//	printk("into my_work_handler----\r\n");

   struct my_data *audit = container_of(work,struct my_data,my_work.work);

    ret=audit->result;
	sec_d=audit->sec_d;
	
   DEBUG_MSG(HTTC_TSB_DEBUG,"into my_work_handler audit->result:%d sec_d->obj_name:%s\r\n",audit->result,sec_d->obj_name);

   *(end_of_stack(current)+1) = FILE_OPEN_MAGIC;
	mb();
	file_critical = filp_open(sec_d->obj_name, O_RDONLY, 0);
	if (IS_ERR(file_critical))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"file open error!\n");
		*(end_of_stack(current)+1) = 0;
		goto out;
	}

	ret = digest_cal(file_critical, file_digest, LEN_HASH);
	if (ret < 0)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], digest_cal error!\n",__func__);
		ret = -EACCES;
		*(end_of_stack(current)+1) = 0;
		goto audit_log;
	}
	memcpy(sec_d->sub_hash, file_digest, LEN_HASH);
	if(file_critical != NULL)
		filp_close(file_critical, NULL);

	*(end_of_stack(current)+1) = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	user = __kuid_val(current->cred->uid);
#else
	user = current->cred->uid;
#endif

	if(audit->result)
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], fullpath[%s] critical confile is fixed, donot rm\n",__func__, sec_d->obj_name);

audit_log:
	DEBUG_MSG(HTTC_TSB_DEBUG,"audit->result=%d\r\n",audit->result);
	if(audit->result)
		keraudit_log(TYPE_WHITELIST, CRITICAL_FILE_OPEN, RESULT_FAIL, sec_d, user, current->pid);
out:
    	if (audit->sec_d){
			kfree(audit->sec_d);
			audit->inuse = 0;
    	}

}


struct my_data* get_audit_data(void)
{
	int index = 0;
	for(index = 0;index < RM_MAX_SIZE;index++){
		if(audit_data[index].inuse == 0){
			audit_data[index].inuse = 1;
			break;
		}
	}

	if(index >= RM_MAX_SIZE){
		return NULL;
	}else{
		return &(audit_data[index]);
	}

}

void smeasure_file_work_init(void)
{
	int index = 0;
	DEBUG_MSG(HTTC_TSB_DEBUG,"Initializing work queue demo\n");

	audit_data=(struct my_data *)kmalloc(sizeof(struct my_data)*RM_MAX_SIZE, GFP_KERNEL);
	if(!audit_data)
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], malloc audit faill!\n", __func__);
		return;	
	}
	my_workqueue = create_workqueue("my_workqueue");
	if (!my_workqueue) {
		return;
	}

	for(index = 0;index < RM_MAX_SIZE; index++){
		INIT_DELAYED_WORK(&(audit_data[index].my_work), my_work_handler);
		audit_data[index].inuse = 0;
	}

	return; 


}

void smeasure_file_work_exit(void)
{
	int index = 0;
	for(index = 0;index < RM_MAX_SIZE; index ++ ){
		cancel_delayed_work_sync(&(audit_data[index].my_work));
	}
	destroy_workqueue(my_workqueue);

	if(audit_data)
	{
		kfree(audit_data);
	}

	DEBUG_MSG(HTTC_TSB_DEBUG,"Exiting work queue demo\n");
}

#endif


static int whitelist_check(struct file *file, int mask, int type)
{
	int retval, ret = 0;
	int skip = 0;
	unsigned int user = 0;
	struct sec_domain *sec_d;
	int flag = 0;
	smeasure_wqueue_t *queue = NULL;
	struct task_struct *tsk = current;


	sec_d = kzalloc(sizeof(struct sec_domain), GFP_KERNEL);
	if (!sec_d) {
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], kzalloc error!\n", __func__);
		ret = -ENOMEM;
		goto out;
	}

	ret = prepare_sec_domain(sec_d, tsk, (void *)file, TYPE_FILE);
	if (ret) {
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], prepare sec domain err!\n", __func__);
		ret=0;
                goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	user = __kuid_val(current->cred->uid);
#else
	user = current->cred->uid;
#endif

	if (!file_integrity_valid)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], whitelist policy file integrity check fail!\n",__func__);
		ret = -EACCES;
		goto audit_log;
	}

	if (whitelist_feature.cache_mode) {
		/*check whitelist cache */
		ret = check_whitelist_cache(file, sec_d->obj_name, sec_d->sub_hash);
		if (ret == 0) {
			if (type == EXEC_CTL || type == SCRIPT_CTL)
				fac_process_msg_set(tsk, sec_d->obj_name, sec_d->sub_hash, type);
			goto audit_log;
		}
	}
#ifdef WHITE_NOT_TPCM
ret = digest_check(file, sec_d, type);
#else
	switch (whitelist_feature.measure_mode) {
	case PROCESS_MEASURE_MODE_SOFT:
	case PROCESS_MEASURE_MODE_AUTO:
		ret = digest_check(file, sec_d, type);
		break;
	case PROCESS_MEASURE_MODE_TCS_CHECK:
		ret = digest_check_tpcm_simple(file, sec_d, type);
		break;
	case PROCESS_MEASURE_MODE_TCS_MEASURE:

		queue = smeasure_wqueue_handle(sec_d->obj_name ,&ret ,&flag);
		if(!queue && (flag == 3))
		{
			switch (ret)
			{
			case DC_PASS:
				ret = 0;
				break;
			case DC_FORBID:
				ret = -EACCES;
				break;
			case DC_EAUDIT_PASS:
				ret = -EACCES;
				skip = 1;
				break;
			case DC_ERROR_PASS:
			default:
				ret = 0;
			}
			goto out;
		}
		ret = digest_check_tpcm(file, sec_d, type);
		if(queue){
			smeasure_wqueue_wake_up(queue ,ret);
		}
		break;
	default:
		ret = 0;
		DEBUG_MSG(HTTC_TSB_INFO,"measure_mode error, pass\n");
		goto out;
	}
#endif

	switch (ret) {
	case DC_PASS:
		ret = 0;
		break;
	case DC_FORBID:
		ret = -EACCES;
		goto audit_log;
	case DC_EAUDIT_PASS:
		ret = -EACCES;
		skip = 1;
		goto audit_log;
	case DC_ERROR_PASS:
	default:
		ret = 0;
		DEBUG_MSG(HTTC_TSB_INFO,"system error, pass\n");
		goto out;
	}

	/* set process msg */
	if (type == EXEC_CTL || type == SCRIPT_CTL)
		fac_process_msg_set(tsk, sec_d->obj_name, sec_d->sub_hash, type);

	/* set whitelist cache */
	if (whitelist_feature.cache_mode)
		set_whitelist_cache(file, sec_d->obj_name, sec_d->sub_hash);

audit_log:




	if (!whitelist_feature.control_mode)
	{
		skip = 1;
		if(ret)
			sync_trust_status(1);
	}

	retval = (ret < 0) ? RESULT_FAIL : RESULT_SUCCESS;
	if (retval == RESULT_SUCCESS)
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], user:[%d], pid:[%d], subject:[%s], object:[%s], type:[%d] OK!\n",
		__func__, user, current->pid, sec_d->sub_name, sec_d->obj_name, type);
	else
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], user:[%d], pid:[%d], subject:[%s], object:[%s], type:[%d] failed!\n",
		__func__, user, current->pid, sec_d->sub_name, sec_d->obj_name, type);

	keraudit_log(TYPE_WHITELIST, mask, retval, sec_d, user, current->pid);

out:
	if (sec_d)
		kfree(sec_d);
	return (skip) ? 0 : ret;
}



#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#ifdef CONFIG_MMU
/*
 * The nascent bprm->mm is not visible until exec_mmap() but it can
 * use a lot of memory, account these pages in current->mm temporary
 * for oom_badness()->get_mm_rss(). Once exec succeeds or fails, we
 * change the counter back via acct_arg_size(0).
 */
static void acct_arg_size(struct linux_binprm *bprm, unsigned long pages)
{
	struct mm_struct *mm = current->mm;
	long diff = (long)(pages - bprm->vma_pages);

	if (!mm || !diff)
		return;

	bprm->vma_pages = pages;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
	atomic_long_add(pages, &mm->rss_stat.count[MM_FILEPAGES]);
#else
	add_mm_counter(mm, MM_ANONPAGES, diff);
#endif
}

static struct page *get_arg_page(struct linux_binprm *bprm, unsigned long pos,
				 int write)
{
	struct page *page;
	int ret;
	unsigned int gup_flags = FOLL_FORCE;

#ifdef CONFIG_STACK_GROWSUP
	if (write) {
		ret = expand_downwards(bprm->vma, pos);
		if (ret < 0)
			return NULL;
	}
#endif

	if (write)
		gup_flags |= FOLL_WRITE;

	/*
	 * We are doing an exec().  'current' is the process
	 * doing the exec and bprm->mm is the new process's mm.
	 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	ret = get_user_pages_remote(bprm->mm, pos, 1, gup_flags,
				    &page, NULL, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	ret = get_user_pages_remote(current, bprm->mm, pos, 1, gup_flags,
				    &page, NULL, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	ret = get_user_pages_remote(current, bprm->mm, pos, 1, gup_flags,
				    &page, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 168)
	ret = get_user_pages(current, bprm->mm, pos, 1, gup_flags,
				    &page, NULL);
#else
	ret = get_user_pages(current, bprm->mm, pos, 1, write, 1, &page, NULL);
#endif
	if (ret <= 0)
		return NULL;

	if (write) {
		unsigned long size = bprm->vma->vm_end - bprm->vma->vm_start;
		unsigned long ptr_size;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 35)
		unsigned long limit;
#else
		struct rlimit *rlim;
#endif
		/*
		 * Since the stack will hold pointers to the strings, we
		 * must account for them as well.
		 *
		 * The size calculation is the entire vma while each arg page is
		 * built, so each time we get here it's calculating how far it
		 * is currently (rather than each call being just the newly
		 * added size from the arg page).  As a result, we need to
		 * always add the entire size of the pointers, so that on the
		 * last call to get_arg_page() we'll actually have the entire
		 * correct size.
		 */
		ptr_size = (bprm->argc + bprm->envc) * sizeof(void *);
		if (ptr_size > ULONG_MAX - size)
			goto fail;
		size += ptr_size;

		acct_arg_size(bprm, size / PAGE_SIZE);

		/*
		 * We've historically supported up to 32 pages (ARG_MAX)
		 * of argument strings even with small stacks
		 */
		if (size <= ARG_MAX)
			return page;

		/*
		 * Limit to 1/4-th the stack size for the argv+env strings.
		 * This ensures that:
		 *  - the remaining binfmt code will not run out of stack space,
		 *  - the program will have a reasonable amount of stack left
		 *    to work from.
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
		limit = _STK_LIM / 4 * 3;
		limit = min(limit, bprm->rlim_stack.rlim_cur / 4);
		if (size > limit)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 39)
		limit = _STK_LIM / 4 * 3;
		limit = min(limit, rlimit(RLIMIT_STACK) / 4);
		if (size > limit)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 35)
		rlim = current->signal->rlim;
		if (size > READ_ONCE(rlim[RLIMIT_STACK].rlim_cur) / 4)
#else
		rlim = current->signal->rlim;
		if (size > ACCESS_ONCE(rlim[RLIMIT_STACK].rlim_cur) / 4)
#endif
			goto fail;
	}

	return page;

fail:
	put_page(page);
	return NULL;
}
#else
static inline void acct_arg_size(struct linux_binprm *bprm, unsigned long pages)
{
}

static struct page *get_arg_page(struct linux_binprm *bprm, unsigned long pos,
				 int write)
{
	struct page *page;

	page = bprm->page[pos / PAGE_SIZE];
	if (!page && write) {
		page = alloc_page(GFP_HIGHUSER | __GFP_ZERO);
		if (!page)
			return NULL;
		bprm->page[pos / PAGE_SIZE] = page;
	}

	return page;
}
#endif
#endif

#ifdef CONFIG_MMU
static void httc_put_arg_page(struct page* page)
{
	put_page(page);
}
#else
static void httc_put_arg_page(struct page* page)
{
}
#endif

struct page *(*httc_get_arg_page) (struct linux_binprm * bprm,
	unsigned long pos, int write);



static inline int is_valid_character(char c)
{

	if (c == '.' || c == '/' || c == '_' || isalnum(c))
		return 1;
	else
		return 0;
}


static int is_valid_args_name(const char* args, char* name)
{
	char* p = NULL;
	char buf[896] = { 0 };
	int len = 0;
	int copy_base = 0;

	if (args[0] == '-')
		return 0;

	p = strchr(args, ' ');
	if (p) {
		len = p - args;
		strncpy(buf, args, sizeof(buf));
		name[p - args] = '\0';
	}
	else {
		strncpy(buf, args, sizeof(buf));
		len = strlen(args);
	}

	do {
		if (is_valid_character(buf[copy_base]))
			break;
	} while (copy_base++);

	do {
		if (is_valid_character(buf[len - 1]))
			break;
	} while (len--);

	strncpy(name, &buf[copy_base], sizeof(buf));

	return 1;
}

static int valid_args_name_from_bprm(struct linux_binprm* bprm, char* name)
{
	int ret = 0;
	unsigned long offset, pos;
	char* kaddr;
	struct page* page;
	char* argv = NULL;
	int i = 0;
	int argc = 0;
	int count = 0;
	char buf[32] = { 0 };

	if (!bprm)
		return -1;

	argc = bprm->argc;
	pos = bprm->p;

	argv = kmalloc(PAGE_SIZE, GFP_ATOMIC);
	if (NULL == argv) {
		DEBUG_MSG(HTTC_TSB_INFO, "alloc page error\n");
		return -1;
	}
	memset(argv, 0, PAGE_SIZE);

	do {
		offset = pos & ~PAGE_MASK;
		page = httc_get_arg_page(bprm, pos, 0);
		if (!page) {
			ret = -1;
			goto out;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
		kaddr = kmap_atomic(page);
#else
		kaddr = kmap_atomic(page, KM_USER0);
#endif
		for (i = 0; offset < PAGE_SIZE && count < argc && i < PAGE_SIZE;
			offset++, pos++) {
			if (kaddr[offset] == '\0') {
				count++;
				pos++;
				//printk("argv %d is %s\n", count, argv);
				if (count > 1) {
					if (is_valid_args_name(argv, name)) {
						ret = 1;
						break;
					}
					else {
						ret = 0;
						break;
					}

				}
				memset(argv, 0, PAGE_SIZE);
				memset(buf, 0, sizeof(buf));
				i = 0;
				continue;
			}
			argv[i] = kaddr[offset];
			i++;
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
		kunmap_atomic(kaddr);
#else
		kunmap_atomic(kaddr, KM_USER0);
#endif
		httc_put_arg_page(page);

		if (ret)
			break;

	} while (offset == PAGE_SIZE);

	kfree(argv);

out:
	return ret;
}


static int check_script_process(struct linux_binprm* bprm)
{
	int ret = 0;
	char name[896] = { 0 };
	struct file* fp = NULL;
	char* p = NULL;
	char* ptr = NULL;

	p = strrchr(bprm->interp, '/');
	if (!p)
		goto out;
	else
		ptr = p + 1;

	if ((strcmp(ptr, "bash") == 0) ||
		(strcmp(ptr, "dash") == 0) ||
		(strcmp(ptr, "zsh") == 0) ||
		(strcmp(ptr, "ash") == 0) ||
		(strcmp(ptr, "csh") == 0) ||
		(strcmp(ptr, "tcsh") == 0) ||
		(strncmp(ptr, "python", strlen("python")) == 0) ||
		(strncmp(ptr, "perl", strlen("perl")) == 0) ||
		(strncmp(ptr, "ruby", strlen("ruby")) == 0) ||
		(strcmp(ptr, "sh") == 0)) {
		if (bprm->argc == 1)
			goto out;

		if (valid_args_name_from_bprm(bprm, name) == 1) {
			/* DEBUG_MSG(HTTC_TSB_DEBUG, "script process:%s\n", name); */
			if (strlen(name) <= 0) {
				goto out;
			}
			fp = filp_open(name, O_RDONLY, 0);
			if (IS_ERR(fp) || !fp) {
				DEBUG_MSG(HTTC_TSB_DEBUG, "[%s] filp_open [%s] error [%ld], pass!\n", __func__, name, PTR_ERR(fp));
				goto out;
			}
			ret = whitelist_check(fp, WHITELIST_OPERATE_EXEC, SCRIPT_CTL);
			filp_close(fp, NULL);
		}
		else {  // do nothing
			DEBUG_MSG(HTTC_TSB_DEBUG, "[%s] %s parse over, skip\n", __func__, bprm->interp);
			/* ret = -EINVAL; */
		}
	}

out:
	return ret;
}

static int smeasure_bprm_check_security(struct linux_binprm *bprm)
{
	int ret = 0;
	struct elfhdr elf_ex;

	if(!whitelist_feature.is_enabled)
		return ret;

	if(global_old_hook != NULL && global_old_hook->bprm_check_security != NULL )
	{
		ret = global_old_hook->bprm_check_security(bprm);
		if(ret)
			return ret;
	}

	if (!bprm->file)
		goto pass;

	elf_ex = *((struct elfhdr *)bprm->buf);

	if (elf_ex.e_type != ET_EXEC && elf_ex.e_type != ET_DYN) {
		ret = whitelist_check(bprm->file, WHITELIST_OPERATE_EXEC, SCRIPT_CTL);
	} else {
		ret = whitelist_check(bprm->file, WHITELIST_OPERATE_EXEC, EXEC_CTL);
		if (ret == 0 && bprm->argc >= 2)
		{
			ret = check_script_process(bprm);
		}
	}

	/* program exec trigger dmeasure */
	if (ret) {
		ProcessExecCount_add();
		goto pass;
	}

pass:
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
static int smeasure_mmap_file(struct file *file, unsigned long reqprot,
	unsigned long prot, unsigned long flags)
#else
static int smeasure_file_mmap(struct file *file, unsigned long reqprot,
	unsigned long prot, unsigned long flags,
	unsigned long addr, unsigned long addr_only)
#endif
{
	int ret = 0;
	int retval = 0;
	int type = 0;
	struct elfhdr elf_ex;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	loff_t offset = 0;
#endif

	if(!whitelist_feature.is_enabled)
		return ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	if(global_old_hook != NULL && global_old_hook->mmap_file != NULL )
	{
		ret = global_old_hook->mmap_file(file, reqprot, prot, flags);
		if(ret)
			return ret;
	}
#else
	if(global_old_hook != NULL && global_old_hook->file_mmap != NULL )
	{
		ret = global_old_hook->file_mmap(file, reqprot, prot, flags, addr, addr_only);
		if(ret)
			return ret;
	}
#endif

	if (!file || !(prot & PROT_EXEC) || (flags & MAP_EXECUTABLE))
		goto pass;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	retval = kernel_read(file, (char *)&elf_ex, sizeof(elf_ex), &offset);
#else
	retval = kernel_read(file, 0, (char *)&elf_ex, sizeof(elf_ex));
#endif
	if (retval != sizeof(elf_ex))
		goto pass;

	type = elf_ex.e_type;


	if (type == ET_DYN) {
		ret = whitelist_check(file, WHITELIST_OPERATE_EXEC, DYN_CTL);
		if (ret) {
			DynamicLibLoadCount_add();
			goto pass;
		}

	}

pass:
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static int smeasure_kernel_read_file(struct file *file, enum kernel_read_file_id id, bool contents)
{
	int ret = 0;

	if(!whitelist_feature.is_enabled)
		return ret;

	if(global_old_hook != NULL && global_old_hook->kernel_read_file != NULL )
	{
		ret = global_old_hook->kernel_read_file(file, id, contents);
		if(ret)
			return ret;
	}

	switch (id) {
	case READING_MODULE:
		ret = whitelist_check(file, WHITELIST_OPERATE_EXEC, MODULE_CTL);
		if (ret)
			KernelModuleCount_add();
		break;
	default:
		break;
	}

	return ret;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
static int smeasure_kernel_read_file(struct file *file, enum kernel_read_file_id id)
{
	int ret = 0;

	if(!whitelist_feature.is_enabled)
		return ret;

	if(global_old_hook != NULL && global_old_hook->kernel_read_file != NULL )
	{
		ret = global_old_hook->kernel_read_file(file, id);
		if(ret)
			return ret;
	}

	if(file == NULL)
	{
		return ret;
	}

	switch (id) {
	case READING_MODULE:
		ret = whitelist_check(file, WHITELIST_OPERATE_EXEC, MODULE_CTL);
		if (ret)
			KernelModuleCount_add();
		break;
	default:
		break;
	}

	return ret;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static int smeasure_kernel_module_from_file(struct file *file)
{
	int ret = 0;

	if(!whitelist_feature.is_enabled)
		return ret;

	if(global_old_hook != NULL && global_old_hook->kernel_module_from_file != NULL )
	{
		ret = global_old_hook->kernel_module_from_file(file);
		if(ret)
			return ret;
	}

	if (!file)
		goto pass;

	ret = whitelist_check(file, WHITELIST_OPERATE_EXEC, MODULE_CTL);
	if (ret)
		KernelModuleCount_add();

pass:
	return ret;
}
#endif

/* Find a module section: 0 means not found. */
static unsigned int find_sec(Elf_Ehdr * hdr, Elf_Shdr * sechdrs,
	const char *secstrings, const char *name)
{
	unsigned int i;

	for (i = 1; i < hdr->e_shnum; i++) {
		/* Alloc bit cleared means "ignore it." */
		if ((sechdrs[i].sh_flags & SHF_ALLOC)
			&& strcmp(secstrings + sechdrs[i].sh_name, name) == 0)
			return i;
	}
	return 0;
}

static struct module *get_module_struct(Elf_Ehdr * hdr, unsigned long len)
{
	Elf_Shdr *sechdrs;
	struct module *mod;
	char *secstrings;
	unsigned int i;
	unsigned int modindex;

	/* Convenience variables */
	sechdrs =(Elf_Shdr*)((char*)hdr + hdr->e_shoff);
	secstrings =(char*) ((char*)hdr + sechdrs[hdr->e_shstrndx].sh_offset);
	sechdrs[0].sh_addr = 0;

	for (i = 1; i < hdr->e_shnum; i++) 
	{
		//unsigned int strindex = 0;
	
		if (sechdrs[i].sh_type != SHT_NOBITS
			&& len < sechdrs[i].sh_offset + sechdrs[i].sh_size)
			return NULL;

		/* Mark all sections sh_addr with their address in the temporary image. */
		sechdrs[i].sh_addr = (size_t) hdr + sechdrs[i].sh_offset;

		/* Internal symbols and strings. */
		if (sechdrs[i].sh_type == SHT_SYMTAB) 
		{
		
			//strindex = sechdrs[i].sh_link;
		}
#ifndef CONFIG_MODULE_UNLOAD
		/* Don't load .exit sections */
		if (strstarts(secstrings + sechdrs[i].sh_name, ".exit"))
			sechdrs[i].sh_flags &= ~(unsigned long)SHF_ALLOC;
#endif
	}

	modindex = find_sec(hdr, sechdrs, secstrings, ".gnu.linkonce.this_module");
	if (!modindex) {
		DEBUG_MSG(HTTC_TSB_INFO,"No module found in object\n");
		return NULL;
	}
	/* This is temporary: point mod into copy of data. */
	mod = (void *)sechdrs[modindex].sh_addr;
	return mod;
}

static int smeasure_init_module(void __user * umod, unsigned long len,
	const char __user * uargs)
{
	int err = 0;
	struct module *mod;
	Elf_Ehdr *hdr;
	char mod_name[MODULE_NAME_LEN + 4] = { 0 };
	char digest[LEN_HASH] = { 0 };
	unsigned int user = 0;
	struct sec_domain sec_d;
	memset(&sec_d, 0, sizeof(sec_d));

	if(!whitelist_feature.is_enabled)
		return err;

	if(global_old_hook != NULL && global_old_hook->init_module != NULL )
	{
		err = global_old_hook->init_module(umod, len, uargs);
		if(err)
			return err;
	}

	if (len < sizeof(*hdr))
		return -ENOEXEC;

	if (len > 64 * 1024 * 1024 || (hdr = vmalloc(len)) == NULL)
		return -ENOMEM;

	if (copy_from_user(hdr, umod, len) != 0) {
		err = -EFAULT;
		goto free_hdr;
	}

	if (!file_integrity_valid)
		err = -EACCES;
	else
		err = check_module_digest((void *)hdr, len, digest);

	mod = get_module_struct(hdr, len);
	if (!mod)
		goto free_hdr;

	memcpy(mod_name, mod->name, strlen(mod->name));
	strcat(mod_name, ".ko");
	memcpy(sec_d.sub_name, mod_name, strlen(mod_name));
	memcpy(sec_d.obj_name, mod_name, strlen(mod_name));
	sec_d.sub_len = sec_d.obj_len = strlen(mod_name);
	memcpy(sec_d.sub_hash, digest, LEN_HASH);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	user = __kuid_val(current->cred->uid);
#else
	user = current->cred->uid;
#endif

	if (err == 0) {
		DEBUG_MSG(HTTC_TSB_DEBUG, "mod_name[%s], check success!\n", mod_name);
		keraudit_log(TYPE_WHITELIST, WHITELIST_OPERATE_EXEC, RESULT_SUCCESS, &sec_d, user, current->pid);	//success audit log
	} else {
		KernelModuleCount_add();
		DEBUG_MSG(HTTC_TSB_INFO, "mod_name[%s], check failed!\n",  mod_name);
		keraudit_log(TYPE_WHITELIST, WHITELIST_OPERATE_EXEC, RESULT_FAIL, &sec_d, user, current->pid);	//fail audit log
		err = -EACCES;
	}

	if (!whitelist_feature.control_mode)
	{
		//???????????????????????????????
		if(err)
			sync_trust_status(1);
		err = 0;
	}

free_hdr:
	vfree(hdr);
	return err;
}

//int smeasure_init_module(void __user *umod, unsigned long len, const char __user *uargs)
//{
//    int ret = 0;
//
//	if(!whitelist_feature.is_enabled)
//		return ret;
//
//	if(global_old_hook != NULL && global_old_hook->init_module != NULL )
//	{
//		ret = global_old_hook->init_module(umod, len, uargs);
//		if(ret)
//			return ret;
//	}
//
//    return ret;
//}






#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) || RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 1)
static int smeasure_file_open(struct file *file)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
static int smeasure_file_open(struct file *file, const struct cred *cred)
#else
static int smeasure_dentry_open(struct file *file, const struct cred *cred)
#endif
{
	int ret = 0;
	//char *fullpath = NULL;
	unsigned char policy_digest[256] = { 0 };
	int len=0, hash_len=0;
	unsigned char file_digest[LEN_HASH] = { 0 };
	struct file *file_critical = NULL;
	unsigned int user = 0;
	struct sec_domain *sec_d = NULL;
	struct task_struct *tsk = current;

	if(!whitelist_feature.is_enabled)
		return ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	if(global_old_hook != NULL && global_old_hook->file_open != NULL)
#else
	if(global_old_hook != NULL && global_old_hook->dentry_open != NULL)
#endif
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) || RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 1)
		ret = global_old_hook->file_open(file);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		ret = global_old_hook->file_open(file, cred);
#else
		ret = global_old_hook->dentry_open(file, cred);
#endif
		if(ret)
			return ret;
	}

	if(*(end_of_stack(current)+1) == FILE_OPEN_MAGIC)
		return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	user = __kuid_val(current->cred->uid);
#else
	user = current->cred->uid;
#endif

	sec_d = kzalloc(sizeof(struct sec_domain), GFP_KERNEL);
	if (!sec_d) {
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], kzalloc error!\n", __func__);
		ret = -ENOMEM;
		goto out;
	}

	//fullpath = vfs_get_fullpath((void *)file, TYPE_FILE);
	ret = prepare_sec_domain(sec_d, tsk, (void *)file, TYPE_FILE);
	if (ret) {
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], prepare sec domain err!\n", __func__);
		ret=0;
                goto out;
	}

	hash_len = get_critical_confile_digest(sec_d->obj_name, policy_digest, 256);
	if (!hash_len) 
	{
		ret = 0;
		goto out;
	}
	
	*(end_of_stack(current)+1) = FILE_OPEN_MAGIC;
	mb();
	file_critical = filp_open(sec_d->obj_name, O_RDONLY, 0);
	if (IS_ERR(file_critical))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"file open error!\n");
		*(end_of_stack(current)+1) = 0;
		goto out;
	}

	ret = digest_cal(file_critical, file_digest, LEN_HASH);
	if (ret < 0) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], digest_cal error!\n",__func__);
		ret = 0;
		*(end_of_stack(current) + 1) = 0;
		if (file_critical != NULL)
			   filp_close(file_critical, NULL);
		goto audit_log;
	}
	memcpy(sec_d->sub_hash, file_digest, LEN_HASH);

	if(file_critical != NULL)
		filp_close(file_critical, NULL);

	*(end_of_stack(current)+1) = 0;

	ret = -EACCES;
	while (len<hash_len)
	{
		if (memcmp(policy_digest+len, file_digest, LEN_HASH) == 0)//文件无变化放行
		{
			ret = 0;
			break;
		}
		len += LEN_HASH;
	}

	if(ret)
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], fullpath[%s] critical confile is fixed, donot read\n",__func__, sec_d->obj_name);

audit_log:
	if(ret)
		keraudit_log(TYPE_WHITELIST, CRITICAL_FILE_OPEN, RESULT_FAIL, sec_d, user, current->pid);
out:
	//if(fullpath)
	//	vfs_put_fullpath(fullpath);
	if (sec_d)
		kfree(sec_d);

	return ret;
}

#ifdef LSM_UNLINK
static int smeasure_file_unlink(struct inode * dir, struct dentry * dentry)
{
	int ret = 0;
	unsigned char policy_digest[256] = { 0 };
	int len=0, hash_len=0;
	unsigned char file_digest[LEN_HASH] = { 0 };
	struct file *file_critical = NULL;
	//unsigned int user = 0;
	struct sec_domain *sec_d = NULL;
	struct task_struct *tsk = current;

	if(!whitelist_feature.is_enabled)
		return ret;

	 if(*(end_of_stack(current)+1) == FILE_OPEN_MAGIC)
		return 0;


	sec_d = kzalloc(sizeof(struct sec_domain), GFP_KERNEL);
	if (!sec_d) {
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], kzalloc error!\n", __func__);
		ret = -ENOMEM;
		goto out;
	}

	ret = prepare_sec_domain(sec_d, tsk,dentry, TYPE_DENTRY);
	if (ret) {
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], prepare sec domain err!\n", __func__);
		ret=0;
                goto out;
	}


	hash_len = get_critical_confile_digest(sec_d->obj_name, policy_digest, 256);


	if (!hash_len)//没在白名单里面放行
	{
		ret = 0;
		goto out;
	}else
	{
      ret=1;

	}

	*(end_of_stack(current)+1) = FILE_OPEN_MAGIC;
	mb();

 // 将自定义数据传递给工作处理函数	
	p_handle = get_audit_data();

	if(p_handle){
 
		p_handle->sec_d=(struct sec_domain *)kmalloc(sizeof(struct sec_domain), GFP_KERNEL);
		p_handle->result=ret;
		memcpy(p_handle->sec_d,sec_d,sizeof(struct sec_domain));
//把工作放入队列中
    	queue_delayed_work(my_workqueue, &(p_handle->my_work), msecs_to_jiffies(1000*1));
	}

out:

	if (sec_d)
		kfree(sec_d);
	return ret;

}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0) || RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 1)
static int smeasure_task_kill(struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
static int smeasure_task_kill(struct task_struct *p, struct siginfo *info, int sig, const struct cred *cred)
#else
static int smeasure_task_kill(struct task_struct *p, struct siginfo *info, int sig, u32 secid)
#endif
{
	int ret = 0;
	ret = is_protect_task(p);
	if( ret == 1)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter[%s] signal[%x] pid[%d] name[%s] protected!\n", __func__ ,info->si_signo, p->pid,p->comm);
		return -EAGAIN;
	}

	if(global_old_hook != NULL && global_old_hook->task_kill != NULL )
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0) || RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 1)
		ret = global_old_hook->task_kill( p, info, sig, cred );
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
		ret = global_old_hook->task_kill( p, info, sig, cred );
#else
		ret = global_old_hook->task_kill( p, info, sig, secid );
#endif
		if(ret)
			return ret;
	}

	return ret;
}

void update_whitelist_conf(struct global_control_policy* p_global_policy, uint32_t tpcm_feature, int valid_license)
{
	int is_enabled = 0;

	is_enabled = valid_license ? p_global_policy->be_program_measure_on : 0;
	if ((whitelist_feature.is_enabled != is_enabled)
		|| (whitelist_feature.control_mode != p_global_policy->be_program_control) 
		|| (whitelist_feature.cache_mode != p_global_policy->be_measure_use_cache)
		|| (whitelist_feature.match_mode != p_global_policy->be_program_measure_match_mode) 
		|| (whitelist_feature.measure_mode != p_global_policy->be_program_measure_mode))
	{
		whitelist_feature.is_enabled = is_enabled;

		whitelist_feature.control_mode = p_global_policy->be_program_control;
		whitelist_feature.cache_mode = p_global_policy->be_measure_use_cache;
		whitelist_feature.match_mode = p_global_policy->be_program_measure_match_mode;

		//????????tpcm????????
		whitelist_feature.measure_mode = p_global_policy->be_program_measure_mode;
		if ((p_global_policy->be_program_measure_mode==PROCESS_MEASURE_MODE_TCS_MEASURE) && (!(tpcm_feature & 0x0001)))
		{
			whitelist_feature.measure_mode=PROCESS_MEASURE_MODE_SOFT;
		}
		if (p_global_policy->be_program_measure_mode==PROCESS_MEASURE_MODE_TCS_CHECK && (!(tpcm_feature & 0x0040)))
		{
			whitelist_feature.measure_mode=PROCESS_MEASURE_MODE_SOFT;
		}
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter[%s] whitelist function switch[%d] control switch[%d] cache switch[%d] measure mode[%d]\n", 
			__func__ ,whitelist_feature.is_enabled, whitelist_feature.control_mode, whitelist_feature.cache_mode, whitelist_feature.measure_mode);
	}
}

void whitelist_feature_conf_notify_func(void)
{
	int ret = 0;
	struct global_control_policy global_policy = {0};
	uint32_t tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);
	else
	{
		process_protection_conf_notify_func(global_policy.be_tsb_flag1);
		update_whitelist_conf(&global_policy, tpcm_feature, valid_license);
	}

}

//static struct httcsec_smeasure_engine smeasure_engine = {
//	//.status = INTERCEPT_MODULE_STATUS_ENABLED,
//
//	.bprm_check_security = smeasure_bprm_check_security,
//	.mmap_file = smeasure_mmap_file,
//
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
//	.kernel_read_file = smeasure_kernel_read_file,
//#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
//	.kernel_module_from_file = smeasure_kernel_module_from_file,
//#endif
//
//	.init_module = smeasure_init_module,
//
//	//.file_permission = smeasure_file_permission,
//	.file_open = smeasure_file_open,
//};
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
int noop_pre(struct kprobe *p, struct pt_regs *regs) 
{ 
	return 0;
}

static struct kprobe kp = 
{
	.symbol_name = "kallsyms_lookup_name",
};

unsigned long (*kallsyms_lookup_name_fun)(const char *name) = NULL;

int find_kallsyms_lookup_name(void)
{
	int ret = -1;
	kp.pre_handler = noop_pre;
	ret = register_kprobe(&kp);
	if (ret < 0) 
	{
		DEBUG_MSG(HTTC_TSB_INFO,"register_kprobe failed, error:%d\n", ret);
		return ret;
        }

	DEBUG_MSG(HTTC_TSB_DEBUG,"kallsyms_lookup_name addr: %p\n", kp.addr);
	kallsyms_lookup_name_fun = (void*)kp.addr;
	unregister_kprobe(&kp);
	return ret;
}
#endif


int get_whitelist_switch(int *whiteswitch)
{

DEBUG_MSG(HTTC_TSB_DEBUG,"enter [%s]:whitelist_feature.is_enabled:%d\r\n",__func__,whitelist_feature.is_enabled);
*whiteswitch=whitelist_feature.is_enabled;
return 0;

}
EXPORT_SYMBOL_GPL(get_whitelist_switch);
int smeasure_engine_init(void)
{
    int ret = 0;
	struct global_control_policy global_policy = {0};
	uint32_t tpcm_feature = 0;
	int valid_license = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	if (k_kallsyms_lookup_name == INVALID_DATA_FULL_FF ||
		k_kallsyms_lookup_name == 0) {
			DEBUG_MSG(HTTC_TSB_INFO,"INVALID argument \n");
			return -EINVAL;
	}

	httc_kallsyms_lookup_name = (void *)k_kallsyms_lookup_name;
	httc_get_arg_page = (void *)httc_kallsyms_lookup_name("get_arg_page");
#else

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	ret = find_kallsyms_lookup_name();
	if(ret == 0 && kallsyms_lookup_name_fun != NULL)
	{
		httc_get_arg_page = (void *)kallsyms_lookup_name_fun("get_arg_page");
	}
#else
	httc_get_arg_page = (void *)kallsyms_lookup_name("get_arg_page");
#endif
	if (httc_get_arg_page == NULL) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
		httc_get_arg_page = (void *)get_arg_page;
#else
		DEBUG_MSG(HTTC_TSB_INFO,"Do not support get arg page !!! \n");
		return -EINVAL;
#endif
	}
#endif

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);
	else
	{
		process_protection_conf_notify_func(global_policy.be_tsb_flag1);
		update_whitelist_conf(&global_policy, tpcm_feature, valid_license);
	}
	
	ret = register_feature_conf_notify(FEATURE_WHITELIST, whitelist_feature_conf_notify_func);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], register_feature_conf_notify error ret[%d]!\n",__func__, ret);

  //  ret = httcsec_register_smeasure_engine(&smeasure_engine);
  //  if (ret) {
  //      printk("Httcsec Register Measure Engine ERROR!\n");
  //  } else
		//printk("Httcsec Register Measure Engine OK!\n");

	global_self_hook = kzalloc( sizeof(struct httcsec_intercept_module), GFP_KERNEL);

	global_old_hook = httcsec_get_hook();
	if(global_old_hook != NULL)
		memcpy(global_self_hook, global_old_hook, sizeof(struct httcsec_intercept_module));

	atomic_set(&global_self_hook->intercept_refcnt, 0);
	global_self_hook->bprm_check_security = smeasure_bprm_check_security;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	global_self_hook->mmap_file = smeasure_mmap_file;
#else
	global_self_hook->file_mmap = smeasure_file_mmap;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	global_self_hook->kernel_read_file = smeasure_kernel_read_file;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	global_self_hook->kernel_module_from_file = smeasure_kernel_module_from_file;
#endif
	global_self_hook->init_module = smeasure_init_module;
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	global_self_hook->file_open = smeasure_file_open;
#else
	global_self_hook->dentry_open = smeasure_dentry_open;
#endif
//	printk("====================global_self_hook->inode_unlink========================\r\n");
#ifdef LSM_UNLINK
	global_self_hook->inode_unlink = smeasure_file_unlink; //rm -f
#endif
	global_self_hook->task_kill = smeasure_task_kill;

	global_self_hook->httc_module = THIS_MODULE;

	ret = httcsec_register_hook(global_old_hook, global_self_hook);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Httcsec Register Measure Engine ERROR!\n");
	else
		DEBUG_MSG(HTTC_TSB_DEBUG,"Httcsec Register Measure Engine OK!\n");
	smeasure_wqueue_init();
#ifdef LSM_UNLINK
	smeasure_file_work_init();
#endif
	return ret;
}

int smeasure_engine_exit(void)
{
    int ret = 0;
#ifdef LSM_UNLINK
	smeasure_file_work_exit();
#endif
    //ret = httcsec_unregister_smeasure_engine(&smeasure_engine);
	ret = httcsec_unregister_hook(global_old_hook, global_self_hook);
    if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Httcsec UNRegister Measure Engine ERROR!\n");
    else
		DEBUG_MSG(HTTC_TSB_DEBUG,"Httcsec UNRegister Measure Engine OK!\n");

	if(global_self_hook)
		kfree(global_self_hook);

	unregister_feature_conf_notify(FEATURE_WHITELIST, whitelist_feature_conf_notify_func);

    return ret;
}


