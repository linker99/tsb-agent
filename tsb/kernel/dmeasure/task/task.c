#include <linux/version.h>
#include <linux/profile.h>
#include <linux/notifier.h>
#include <linux/unistd.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#else
#include <linux/sched.h>
#endif
#include <linux/slab.h>
#include <linux/crc32.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/version.h>
#include <asm/mman.h>
#include "dmeasure_types.h"
#include "version.h"
#include "hook/hook.h"
#include "utils/vfs.h"
#include "../policy/policy_dmeasure.h"
#include "sec_domain.h"
#include "function_types.h"
#include "tpcm/tpcmif.h"
#include "utils/debug.h"
#include "../encryption/sm3/sm3.h"
#include "log/log.h"
#include "tsbapi/tsb_measure_kernel.h"
#include "tsbapi/tsb_log_notice.h"
#include "../process_identity/process_identity.h"
#include "../utils/traceability.h"

#define TASK_HASH_CACHE
#ifdef TASK_HASH_CACHE
//#include "../../smeasure/policy/policy_whitelist_cache.h"
#include "file_hash_cache.h"
#endif

static unsigned long tasklistlock = INVALID_DATA_FULL_FF;
module_param(tasklistlock, ulong, 0644);
MODULE_PARM_DESC(tasklistlock, "ulong task list lock address");

static rwlock_t *ptasklist_lock;

#define MEASURE_HASH_LENGTH		4096
static DEFINE_MUTEX(dmeasure_task_mutex);
extern atomic_t dmeasure_hook_use;
static int task_info_count;
static struct hlist_head task_hashtable[MEASURE_HASH_LENGTH];

static void task_dmeasure_check(struct work_struct *work_arg);

#define CIRCLE_NAME	"Periodicity"
#define ACTION_NAME DM_ACTION_TASKLIST_NAME

struct mmap_reference {
	unsigned long addr;
	unsigned long len;
	unsigned char sm3_value[32];
	char md5_value[16];
	unsigned int crc;
	struct file *vm_file;
	int file_type;
	struct list_head list;
};

struct dtask_info {
	struct list_head maps;
	struct list_head tmp_maps;
	int map_count;
	int temp_map_count;
	struct hlist_node list;
	pid_t pid;
	struct task_struct *task;
	struct delayed_work dwork;
	void *private_data;
	struct process_policy *p_process_policy;
	//int interval_count;
	unsigned int status;
	int collected;
	char path[0];
};

rwlock_t* get_tasklist_lock(void)
{
	return ptasklist_lock;
}

static int kernel_args_addr_init(void)
{
	if (tasklistlock == INVALID_DATA_FULL_FF || tasklistlock == 0)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Insmod [TASK] Argument Error!\n");
		return -EINVAL;
	}
	else
	{
		DEBUG_MSG(HTTC_TSB_DEBUG, "tasklistlock:[%0lx]!\n", tasklistlock);
	}

	ptasklist_lock = (rwlock_t *) tasklistlock;

	return 0;
}

static int send_audit_log(struct dmeasure_point *point, const char *name,
			  int result, unsigned char *hash, int pid)
{
	int ret = 0;
	struct sec_domain *sec_d;
	unsigned int user = 0;

	sec_d = kzalloc(sizeof (struct sec_domain), GFP_KERNEL);
	if (!sec_d)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc error!\n", __func__);
		ret = -ENOMEM;
		goto out;
	}

	if (point)
	{
		memcpy(sec_d->sub_name, point->name, strlen(point->name));
	}
	else
	{
		memcpy(sec_d->sub_name, "TSB", strlen("TSB"));
	}
	memcpy(sec_d->obj_name, "task_list(", strlen("task_list("));
	memcpy(sec_d->obj_name+strlen(sec_d->obj_name), name, strlen(name));
	memcpy(sec_d->obj_name+strlen(sec_d->obj_name), ")", 1);
	//memset(sec_d->sub_hash, 0, LEN_HASH);
	memcpy(sec_d->sub_hash, hash, LEN_HASH);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	user = __kuid_val(current->cred->uid);
#else
	user = current->cred->uid;
#endif

	if (point)
	{
		keraudit_log(TYPE_DMEASURE, point->type, result, sec_d, user, pid);
	}
	else
	{
		keraudit_log(TYPE_DMEASURE, DMEASURE_OPERATE_PERIODICITY, result, sec_d,
			     user, pid);
	}

	kfree(sec_d);
out:
	return ret;
}

int calc_hash_from_file(struct file *file, char *digest, int len)
{
	int ret;
	loff_t i_size, offset = 0;
	char *rbuf;
	sm3_context ctx;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	i_size = i_size_read(file->f_inode);
#else
	i_size = i_size_read(file->f_path.dentry->d_inode);
#endif

	sm3_init(&ctx);

	rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!rbuf)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc error!\n", __func__);
		return -ENOMEM;
	}

	while (offset < i_size)
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
		int rbuf_len = kernel_read(file, rbuf, PAGE_SIZE, &offset);
#else
	 	int rbuf_len = kernel_read(file, offset, rbuf, PAGE_SIZE);
#endif
		if (rbuf_len < 0)
		{
			ret = rbuf_len;
			break;
		}
		if (rbuf_len == 0)
			break;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
		offset += rbuf_len;
#endif

		sm3_update(&ctx, rbuf, rbuf_len);
	}

	if (offset == i_size)
	{
		 sm3_finish(&ctx, digest);
		ret = 0;
	}

	if (rbuf)
		kfree(rbuf);

	if (!ret)
	{
		//DEBUG_MSG(HTTC_TSB_DEBUG, "ENTER:[%s], digest SUCCESS!\n", __func__);
		//print_hex(digest, LEN_HASH);
	}
	else
	{
		DEBUG_MSG(HTTC_TSB_INFO, "ENTER:[%s],  dmeasure task calc hash error!\n", __func__);
	}

	return ret;
}

/* original sys call table */
static asmlinkage long (*origin_sys_mmap)(unsigned long addr,
					  unsigned long len,
					  unsigned long prot,
					  unsigned long flags,
					  unsigned long fd, unsigned long offset) = 0;
static asmlinkage long (*origin_sys_mprotect)(unsigned long start, size_t len,
					      unsigned long prot) = 0;



int task_cal_mem_sm3(struct task_struct *task, struct mm_struct *mm,
		     unsigned long from, int length, unsigned char *sm3_hash)
{
	int ret = 0;
	int i = 0;
	int plen = 0;
	int npages = 0;
	unsigned int off = 0;
	unsigned char *maddr = NULL;
	struct page **pages;
	sm3_context ctx;

	off = from & ~PAGE_MASK;
	npages = ((unsigned long) off + length + PAGE_SIZE - 1) >> PAGE_SHIFT;

	pages = kzalloc(npages * sizeof (struct page *), GFP_KERNEL);
	if (!pages)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "No memory, skip measure\n");
		return -ENOMEM;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	ret = get_user_pages_remote(mm, from, npages, FOLL_FORCE, pages, NULL, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	ret = get_user_pages_remote(task, mm, from, npages, FOLL_FORCE, pages, NULL, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	ret = get_user_pages_remote(task, mm, from, npages, FOLL_FORCE, pages, NULL);
#else
	ret = get_user_pages(task, mm, from, npages, 0, 0, pages, NULL);
#endif
	if (ret != npages)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], Get User Page failed. Skip measure .address:[%p] ret:%d, npages:%d\n",
			__func__, (void*)from, ret, npages);
		npages = ret;
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < npages; i++)
	{
		if (!pages[i])
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Get User Page failed. Skip measure \n");
			ret = -ENOMEM;
			goto out;
		}
	}

	sm3_init(&ctx);
	for (i = 0; i < npages; i++)
	{
		plen = min_t(int, length, PAGE_SIZE - off);
		maddr = kmap(pages[i]);
		//crc = crc32(crc, maddr + off, plen);
		sm3_update(&ctx, maddr + off, plen);
		kunmap(pages[i]);
		off = 0;
		length -= plen;
	}
	sm3_finish(&ctx, sm3_hash);

	//*result = crc;
	ret = 0;

out:
	for (i = 0; i < npages; i++)
	{
		if (pages[i])
			put_page(pages[i]);
	}
	kfree(pages);
	return ret;
}

int task_cal_proc_mem_sm3(struct task_struct *task, unsigned long from,
			  int length, unsigned char *sm3_hash)
{
	int ret = 0;
	struct mm_struct *mm = get_task_mm(task);

	if (!mm)
	{
		return -EINVAL;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	down_read(&mm->mmap_lock);
#else
	down_read(&mm->mmap_sem);
#endif
	ret = task_cal_mem_sm3(task, mm, from, length, sm3_hash);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	up_read(&mm->mmap_lock);
#else
	up_read(&mm->mmap_sem);
#endif

	mmput(mm);
	return ret;
}

static struct mmap_reference *init_task_mmap(unsigned long addr, unsigned long len, struct file* vm_file, int type)
{
	struct mmap_reference *mmap;
	int size = sizeof (struct mmap_reference);

	mmap = (struct mmap_reference *) kzalloc(size, GFP_KERNEL);
	if (!mmap)
	{
		return NULL;
	}
	mmap->addr = addr;
	mmap->len = len;
	mmap->vm_file = vm_file;
	mmap->file_type = type;
	return mmap;
}

static struct dtask_info *init_dtask_info(struct task_struct *task,
					  const char *path, struct process_policy *p_process_policy)
{
	struct dtask_info *tski;
	bool issuc;
	unsigned int period;

	int size = sizeof (struct dtask_info) + strlen(path) + 1;

	tski = (struct dtask_info *) kzalloc(size, GFP_KERNEL);
	if (!tski)
	{
		return NULL;
	}
	tski->pid = task->pid;
	tski->task = task;
	atomic_inc(&p_process_policy->obj_count);
	tski->p_process_policy = p_process_policy;
	//tski->interval_count = p_process_policy->be_measure_interval;
	strcpy(tski->path, path);
	INIT_DELAYED_WORK(&tski->dwork, task_dmeasure_check);
	INIT_LIST_HEAD(&tski->maps);
	INIT_LIST_HEAD(&tski->tmp_maps);

	if (p_process_policy->be_measure_interval <= 0)
		period = 10000;
	else
		period = p_process_policy->be_measure_interval;

	issuc = schedule_delayed_work(&tski->dwork, msecs_to_jiffies(period));
	if (!issuc)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "[%s]added delay work failed\n", __func__);
	}

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], path:[%s]!\n", __func__, path);
	return tski;
}

static inline int cal_task_hash_func(const struct task_struct *task)
{
	return ((unsigned long) task) % MEASURE_HASH_LENGTH;
}

struct dtask_info *check_dtask_info(struct task_struct *task)
{
	struct dtask_info *tpos;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *node;
	hlist_for_each_entry(tpos, node, task_hashtable + cal_task_hash_func(task), list)
#else
	hlist_for_each_entry(tpos, task_hashtable + cal_task_hash_func(task), list)
#endif
	{
		if (tpos->task == task && tpos->pid == task->pid
		    && tpos->p_process_policy->process_switch)
		{
			return tpos;
		}
	}
	return NULL;
}

#if defined(CONFIG_CSKY) //奔图2700项目特殊处理，需要最后一次进入__NR_mprotect系统调用时采集基准值
static int collect_exsited_mmap(struct dtask_info *tski, struct mm_struct *mm)
{
	int ret = 0;
	//int flag = 0;
	struct vm_area_struct *vma = NULL;
	struct mmap_reference *item = NULL, *next = NULL;
	struct mmap_reference *mmap = NULL;
	//char *fullpath = NULL;

	for (vma = mm->mmap; vma; vma = vma->vm_next)
	{
		//flag = 0;
		if (vma->vm_file && vma->vm_flags & VM_EXEC)
		{
			list_for_each_entry_safe(item, next, &tski->maps, list)
			{
				if (item->vm_file == vma->vm_file)
				{
					list_del(&item->list);
					kfree(item);
					tski->map_count--;
				}
			}
			//if (flag == 1)
			//	continue;
			//fullpath = vfs_get_fullpath(vma->vm_file, TYPE_FILE);
			//printk("Enter:[%s], fullpath:[%s] OK!\n", __func__, fullpath);

			mmap = init_task_mmap(vma->vm_start, vma->vm_end - vma->vm_start, vma->vm_file, 0);
			if (!mmap)
				return -ENOMEM;

			mmap->vm_file = vma->vm_file;
			if (task_cal_mem_sm3
			    (tski->task, mm, vma->vm_start,
			     vma->vm_end - vma->vm_start, mmap->sm3_value))
				kfree(mmap);
			else
			{
				list_add_tail(&mmap->list, &tski->maps);
				tski->map_count++;

				//printk("Enter:[%s], add task->comm[%s] addr[%p] length[%lu] ok\n",
				//       __func__, tski->task->comm, (void *) vma->vm_start,
				//       vma->vm_end - vma->vm_start);
				//print_hex("task_bak", mmap->sm3_value, LEN_HASH);
			}
		}
	}
	return ret;
}
#else
static int collect_exsited_mmap(struct dtask_info *tski, struct mm_struct *mm)
{
	int ret = 0;
	struct vm_area_struct *vma;
	struct mmap_reference *item = NULL;
	struct mmap_reference *mmap = NULL;
	struct elfhdr elf_ex;
	int retval = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	loff_t offset = 0;
#endif
	//char *fullpath = NULL;

	for (vma = mm->mmap; vma; vma = vma->vm_next)
	{
		if (vma->vm_file && vma->vm_flags & VM_EXEC)
		{
			int flag = 0;
			list_for_each_entry(item, &tski->maps, list)
			{
				if (item->vm_file == vma->vm_file)
				{
					flag = 1;
					break;
				}
			}
			if (flag == 1)
				continue;
			//fullpath = vfs_get_fullpath(vma->vm_file, TYPE_FILE);
			//printk("Enter:[%s], fullpath:[%s] OK!\n", __func__, fullpath);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
			offset = 0;
			retval = kernel_read(vma->vm_file, (char *)&elf_ex, sizeof(elf_ex), &offset);
#else
			retval = kernel_read(vma->vm_file, 0, (char *)&elf_ex, sizeof(elf_ex));
#endif
			if (retval != sizeof(elf_ex)) {
				DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vma_name[%s] read error!\n", __func__, vma->vm_file->f_path.dentry->d_iname);
				continue;
			}
			//printk("Enter:[%s], vma_name[%s] elf_ex.e_type[%d] ET_EXEC[%d] ET_DYN[%d]\n", __func__, vma->vm_file->f_path.dentry->d_iname, elf_ex.e_type, ET_EXEC, ET_DYN);
			if ((elf_ex.e_type!=ET_EXEC) && (elf_ex.e_type!=ET_DYN)) {
				DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vma_name[%s] elf_ex.e_type[%d] is invalid skip! ET_EXEC[%d] ET_DYN[%d] \n", __func__, vma->vm_file->f_path.dentry->d_iname, elf_ex.e_type, ET_EXEC, ET_DYN);
				continue;
			}

			mmap = init_task_mmap(vma->vm_start, vma->vm_end - vma->vm_start, vma->vm_file, elf_ex.e_type);
			if (!mmap)
				return -ENOMEM;

			mmap->vm_file = vma->vm_file;
			if (task_cal_mem_sm3
				(tski->task, mm, vma->vm_start,
				vma->vm_end - vma->vm_start, mmap->sm3_value))
				kfree(mmap);
			else
			{
				list_add_tail(&mmap->list, &tski->maps);
				tski->map_count++;
				DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], add vm_file[%s] addr[%p] length[%lu] elf_ex.e_type[%d] ET_EXEC[%d] ET_DYN[%d] ok\n",
					__func__, /*tski->task->comm*/vma->vm_file->f_path.dentry->d_iname, (void*)vma->vm_start,
					vma->vm_end - vma->vm_start, elf_ex.e_type, ET_EXEC, ET_DYN);
			}
		}
	}
	return ret;
}
#endif
static int add_tmp_mem_map(struct task_struct *task, unsigned long addr,
			   unsigned long len, const char *path)
{
	int ret = 0;
	struct dtask_info *tski;
	//struct mmap_reference *mmap = NULL;
	struct file *exec_file = NULL;
	struct mm_struct *mm = NULL;
	char file_hash[LEN_HASH] = { 0 };
	//int is_measure_child_proesss = 0;
	struct process_policy *p_process_policy = NULL;
	struct dtask_info *task_info = NULL;

	tski = check_dtask_info(task);
	if (!tski)
	{

		mm = get_task_mm(task);
		if (!mm)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_task_mm error!\n", __func__);
			ret = -ENOMEM;
			goto out;
		}
		exec_file = get_mm_exe_file(mm);
		if (!exec_file)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_mm_exe_file error!\n", __func__);
			mmput(mm);
			ret = -ENOMEM;
			goto out;
		}

#ifdef TASK_HASH_CACHE
		ret = check_file_hash_cache(exec_file, (char *) path, file_hash);
		if (ret)
		{
			ret = calc_hash_from_file(exec_file, file_hash, LEN_HASH);
			//fput(exec_file);
			//mmput(mm);
			if (ret)
			{
				DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], calc_hash_from_file path[%s] error!\n",
					__func__, path);
				ret = -ENOMEM;
				goto out;
			}

			set_file_hash_cache(exec_file, (char *) path, file_hash);
		}
#else
		ret = calc_hash_from_file(exec_file, file_hash, LEN_HASH);
		//fput(exec_file);
		//mmput(mm);
		if (ret)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], calc_hash_from_file path[%s] error!\n", __func__, path);
			ret = -ENOMEM;
			goto out;
		}
#endif
		task_info = check_dtask_info(task->real_parent);
		p_process_policy = query_policy_dmeasure_process((char *) path, task->comm, file_hash, LEN_HASH);
		if (!p_process_policy)
		{
			//task不在策略里，需要判断其父进程是否在已采集信息的进程中，如果在并且该父进程需要度量子进程，那么需要采集task信息并且将信息添加到进程检测列表中
			if ((!task_info) || (task_info->p_process_policy->sub_process_mode != PROCESS_DMEASURE_MODE_MEASURE))
			{
				ret = -ENOMEM;
				goto out;
			}
			//父进程需要度量子进程，采集子进程task信息
			p_process_policy = task_info->p_process_policy;
			DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], task[%s] parent process need measure child process\n", __func__, path);
		}
		else
		{
			//fork子进程后，execl动作在另外一个函数启动时，子进程全路径与父进程全路径相同，需跳过
			if(task_info && strcmp(path, task_info->path)==0)
			{
				DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], parent process path[%s] == child process path[%s], skip\n", __func__, task_info->path, path);
				ret = -ENOMEM;
				goto out;
			}
		}

		tski = init_dtask_info(task, path, p_process_policy);
		if (!tski)
		{
			ret = -ENOMEM;
			goto out;
		}
		hlist_add_head(&tski->list, task_hashtable + cal_task_hash_func(task));
		task_info_count++;

		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], process_check_hash_table add process path[%s] success\n",
			__func__, path);
	}

	//if (addr && len) {
	//      mmap = init_task_mmap(addr, len);
	//      if (!mmap) {
	//              ret = -ENOMEM;
	//              goto out;
	//      }
	//      list_add(&mmap->list, &tski->tmp_maps);
	//      tski->temp_map_count++;
	//      printk("Enter:[%s], add task mmap, addr:[%p], len:[%lu]!\n", __func__, (void *)addr, len);
	//}
	//printk("Enter:[%s], process_check_hash_table add process path[%s] success\n", __func__, path);
out:
	if (exec_file)
		fput(exec_file);
	if (mm)
		mmput(mm);
	return ret;
}

static void convert_tmp_mem_map(struct task_struct *task, unsigned long addr)
{
	//int ret = 0;
	struct dtask_info *tski;
	//struct mmap_reference *tpos, *n;

	tski = check_dtask_info(task);
	if (!tski)
		goto out;

	collect_exsited_mmap(tski, tski->task->mm);

out:
	return;
//
//      list_for_each_entry_safe(tpos, n, &tski->tmp_maps, list) {
//              if (addr < tpos->addr || addr >= tpos->addr + tpos->len)
//                      continue;
//
//              tpos->len = addr - tpos->addr;
//
//              ret =
//                  task_cal_proc_mem_sm3(task, tpos->addr, tpos->len,
//                                          tpos->sm3_value);
//              if (ret) {
//                      list_del(&tpos->list);
//                      kfree(tpos);
//                      tski->temp_map_count--;
//                      continue;
//              }
//
//              if (!tski->collected) {
//                      if (!collect_exsited_mmap(tski, tski->task->mm)) {
//                              tski->collected = 1;
//                      }
//                      list_del(&tpos->list);
//                      kfree(tpos);
//                      tski->temp_map_count--;
//                      continue;
//              }
//
//              list_del(&tpos->list);
//              list_add(&tpos->list, &tski->maps);
//              tski->map_count++;
//              tski->temp_map_count--;
//              //printk("Add task mmap path:[%s], task:[%p], pid:[%d], address:[%p], end:[%p], count:[%d]\n", 
//              //              tski->path, tski->task, tski->pid, (void *)tpos->addr, (void *)tpos->addr + tpos->len, tski->map_count);
//      }
//
//out:
//      return;
}



static asmlinkage long new_sys_mmap(unsigned long addr, unsigned long len,
				    unsigned long prot, unsigned long flags,
				    unsigned long fd, unsigned long offset)
{
	long ret = 0;
	int result = 0;
	char *path = NULL;

	atomic_inc(&dmeasure_hook_use);
	ret = origin_sys_mmap(addr, len, prot, flags, fd, offset);
	if (ret < 0)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], origin_sys_mmap return err!\n", __func__);
		goto out;
	}

	if(policy_is_empty() == 0){
		goto out;	
	}

	if ((int)fd >= 0)
	{
		path = vfs_get_fullpath(current, TYPE_TASK);
		if (!path)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get fullpath is NULL!\n", __func__);
			goto out;
		}

		mutex_lock(&dmeasure_task_mutex);
		result = add_tmp_mem_map(current->group_leader, ret, len, path);
		if (result == 0)
		{
			//printk("Enter:[%s], add task:[%s] tmp_mem_map success!\n", __func__, path);
		}
		else
		{
			//printk("Enter:[%s], add task:[%s] tmp_mem_map failed!\n", __func__, path);
		}
		mutex_unlock(&dmeasure_task_mutex);

		vfs_put_fullpath(path);
	}

out:
	atomic_dec(&dmeasure_hook_use);
	remove_current_task_ids_cache(NULL);
	return ret;
}

static asmlinkage long new_sys_mprotect(unsigned long start, size_t len, unsigned long prot)
{
	unsigned long ret = 0;

	atomic_inc(&dmeasure_hook_use);
	ret = origin_sys_mprotect(start, len, prot);
	if (ret != 0)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], origin_sys_mprotect return err!\n", __func__);
		goto out;
	}

	if(policy_is_empty() == 0){
		goto out;	
	}

	mutex_lock(&dmeasure_task_mutex);
	convert_tmp_mem_map(current->group_leader, start);
	mutex_unlock(&dmeasure_task_mutex);

out:
	atomic_dec(&dmeasure_hook_use);
	remove_current_task_ids_cache(NULL);
	return ret;
}

int delete_task_all_mmap(struct dtask_info *tski)
{
	struct mmap_reference *mmap, *next;

	list_for_each_entry_safe(mmap, next, &tski->maps, list)
	{
		list_del(&mmap->list);
		kfree(mmap);
		tski->map_count--;
		//printk("Enter:[%s], task_info:[%s](%d), [%p] map_count:[%d]\n", 
		//              __func__, tski->path, tski->pid, tski->task, tski->map_count);
	}

	list_for_each_entry_safe(mmap, next, &tski->tmp_maps, list)
	{
		list_del(&mmap->list);
		kfree(mmap);
		tski->temp_map_count--;
		//printk("Enter:[%s], task_info:[%s](%d), [%p] temp_map_count:[%d]\n", 
		//              __func__, tski->path, tski->pid, tski->task, tski->temp_map_count);
	}
	return 0;
}

static void remove_task_info(struct dtask_info *tski)
{
	delete_task_all_mmap(tski);
	hlist_del(&tski->list);

	atomic_dec(&tski->p_process_policy->obj_count);
	if (!tski->p_process_policy->process_switch)
	{
		if (atomic_read(&tski->p_process_policy->obj_count) == 0)
		{
			DEBUG_MSG(HTTC_TSB_DEBUG,
				  "Enter:[%s], dmeasure_process policy [%s] isnot using, delete success\n",
				  __func__, tski->p_process_policy->object_id);
			kfree(tski->p_process_policy);
		}
	}

	cancel_delayed_work(&tski->dwork);
	task_info_count--;
	//printk("Enter:[%s], [%s] pid:[%d] (m_c:[%d], tm_c:[%d]) task_info_count:[%d]\n", 
	//              __func__, tski->path, tski->pid, tski->map_count, tski->temp_map_count, task_info_count);
	kfree(tski);
}

static void remove_all_task_info(void)
{
	int i = 0;
	struct dtask_info *tski = NULL;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif

	mutex_lock(&dmeasure_task_mutex);
	for (i = 0; i < MEASURE_HASH_LENGTH; i++)
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
		hlist_for_each_entry_safe(tski, node, next, task_hashtable + i, list)
		{
#else
		hlist_for_each_entry_safe(tski, node, task_hashtable + i, list)
		{
#endif
			remove_task_info(tski);
		}
	}
	mutex_unlock(&dmeasure_task_mutex);
}

static void remove_task_info_of_task(struct task_struct *task)
{
	struct dtask_info *task_info = check_dtask_info(task);

	if (task_info)
		remove_task_info(task_info);
}

static int task_exit_handler(struct notifier_block *nb, unsigned long val, void *data)
{
	int ret = 0;
	//char *path = NULL;
	struct task_struct *tsk = NULL;

	if (data != NULL)
	{
		tsk = (struct task_struct *) data;
		//test
		//path = vfs_get_fullpath(tsk, TYPE_TASK);
		//if (path)
		//      printk("Enter:[%s], fullpath:[%s]!\n", __func__, path);
		//vfs_put_fullpath(path);
		//end
		mutex_lock(&dmeasure_task_mutex);
		if (thread_group_leader(tsk))
			remove_task_info_of_task(tsk);
		mutex_unlock(&dmeasure_task_mutex);

		if (thread_group_leader(tsk))
			remove_current_task_ids_cache(tsk);
	}

	return ret;
}

static inline struct task_struct *pid_to_task(pid_t pid)
{
	return pid_task(find_pid_ns(pid, &init_pid_ns), PIDTYPE_PID);
}

static void task_dmeasure_check(struct work_struct *work_arg)
{
	int ret = -1;
	unsigned char hash[LEN_HASH] = { 0 };
	struct mmap_reference *mmap = NULL;
	struct task_struct *task = NULL;
	struct dtask_info *dski_info;
	struct dmeasure_point *point = NULL;
	struct delayed_work *delay_work;
	struct dmeasure_feature_conf *dmeasure_feature;
	bool issuc;
	unsigned int period;

	delay_work = container_of(work_arg, struct delayed_work, work);
	dski_info = container_of(delay_work, struct dtask_info, dwork);

	dmeasure_feature = get_dmeasure_feature_conf();
	if (!dmeasure_feature->is_enabled)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "[%s]dmeasure_switch[%d], dmeasure function not have!\n", __func__, dmeasure_feature->is_enabled);
		goto out;
	}

	if (dski_info->private_data)
	{
		point = (struct dmeasure_point *) dski_info->private_data;
	}

	mutex_lock(&dmeasure_task_mutex);
	if (!dski_info->p_process_policy->process_switch)
	{
		remove_task_info(dski_info);
		mutex_unlock(&dmeasure_task_mutex);
		return;
	}
	ret = 0;

	rcu_read_lock();
	task = pid_to_task(dski_info->pid);
	if (task)
	{
		if (task == dski_info->task)
			get_task_struct(task);
		else
			task = NULL;
	}
	rcu_read_unlock();

	if (!task)
	{
		remove_task_info(dski_info);
		mutex_unlock(&dmeasure_task_mutex);
		return;
	}

	list_for_each_entry(mmap, &dski_info->maps, list)
	{
		//如果不需要度量库
		if ((dski_info->p_process_policy->share_lib_mode==PROCESS_DMEASURE_MODE_NON_MEASURE) && 
			(strcmp(mmap->vm_file->f_path.dentry->d_iname+strlen(mmap->vm_file->f_path.dentry->d_iname)-3, ".so")==0)) {
			DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], share_lib_mode[%d], so file[%s] skip!\n", __func__, dski_info->p_process_policy->share_lib_mode, mmap->vm_file->f_path.dentry->d_iname);
			continue;
		}

		if (task_cal_proc_mem_sm3(dski_info->task, mmap->addr, mmap->len, hash))
			break;

		if (memcmp(mmap->sm3_value, hash, LEN_HASH) != 0) {

			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], DMeasure TaskMem(path:[%s], pid:[%d], addr:[%p], length:[%d]) failed\n",
				__func__, dski_info->path, dski_info->pid, (void*)mmap->addr,
				(int)mmap->len);
			//print_hex("err_task_bak", mmap->sm3_value, LEN_HASH);
			//print_hex("err_task_now", hash, LEN_HASH);

			ProcessCodeFailureCount_add();
			send_audit_log(point, dski_info->path, RESULT_FAIL, hash, dski_info->pid);
			ret = -EACCES;
			break;
		}
	}

	put_task_struct(task);
//task_done:
	mutex_unlock(&dmeasure_task_mutex);

	//dski_info->interval_count = dski_info->p_process_policy->be_measure_interval;

	if(ret == 0) {
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], Dmeasure task:[%s] pid:[%d] ret:[%d] interval[%d] OK!\n", __func__,
			dski_info->path, dski_info->pid, ret, dski_info->p_process_policy->be_measure_interval);
		memset(hash, 0, LEN_HASH);
		send_audit_log(point, dski_info->path, RESULT_SUCCESS, hash, dski_info->pid);
	}

out:
	if (dski_info->p_process_policy->be_measure_interval <= 0)
		period = 10000;
	else
		period = dski_info->p_process_policy->be_measure_interval;

	issuc = schedule_delayed_work(&dski_info->dwork, msecs_to_jiffies(period));
	if (!issuc)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "[%s]added delay work failed\n", __func__);
	}

	return;
}

static int add_exist_task_info(struct task_struct *task, struct mm_struct *mm,
			       const char *path, struct process_policy *p_process_policy)
{
	int ret = 0;
	unsigned long len = 0;
	struct vm_area_struct *vma = NULL;
	struct mmap_reference *mmap = NULL;
	struct dtask_info *tski = NULL;
	struct elfhdr elf_ex;
	int retval = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	loff_t offset = 0;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	down_read(&mm->mmap_lock);
#else
	down_read(&mm->mmap_sem);
#endif
	if (!mm->mmap)
	{
		ret = -EINVAL;
		goto out_upsem;
	}
	vma = mm->mmap;

	tski = init_dtask_info(task, path, p_process_policy);
	if (!tski)
	{
		ret = -ENOMEM;
		goto out_upsem;
	}

	for (; vma; vma = vma->vm_next)
	{
		len = vma->vm_end - vma->vm_start;
		if (vma->vm_file && (vma->vm_flags & VM_EXEC) && !(vma->vm_flags & VM_WRITE))
		{

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
			offset = 0;
			retval = kernel_read(vma->vm_file, (char *)&elf_ex, sizeof(elf_ex), &offset);
#else
			retval = kernel_read(vma->vm_file, 0, (char *)&elf_ex, sizeof(elf_ex));
#endif
			if (retval != sizeof(elf_ex)) {
				DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vma_name[%s] read error!\n", __func__, vma->vm_file->f_path.dentry->d_iname);
				continue;
			}
			//printk("Enter:[%s], vma_name[%s] elf_ex.e_type[%d] ET_EXEC[%d] ET_DYN[%d]\n", __func__, vma->vm_file->f_path.dentry->d_iname, elf_ex.e_type, ET_EXEC, ET_DYN);
			if ((elf_ex.e_type!=ET_EXEC) && (elf_ex.e_type!=ET_DYN)) {
				DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vma_name[%s] elf_ex.e_type[%d] is invalid skip! ET_EXEC[%d] ET_DYN[%d] \n", __func__, vma->vm_file->f_path.dentry->d_iname, elf_ex.e_type, ET_EXEC, ET_DYN);
				continue;
			}

			mmap = init_task_mmap(vma->vm_start, len, vma->vm_file, elf_ex.e_type);
			if (!mmap)
			{
				DEBUG_MSG(HTTC_TSB_INFO, "kmalloc init_task_mmap error!\n");
				ret = -ENOMEM;
				goto out_error;
			}

			if (task_cal_mem_sm3(task, mm, vma->vm_start, len, mmap->sm3_value))
			{
				kfree(mmap);
			}
			else
			{
				list_add_tail(&mmap->list, &tski->maps);
				tski->map_count++;
			}
		}
	}

	hlist_add_head(&tski->list, task_hashtable + cal_task_hash_func(task));
	task_info_count++;
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], task:[%s]\n", __func__, path);
	ret = 0;
	goto out_upsem;

out_error:
	delete_task_all_mmap(tski);
	cancel_delayed_work(&tski->dwork);
	kfree(tski);
out_upsem:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	up_read(&mm->mmap_lock);
#else
	up_read(&mm->mmap_sem);
#endif
	return ret;
}

static int collect_child_task_info(struct task_struct *task,
				   struct process_policy *p_process_policy)
{
	int ret = 0;
	char *p, *pathname;
	struct file *exec_file = NULL;
	struct mm_struct *mm = NULL;
	//struct list_head *pos = NULL;
	struct task_struct *tsk = NULL;

	pathname = kzalloc(PATH_MAX + 11, GFP_KERNEL);
	if (!pathname)
	{
		goto out;
	}

	//list_for_each(pos, &task->children) {
	//      tsk = list_entry(pos, struct task_struct, sibling);  //不能用children，用sibling
	list_for_each_entry(tsk, &task->children, sibling)
	{

		mm = get_task_mm(tsk);
		if (!mm)
			continue;
		exec_file = get_mm_exe_file(mm);
		if (!exec_file)
		{
			mmput(mm);
			continue;
		}
		memset(pathname, 0, PATH_MAX + 11);
		if (!check_dtask_info(tsk))
		{
			p = d_path(&exec_file->f_path, pathname, PATH_MAX + 11);
			if (IS_ERR(p))
			{
				fput(exec_file);
				mmput(mm);
				continue;
			}
			add_exist_task_info(tsk, mm, p, p_process_policy);
			DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], add child process[%s] success\n",
				  __func__, p);
		}
		fput(exec_file);
		mmput(mm);
	}
	kfree(pathname);

out:
	return ret;
}

/*static */ int collect_existed_task_info(void)
{
	int ret = 0;
	char *p, *pathname;
	struct file *exec_file = NULL;
	struct task_struct *tsk = NULL;
	struct mm_struct *mm = NULL;
	unsigned char file_hash[LEN_HASH] = { 0 };
	//int is_measure_child_proesss = 0;
	struct process_policy *p_process_policy = NULL;

	pathname = kzalloc(PATH_MAX + 11, GFP_KERNEL);
	if (!pathname)
	{
		goto out;
	}
	//read_lock(ptasklist_lock);
	for_each_process(tsk)
	{
		mm = get_task_mm(tsk);
		if (!mm)
			continue;
		exec_file = get_mm_exe_file(mm);
		if (!exec_file)
		{
			mmput(mm);
			continue;
		}
		memset(pathname, 0, PATH_MAX + 11);
		if (!check_dtask_info(tsk))
		{
			p = d_path(&exec_file->f_path, pathname, PATH_MAX + 11);
			if (IS_ERR(p))
			{
				fput(exec_file);
				mmput(mm);
				continue;
			}

#ifdef TASK_HASH_CACHE
			memset(file_hash, 0, LEN_HASH);
			ret = check_file_hash_cache(exec_file, p, file_hash);
			if (ret)
			{
				ret = calc_hash_from_file(exec_file, file_hash, LEN_HASH);
				if (ret)
				{
					fput(exec_file);
					mmput(mm);
					continue;
				}

				set_file_hash_cache(exec_file, p, file_hash);
			}

			p_process_policy =
			    query_policy_dmeasure_process(p, tsk->comm, file_hash, LEN_HASH);
			if (p_process_policy)
			{
				add_exist_task_info(tsk, mm, p, p_process_policy);

				if (p_process_policy->sub_process_mode ==
				    PROCESS_DMEASURE_MODE_MEASURE)
					collect_child_task_info(tsk, p_process_policy);

			}
#else
			memset(file_hash, 0, LEN_HASH);
			if (!calc_hash_from_file(exec_file, file_hash, LEN_HASH))
			{
				p_process_policy =
				    query_policy_dmeasure_process(p, tsk->comm, file_hash,
								  LEN_HASH);
				if (p_process_policy)
				{
					add_exist_task_info(tsk, mm, p, p_process_policy);

					if (p_process_policy->sub_process_mode ==
					    PROCESS_DMEASURE_MODE_MEASURE)
						collect_child_task_info(tsk, p_process_policy);

				}
			}
#endif

		}
		fput(exec_file);
		mmput(mm);
	}
	//read_unlock(ptasklist_lock);

	kfree(pathname);

out:
	return ret;
}

static struct notifier_block exit_notifier = {
	.notifier_call = task_exit_handler,
};

int task_init(void)
{
	int ret = 0;

	ret = kernel_args_addr_init();
	if (ret)
		goto out;

	ret = file_hash_cache_init();
	if (ret < 0)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "file hash cache init error!\n");
		goto out;
	}

	collect_existed_task_info();

	ret = profile_event_register(PROFILE_TASK_EXIT, &exit_notifier);
	if (ret) {
		ret = -EINVAL;
		goto event_out;
	}

#if defined(CONFIG_MIPS)
	ret = hook_replace_system_call(__NR_mmap-__NR_Linux, (unsigned long *) new_sys_mmap, (unsigned long **) &origin_sys_mmap);
	if (ret) {
		ret = -EINVAL;
		goto mmap_out;
	}

	ret = hook_replace_system_call(__NR_mprotect-__NR_Linux, (unsigned long *) new_sys_mprotect, (unsigned long **) &origin_sys_mprotect);
	if (ret) {
		ret = -EINVAL;
		goto mprotect_out;
	}
#else
	ret = hook_replace_system_call(__NR_mmap, (unsigned long *) new_sys_mmap, (unsigned long **) &origin_sys_mmap);
	if (ret) {
		ret = -EINVAL;
		goto mmap_out;
	}

	ret = hook_replace_system_call(__NR_mprotect, (unsigned long *) new_sys_mprotect, (unsigned long **) &origin_sys_mprotect);
	if (ret) {
		ret = -EINVAL;
		goto mprotect_out;
	}
#endif

	return ret;

mprotect_out:
#if defined(CONFIG_MIPS)
	hook_restore_system_call(__NR_mmap-__NR_Linux, (unsigned long *) new_sys_mmap, (unsigned long **) &origin_sys_mmap);
#else
	hook_restore_system_call(__NR_mmap, (unsigned long *) new_sys_mmap, (unsigned long **) &origin_sys_mmap);
#endif
	
mmap_out:
	profile_event_unregister(PROFILE_TASK_EXIT, &exit_notifier);
event_out:
	remove_all_task_info();
out:
	return ret;
}

void task_exit(void)
{
	profile_event_unregister(PROFILE_TASK_EXIT, &exit_notifier);

#if defined(CONFIG_MIPS)
	if (origin_sys_mmap)
		hook_restore_system_call(__NR_mmap-__NR_Linux, (unsigned long *) new_sys_mmap, (unsigned long **) &origin_sys_mmap);
	if (origin_sys_mprotect)
		hook_restore_system_call(__NR_mprotect-__NR_Linux, (unsigned long *) new_sys_mprotect, (unsigned long **) &origin_sys_mprotect);
#else
	if (origin_sys_mmap)
		hook_restore_system_call(__NR_mmap, (unsigned long *) new_sys_mmap, (unsigned long **) &origin_sys_mmap);
	if (origin_sys_mprotect)
		hook_restore_system_call(__NR_mprotect, (unsigned long *) new_sys_mprotect, (unsigned long **) &origin_sys_mprotect);
#endif

	remove_all_task_info();
	file_hash_cache_exit();
	DEBUG_MSG(HTTC_TSB_DEBUG, "######################### dmeasure task exit!\n");
	return;
}

/* process dmeasure interface */
int tsb_measure_process(unsigned pid)
{
	struct task_struct *task = NULL;
	int ret = 0;

	if(pid==0)
	{
		task = current;
	}
	else
	{
		rcu_read_lock();
		task = pid_to_task(pid);
		rcu_read_unlock();
		if (!task)
			return TSB_ERROR_SYSTEM;
	}

	get_task_struct(task);
	ret = tsb_measure_process_taskp(task);
	put_task_struct(task);

	return ret;
}

EXPORT_SYMBOL(tsb_measure_process);

int tsb_measure_process_taskp(struct task_struct *task)
{
	struct dtask_info *dski_info;
	int ret = 0;
	unsigned char hash[LEN_HASH] = { 0 };
	struct mmap_reference *mmap = NULL;

	mutex_lock(&dmeasure_task_mutex);

	dski_info = check_dtask_info(task);
	if ((!dski_info) || (!dski_info->p_process_policy->process_switch))
	{
		ret = TSB_ERROR_DMEASURE_POLICY_NOT_FOUND;
		goto out;
	}

	list_for_each_entry(mmap, &dski_info->maps, list)
	{
		if (task_cal_proc_mem_sm3(dski_info->task, mmap->addr, mmap->len, hash))
		{
			ret = TSB_ERROR_CALC_HASH;
			goto out;
		}

		if (memcmp(mmap->sm3_value, hash, LEN_HASH) != 0)
		{

			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], measure TaskMem(path:[%s], pid:[%d], addr:[%p], length:[%d]) failed\n",
				__func__, dski_info->path, dski_info->pid, (void*)mmap->addr,
				(int)mmap->len);
			ret = TSB_MEASURE_FAILE;
			goto out;
		}

		//如果不需要度量库，仅度量第一个节点即可
		if (dski_info->p_process_policy->share_lib_mode ==
		    PROCESS_DMEASURE_MODE_NON_MEASURE)
			break;
	}

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], measure task:[%s] OK!\n", __func__, dski_info->path);
out:
	mutex_unlock(&dmeasure_task_mutex);
	return ret;
}

EXPORT_SYMBOL(tsb_measure_process_taskp);
