#include <linux/version.h>
#include <linux/version.h>
#include <linux/binfmts.h>
#include <linux/elf.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/mman.h>
//#include <asm-generic/module.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/sched/task_stack.h>
#else
#include <linux/sched.h>
#endif
#include "list_fac.h"
#include "policy_fac_cache.h"
#include "regexp.h"
#include "utils/debug.h"
#include "utils/vfs.h"
#include "common.h"
#include "tpcm_def.h"
#include "msg/command.h"
#include "tcsapi/tcs_file_protect_def.h"
#include "tsbapi/tsb_measure_kernel.h"
#include "../../smeasure/policy/hash_whitelist.h"
#include "../encryption/sm3/sm3.h"

LIST_HEAD(g_list_policy_fac);
rwlock_t policy_fac_lock;

#define FILE_OPEN_MAGIC 0xab12ddef
int calc_sub_hash(const char *fullpath, unsigned char *hash, int is_file_open)
{
	int ret = 0;
	struct file *fp = NULL;

	//if(*(end_of_stack(current)+1) == FILE_OPEN_MAGIC)
	//	return 0;

	if (is_file_open)
	{
		*(end_of_stack(current)+1) = FILE_OPEN_MAGIC;
		mb();
		fp = filp_open(fullpath, O_RDONLY, 0);
		*(end_of_stack(current)+1) = 0;
	}
	else
	{
		fp = filp_open(fullpath, O_RDONLY, 0);
	}
	if (IS_ERR(fp) || !fp) {
		DEBUG_MSG(HTTC_TSB_INFO,"filp_open [%s] error! error code[%ld]!\n", fullpath, PTR_ERR(fp));
		ret = -EINVAL;
		goto err_out;
	}

	ret = digest_cal(fp, hash, LEN_HASH);
	if (ret < 0) {
		DEBUG_MSG(HTTC_TSB_INFO, "digest check [%s] error!\n", fullpath);
		filp_close(fp, NULL);
		goto err_out;
	}
	filp_close(fp, NULL);

err_out:
	return ret;
}

int task_cal_mem_file_hash(char *fullpath, struct task_struct *task, struct mm_struct *mm, unsigned long from, int length, int file_offset, unsigned char *hash, int is_file_open)
{
	int ret = 0;
	int i = 0;
	int plen = 0;
	int npages = 0;
	unsigned int off = 0;
	unsigned char *maddr = NULL;
	struct page **pages = NULL;
	sm3_context ctx;
	struct file *file = NULL;
	unsigned char *buff = NULL;
	int read_len = 0;
	loff_t offset = 0;

	if (is_file_open) {
		*(end_of_stack(current)+1) = FILE_OPEN_MAGIC;
		mb();
		file = filp_open(fullpath, O_RDONLY, 0);
		*(end_of_stack(current)+1) = 0;
	}
	else {
		file = filp_open(fullpath, O_RDONLY, 0);
	}
	if (IS_ERR(file)) {
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], filp_open[%s] error!\n", __func__, fullpath);
		return -ENOMEM;
	}

	sm3_init(&ctx);
	buff = kmalloc(4096,GFP_KERNEL);
	while(offset<file_offset)
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
		read_len = kernel_read(file, buff, 4096, &offset);
#else
		read_len = kernel_read(file, offset, buff, 4096);
		offset += read_len;
#endif

		sm3_update(&ctx, buff, read_len);
	}
	offset += length;

	off = from & ~PAGE_MASK;
	npages = ((unsigned long)off + length + PAGE_SIZE - 1) >> PAGE_SHIFT;

	pages = kzalloc(npages * sizeof(struct page *), GFP_KERNEL);
	if (!pages) {
		DEBUG_MSG(HTTC_TSB_INFO, "No memory, skip measure\n");
		kfree(buff);
		filp_close(file, NULL);
		return -ENOMEM;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	ret = get_user_pages(from, npages, 0, pages, NULL);
#else
	ret = get_user_pages(task, mm, from, npages, 0, 0, pages, NULL);
#endif
	if (ret != npages) {
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], Get User Page failed. Skip measure .address:[%p] ret:%d, npages:%d\n",
			__func__, (void*)from, ret, npages);
		npages = ret;
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < npages; i++) {
		if (!pages[i]) {
			DEBUG_MSG(HTTC_TSB_INFO, "Get User Page failed. Skip measure \n");
			ret = -ENOMEM;
			goto out;
		}
	}

	//进程代码段数据
	for (i = 0; i < npages; i++) {
		plen = min_t(int, length, PAGE_SIZE - off);
		maddr = kmap(pages[i]);
		//crc = crc32(crc, maddr + off, plen);
		sm3_update(&ctx, maddr + off, plen);
		kunmap(pages[i]);
		off = 0;
		length -= plen;
	}

	//剩余数据从文件中读取
	while(1)
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
		read_len = kernel_read(file, buff, 4096, &offset);
#else
		read_len = kernel_read(file, offset, buff, 4096);
#endif
		if (read_len<=0)
			break;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
		offset += read_len;
#endif

		sm3_update(&ctx, buff, read_len);
	}

	sm3_finish(&ctx, hash);
	//print_hex("hash", digest, LEN_HASH);

	ret = 0;
	//DEBUG_MSG(HTTC_TSB_INFO, "task_cal_mem_file_hash success\n");
out:
	kfree(buff);
	filp_close(file, NULL);
	for (i = 0; i < npages; i++) {
		if (pages[i])
			put_page(pages[i]);
	}
	kfree(pages);
	return ret;
}

int measure_process(struct sec_domain *sec_d, int is_file_open)
{
	unsigned char hash[LEN_HASH] = {0};
	int ret = 0, len = 0;
	struct file *exec_file = NULL;
	struct mm_struct *mm ;
	struct vm_area_struct *vma = NULL;
	int file_offset=0;
	struct task_struct *tsk = current;

	mm = get_task_mm(tsk);
	if (!mm)
		return -1;
	exec_file = get_mm_exe_file(mm);
	if (!exec_file) {
		mmput(mm);
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_mm_exe_file error!\n", __func__);
		return -1;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	down_read(&mm->mmap_lock);
#else
	down_read(&mm->mmap_sem);
#endif
	if (!mm->mmap) {
		DEBUG_MSG(HTTC_TSB_INFO, "mm->mmap is null\n");
		ret = -1;
		goto out;
	}
	vma = mm->mmap;

	for (; vma; vma = vma->vm_next) {

		if (!vma->vm_file)
			continue;

		if (!(vma->vm_flags & VM_EXEC)) {
			file_offset = vma->vm_end - vma->vm_start;
			DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], sub_name[%s] have special section, len[%d]\n", __func__, sec_d->sub_name, file_offset);
		}

		if ((vma->vm_flags & VM_EXEC) && !(vma->vm_flags & VM_WRITE)) {

			len = vma->vm_end - vma->vm_start;

			//DEBUG_MSG(HTTC_TSB_INFO, "sec_d->sub_name[%s] vm_start[%08lx] vm_end[%08lx], len[%d], vm_flags[%lx]\n", sec_d->sub_name, vma->vm_start, vma->vm_end, len, vma->vm_flags);

			ret = task_cal_mem_file_hash(sec_d->sub_name, tsk, mm, vma->vm_start, len, file_offset, hash, is_file_open);
			if (ret || memcmp(sec_d->sub_hash, hash, LEN_HASH)) {
				DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], current process[%s] ret[%d] measure_process error!\n", __func__, sec_d->sub_name, ret);
				ret = -1;
				goto out;
			}

			//不需要验证动态库
			break;
		}
	}

	ret = 0;
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], current process[%s] measure_process success!\n", __func__, sec_d->sub_name);
out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	up_read(&mm->mmap_lock);
#else
	up_read(&mm->mmap_sem);
#endif
	fput(exec_file);
	mmput(mm);

	return ret;
}

int is_special_kernel_version(void)
{
	//以下项目内存计算hash与文件采集hash不一致，走特殊流程
	//CONFIG_CSKY：奔图2700项目    CONFIG_PAGE_SIZE_16KB：南瑞3310项目、傲拓项目
#if defined(CONFIG_CSKY) || defined(CONFIG_PAGE_SIZE_16KB)
	return 1;
#endif
	//if (strcmp(CONFIG_DEFAULT_HOSTNAME, "NARI")==0) {
	//	//南瑞3310项目，文件hash与内存计算hash不一致
	//	return 1;
	//}

	return 0;
}

int query_dac_policy_state(struct mac_policy *p_mac_item, struct sec_domain *sec_d, int is_file_open)
{
	struct list_head *pos = NULL;
	struct dac_policy *p_dac_item = NULL;
	int ret = -1, ret_measure = 0;

	list_for_each(pos, &p_mac_item->list_dac)
	{
		p_dac_item = list_entry(pos, struct dac_policy, list);

		if (memcmp(p_dac_item->process_hash, sec_d->sub_hash, LEN_HASH))
			continue;

		if(p_dac_item->privi_type==PRIVI_ALL)
			ret = 0;
		else if(p_dac_item->privi_type==PRIVI_READ_ONLY)
			ret = CONTROL_WRITE;
		break;
	}

	if(ret>=0) {
		if (p_mac_item->measure_flags & FILE_PROTECT_MEASURE_ENV) {
			// 环境度量
			ret_measure = tsb_measure_kernel_memory_all();
			if (ret_measure) {
				DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], current process[%s] measure_env tsb_measure_kernel_memory_all ret_measure[%d] error!\n", __func__, sec_d->sub_name, ret_measure);
				ret = -1;
				goto out;
			}
			DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], current process[%s] measure_env success!\n", __func__, sec_d->sub_name);
		}

		if ((p_mac_item->measure_flags & FILE_PROTECT_MEASURE_PROCESS)) {
			// 进程度量
			ret_measure = measure_process(sec_d, is_file_open);
			if (ret_measure < 0)
				ret = -1;
		}
	}

out:
	return ret;
}

static int mac_wildcard_cmp(struct mac_policy *p_mac_item, char *obj_name, int type)
{
	int len = 0;
	//ordinary
	if (type == ORDINARY) {
		return memcmp(p_mac_item->obj_name, obj_name, strlen(p_mac_item->obj_name));
	}
	//wildcard
	if (type == WILDCARD) {
	   regexp * comppattern = regcomp(p_mac_item->obj_name, &len);
		if (comppattern) {
			int ret = regexec(comppattern, obj_name);
			if (ret != 0) {
				DEBUG_MSG(HTTC_TSB_INFO, "Mac find %d %s %s\n", ret, p_mac_item->obj_name, obj_name);
				kfree(comppattern);
				return 0;
			}
			kfree(comppattern);
			return -1;
		}
		return -1;
	}
	return -1;
}

int query_fac_policy_state(struct sec_domain *sec_d, int is_file_open)
{
	struct list_head *pos = NULL;
	struct mac_policy *p_mac_item = NULL;
	int ret = 0;
	unsigned char hash[LEN_HASH] = {0};
	
	read_lock(&policy_fac_lock);
	list_for_each(pos, &g_list_policy_fac)
	{
		p_mac_item = list_entry(pos, struct mac_policy, list);

		if(mac_wildcard_cmp(p_mac_item, sec_d->obj_name, WILDCARD) == 0)
		{
			read_unlock(&policy_fac_lock);      //奔图2700项目，需要在calc_sub_hash之前释放读锁，否则会死机
			//计算主体hash
			ret = calc_sub_hash(sec_d->sub_name, hash, is_file_open);
			if(ret<0)
			{
				DEBUG_MSG(HTTC_TSB_INFO, "[%s], calc_sub_hash err pass!\n", __func__);
				ret = 0;
				goto out;
			}
			memcpy(sec_d->sub_hash, hash, LEN_HASH);

			if (p_mac_item->privileged_process_num > 0)
			{
				ret = query_dac_policy_state(p_mac_item, sec_d, is_file_open);
				if(ret>=0)
					goto out;
			}
			
			if(p_mac_item->type == FILE_READ_PROTECT)
				ret = CONTROL_READ;
			else
				ret = CONTROL_WRITE;
			goto out;
		}
	}
	read_unlock(&policy_fac_lock);

out:
	return ret;
}

int query_dir_segment_fac_policy_state(struct sec_domain *sec_d, int is_file_open)
{
	struct list_head *pos = NULL;
	struct mac_policy *p_mac_item = NULL;
	int ret = 0;
	unsigned char hash[LEN_HASH] = {0};
	char obj_name[LEN_NAME_MAX] = {0};

	memcpy(obj_name, sec_d->obj_name, sec_d->obj_len);
	if (sec_d->obj_len < LEN_NAME_MAX)
		obj_name[sec_d->obj_len] = '/';

	read_lock(&policy_fac_lock);
	list_for_each(pos, &g_list_policy_fac)
	{
		p_mac_item = list_entry(pos, struct mac_policy, list);

		//if(mac_wildcard_cmp(p_mac_item, sec_d->obj_name, WILDCARD) == 0)
		if(strncmp(p_mac_item->obj_name+1, obj_name, strlen(obj_name)) == 0)
		{
			//计算主体hash
			ret = calc_sub_hash(sec_d->sub_name, hash, is_file_open);
			if(ret<0)
			{
				DEBUG_MSG(HTTC_TSB_INFO, "[%s], calc_sub_hash err pass!\n", __func__);
				ret = 0;
				break;
			}
			memcpy(sec_d->sub_hash, hash, LEN_HASH);

			if (p_mac_item->privileged_process_num > 0)
			{
				ret = query_dac_policy_state(p_mac_item, sec_d, is_file_open);
				if(ret>=0)
					break;
			}

			if(p_mac_item->type == FILE_READ_PROTECT)
				ret = CONTROL_READ;
			else
				ret = CONTROL_WRITE;
			break;
		}
	}
	read_unlock(&policy_fac_lock);

	return ret;
}

int is_exist_mac_policy(char* obj_name)
{
	struct list_head *pos = NULL;
	struct mac_policy *p_mac_item = NULL;

	list_for_each(pos, &g_list_policy_fac) {
		p_mac_item = list_entry(pos, struct mac_policy, list);

		if(strcmp(p_mac_item->obj_name, obj_name) == 0)
			return 1;
	}

	return 0;
}

//return 0 means empty
int is_empty_mac_policy(void)
{
	int ret = -1;

	if(list_empty(&g_list_policy_fac) == 0){
		ret = 0;
	}

	return ret;
}

static int load_fac_policy(void)
{
	int ret = -1;
	char *buff=NULL, *p=NULL;
	struct file *file;
	char file_path[128] = {0};
	loff_t offset = 0;
	int i=0, read_len=0, i_size=0;
	struct mac_policy *p_mac_item=NULL;
	struct file_protect_item *p_mac=NULL;
	struct dac_policy *p_dac_item=NULL;
	struct file_protect_privileged_process *p_dac=NULL;

	snprintf(file_path, 128, "%s%s", BASE_PATH, "conf/file_protect.data");
	file = filp_open(file_path, O_RDONLY, 0);
	if (IS_ERR(file))
	{
		DEBUG_MSG(HTTC_TSB_INFO, "file_protect file open error!\n");
		return ret;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	i_size = i_size_read(file->f_inode);
#else
	i_size = i_size_read(file->f_path.dentry->d_inode);
#endif

	if (!(buff = vmalloc(i_size)))
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc error!\n",__func__);
		ret = -ENOMEM;
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	read_len = kernel_read(file, buff, i_size, &offset);
#else
	read_len = kernel_read(file, offset, buff, i_size);
#endif
	if (read_len != i_size)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kernel_read error!\n",__func__);
		ret = -ENOMEM;
		goto out;
	}
	p = buff;
	p += 8;

	write_lock(&policy_fac_lock);
	while ((p-buff) < read_len)
	{
		p_mac = (struct file_protect_item*)p;

		if(is_exist_mac_policy(p_mac->path)) {
			DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], fac policy[%s] is existed, invalid operation!\n",__func__, p_mac->path);
			p += sizeof(struct file_protect_item);
			p += (NTOHS(p_mac->be_privileged_process_num)*sizeof(struct file_protect_privileged_process));
			continue;
		}

		p_mac_item = kzalloc(sizeof(struct mac_policy), GFP_KERNEL);
		INIT_LIST_HEAD(&p_mac_item->list);
		INIT_LIST_HEAD(&p_mac_item->list_dac);

		p_mac_item->measure_flags = p_mac->measure_flags;
		p_mac_item->type = p_mac->type;
		memcpy(p_mac_item->obj_name, p_mac->path, sizeof(p_mac_item->obj_name));
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], add mac[%s] type[%d] measure_flags[%d] success\n", __func__, p_mac_item->obj_name, p_mac_item->type, p_mac_item->measure_flags);

		p += sizeof(struct file_protect_item);
		p_mac_item->privileged_process_num = NTOHS(p_mac->be_privileged_process_num);
		for (i=0; i<p_mac_item->privileged_process_num; i++)
		{
			p_dac = (struct file_protect_privileged_process*)p;

			p_dac_item = kzalloc(sizeof(struct dac_policy), GFP_KERNEL);
			INIT_LIST_HEAD(&p_dac_item->list);
			p_dac_item->privi_type = NTOHL(p_dac->be_privi_type);
			memcpy(p_dac_item->process_hash, p_dac->hash, LEN_HASH);
			memcpy(p_dac_item->sub_name, p_dac->path, sizeof(p_dac_item->sub_name));
			list_add_tail(&p_dac_item->list, &p_mac_item->list_dac);
			DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], add dac[%s] privi_type[%d] success\n", __func__, p_dac_item->sub_name, p_dac_item->privi_type);

			p += sizeof(struct file_protect_privileged_process);
		}
		
		list_add_tail(&p_mac_item->list, &g_list_policy_fac);
	}
	write_unlock(&policy_fac_lock);
	ret = 0;

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], add fac policy success\n", __func__);
out:	
	if(file != NULL)
		filp_close(file, NULL);
	if(buff)
		vfree(buff);

	return ret;
}

static void clean_list_fac(void)
{
	struct list_head *pos_mac = NULL, *tmp_mac = NULL;
	struct list_head *pos_dac = NULL, *tmp_dac = NULL;
	struct mac_policy *p_mac_item = NULL;
	struct dac_policy *p_dac_item = NULL;

	write_lock(&policy_fac_lock);
	list_for_each_safe(pos_mac, tmp_mac, &g_list_policy_fac)
	{
		p_mac_item = list_entry(pos_mac, struct mac_policy, list);

		list_for_each_safe(pos_dac, tmp_dac, &p_mac_item->list_dac)
		{
			p_dac_item = list_entry(pos_dac, struct dac_policy, list);

			if(pos_dac != NULL)
				list_del(pos_dac);

			if(p_dac_item != NULL)
				kfree(p_dac_item);
		}

		if(pos_mac != NULL)
			list_del(pos_mac);

		if(p_mac_item != NULL)
			kfree(p_mac_item);
	}
	write_unlock(&policy_fac_lock);

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], fac policy clean success\n", __func__);
}

long ioctl_reload_file_protect_policy(unsigned long param)
{
	clean_list_fac();
	//policy_fac_cache_clean();
	load_fac_policy();
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], reload mac success\n", __func__);

	return 0;
}

void list_fac_init(void)
{
	rwlock_init(&policy_fac_lock);

	load_fac_policy();

	if (httcsec_io_command_register(COMMAND_RELOAD_FILE_PROTECT_POLICY, (httcsec_io_command_func)ioctl_reload_file_protect_policy)) 
	{
	    DEBUG_MSG(HTTC_TSB_INFO, "Command NR duplicated %d.\n", COMMAND_RELOAD_FILE_PROTECT_POLICY);
	}

	//DEBUG_MSG(HTTC_TSB_INFO, "mac(file access control) list init success!\n");
}

void list_fac_exit(void)
{
	httcsec_io_command_unregister(COMMAND_RELOAD_FILE_PROTECT_POLICY, (httcsec_io_command_func)ioctl_reload_file_protect_policy);
	clean_list_fac();
}
