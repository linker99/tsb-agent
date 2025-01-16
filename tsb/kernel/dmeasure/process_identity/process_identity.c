#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#else
#include <linux/sched.h>
#endif
#include <linux/jhash.h>

#include "process_identity.h"
#include "tpcm/tpcmif.h"
#include "utils/debug.h"
#include "common.h"
#include "tpcm_def.h"
#include "msg/command.h"
#include "utils/vfs.h"
#include "utils/klib_fileio.h"
//#include "policy/global_policy.h"
#include "policy/feature_configure.h"
#include "../encryption/sm3/sm3.h"
#include "../../smeasure/policy/hash_whitelist.h"
#include "tsbapi/tsb_measure_kernel.h"
#include "../utils/traceability.h"

#define IDS_HASH_TAB_SIZE	256
//#define IDS_HASH_TAB_MASK	(IDS_HASH_TAB_SIZE-1)
static struct hlist_head process_identity_hashtable[IDS_HASH_TAB_SIZE];
//static unsigned int ids_hash_random;
static DEFINE_MUTEX(ids_hashtable_mutex);

struct ids_hash_cache
{
	struct hlist_node list;
	unsigned char process_name[256];
	int ret;
	unsigned char hash[LEN_HASH];
	//char path[512];
	pid_t pid;
	struct task_struct *task;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	ktime_t time;
#else
	time_t time;
#endif
};
//static struct task_struct *clear_timeout_ids_cache_task;

struct process_role_user{
	int member_number;
	unsigned char *name;
	unsigned char **members;
};
struct process_identity_user{
	unsigned char *name;
	int specific_libs;
	int hash_length;
	int lib_number;
	unsigned char *hash;
};

struct policy_process_identity{
	struct list_head list;
	struct process_identity_user item;
};
struct policy_process_role{
	struct list_head list;
	struct process_role_user item;
};

LIST_HEAD(g_list_policy_process_identity);
LIST_HEAD(g_list_policy_process_role);
rwlock_t policy_process_identity_lock;
rwlock_t policy_process_role_lock;

struct process_identity_feature_conf {
	//uint32_t is_enabled;
	uint32_t process_verify_lib_mode;
};
static struct process_identity_feature_conf process_identity_feature;

int is_special_kernel_version(void)
{
	//以下项目内存计算hash与文件采集hash不一致，通过文件计算hash
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


int check_policy_process_ids_repeat(char *hash, int lenth)
{
	struct list_head *pos = NULL;
	struct policy_process_identity *p_policy_process_identity = NULL;

	list_for_each(pos, &g_list_policy_process_identity)
	{
		p_policy_process_identity = list_entry(pos, struct policy_process_identity, list);
		if (memcmp(p_policy_process_identity->item.hash, hash, lenth) == 0)
			return -1;
	}

	return 0;
}

//策略
int parse_policy_process_ids(char *p, int length)
{
	struct process_identity *p_item;

	p_item = (struct process_identity *)p;
	while(length>0)
	{
		int item_len = 0, hash_len = 0;
		struct policy_process_identity *p_policy_process_identity_item = NULL;

		//转换字节序
		p_item->be_hash_length = NTOHS(p_item->be_hash_length);
		p_item->be_lib_number = NTOHS(p_item->be_lib_number);

		if (check_policy_process_ids_repeat(p_item->data, p_item->be_hash_length))
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], process_ids policy have repeated!\n", __func__);
		}

		hash_len = p_item->be_hash_length*(p_item->be_lib_number+1);

		p_policy_process_identity_item = kzalloc(sizeof(struct policy_process_identity), GFP_KERNEL);
		if (!p_policy_process_identity_item)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc error!\n", __func__);
			return -1;
		}
		p_policy_process_identity_item->item.name = kzalloc(p_item->name_length + 1, GFP_KERNEL);  //加1，为了防止名字字符串长度没有包含"\0"
		if (!p_policy_process_identity_item->item.name)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc error!\n", __func__);
			return -1;
		}
		p_policy_process_identity_item->item.hash = kzalloc(hash_len, GFP_KERNEL);
		if (!p_policy_process_identity_item->item.hash)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc error!\n", __func__);
			return -1;
		}

		INIT_LIST_HEAD(&p_policy_process_identity_item->list);
		p_policy_process_identity_item->item.specific_libs = p_item->specific_libs;
		p_policy_process_identity_item->item.hash_length = p_item->be_hash_length;
		p_policy_process_identity_item->item.lib_number = p_item->be_lib_number;
		memcpy(p_policy_process_identity_item->item.hash, p_item->data, hash_len);
		memcpy(p_policy_process_identity_item->item.name, p_item->data+hash_len, p_item->name_length);

		list_add(&p_policy_process_identity_item->list, &g_list_policy_process_identity);
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], g_list_policy_process_identity add process_ids policy name[%s] success\n", __func__, p_policy_process_identity_item->item.name);

		item_len = sizeof(struct process_identity) + p_item->name_length + hash_len;
		BYTE4_ALIGNMENT(item_len);  //处理4字节对齐的问题
		p_item = (struct process_identity *)((char*)p_item + item_len);
		length -= item_len;
	}

	if (length!=0)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], length[%d] error!\n", __func__, length);
	}
	//print_policy_process_ids();

	return 0;
}

int policy_tcs_get_process_ids(void)
{
	struct process_identity *p=NULL;
	int item_count=0, length=0, ret=0;

	ret = get_process_ids(&p, &item_count, &length);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], tcsk_get_process_ids ret[%x] error!\n", __func__, ret);
		return -1;
	}

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], get_process_ids ret[%x] item_count[%d] length[%d]\n", __func__, ret, item_count, length);

	parse_policy_process_ids((char *)p, length);

	vfree(p);

	return 0;
}

int parse_policy_process_roles(char *p, int length)
{
	struct process_role *p_item;
	int j=0;

	p_item = (struct process_role *)p;
	while(length>0)
	{
		char *p_process_role_member = NULL;
		int item_len=0;

		struct policy_process_role *p_policy_process_role_item = kzalloc(sizeof(struct policy_process_role), GFP_KERNEL);
		if (!p_policy_process_role_item)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc policy_process_role error!\n", __func__);
			return -1;
		}

		//转换字节序
		p_item->be_name_length = NTOHL(p_item->be_name_length);
		p_item->be_members_length = NTOHL(p_item->be_members_length);
		p_item->be_members_number = NTOHL(p_item->be_members_number);

		p_policy_process_role_item->item.name = kzalloc(p_item->be_name_length + 1, GFP_KERNEL);  //加1，为了防止名字字符串长度没有包含"\0"
		if (!p_policy_process_role_item->item.name)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc be_name_length error!\n", __func__);
			return -1;
		}
		memcpy(p_policy_process_role_item->item.name, p_item->members, p_item->be_name_length);

		p_policy_process_role_item->item.members = kzalloc(sizeof(char *) * p_item->be_members_number, GFP_KERNEL);
		if (!p_policy_process_role_item->item.members)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc be_members_number[%d] error!\n", __func__, p_item->be_members_number);
			return -1;
		}

		p_process_role_member = p_item->members + p_item->be_name_length;
		for (j=0; j<p_item->be_members_number; j++)
		{
			char *role_member_name;
			struct role_member *p_role_member = (struct role_member *)p_process_role_member;

			role_member_name = kzalloc(p_role_member->length+1, GFP_KERNEL);
			if (!role_member_name)
			{
				DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc role_member name error!\n", __func__);
				return -1;
			}
			memcpy(role_member_name, p_role_member->name, p_role_member->length);
			p_policy_process_role_item->item.members[j] = role_member_name;
			DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], g_list_policy_process_role add process_role policy role_member_name[%s]\n", __func__, p_policy_process_role_item->item.members[j]);

			p_process_role_member = p_process_role_member + sizeof(struct role_member) + p_role_member->length;
		}

		p_policy_process_role_item->item.member_number = p_item->be_members_number;
		INIT_LIST_HEAD(&p_policy_process_role_item->list);

		list_add(&p_policy_process_role_item->list, &g_list_policy_process_role);
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], g_list_policy_process_role add process_role policy name[%s] success\n", __func__, p_policy_process_role_item->item.name);

		item_len = sizeof(struct process_role) + p_item->be_name_length + p_item->be_members_length;
		BYTE4_ALIGNMENT(item_len);  //处理4字节对齐的问题
		p_item = (struct process_role *)((char*)p_item + item_len);
		length -= item_len;
	}

	if (length!=0)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], length[%d] error!\n", __func__, length);
	}

	return 0;
}

int policy_tcs_get_process_roles(void)
{
	struct process_role *p=NULL;
	int item_count=0, length=0, ret=0;

	ret = get_process_roles(&p, &item_count, &length);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], tcsk_get_process_roles ret[%x] error!\n", __func__, ret);
		return -1;
	}

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], get_process_roles ret[%x] item_count[%d] length[%d]\n", __func__, ret, item_count, length);

	parse_policy_process_roles((char *)p, length);

	vfree(p);

	return 0;
}

void clean_policy_list_process_ids(void)
{
	struct list_head *pos = NULL, *tmp = NULL;
	struct policy_process_identity *p_policy_process_identity = NULL;

	list_for_each_safe(pos, tmp, &g_list_policy_process_identity)
	{
		p_policy_process_identity = list_entry(pos, struct policy_process_identity, list);

		list_del(pos);
		kfree(p_policy_process_identity->item.name);
		kfree(p_policy_process_identity->item.hash);
		kfree(p_policy_process_identity);
	}

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], process_ids policy clean success\n", __func__);
}

long ioctl_process_ids_set_policy(unsigned long param)
{

	struct tsb_general_policy general_policy;
	char *p_buff = NULL;
	int ret = 0;

	ret =copy_from_user(&general_policy, (void *)param, sizeof(general_policy));
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user process_ids policy error! ret[%d]\n", __func__, ret);
		return -1;
	}
	if (!general_policy.length)
	{
		write_lock(&policy_process_identity_lock);
		clean_policy_list_process_ids();
		write_unlock(&policy_process_identity_lock);
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], policy length is 0, clean process_ids policy success\n", __func__);
		return 0;
	}
	

	p_buff = vmalloc(general_policy.length);
	if (!p_buff)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc error! process_ids policy length[%d]\n", __func__, general_policy.length);
		return -1;
	}

	ret =copy_from_user(p_buff, general_policy.data, general_policy.length);
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user dmeasure update policy failed!\n", __func__);
		vfree(p_buff);
		return -1;
	}
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], process_ids_set_policy length[%d]\n", __func__, general_policy.length);

	write_lock(&policy_process_identity_lock);
	clean_policy_list_process_ids();
	parse_policy_process_ids(p_buff, general_policy.length);
	write_unlock(&policy_process_identity_lock);

	vfree(p_buff);

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], process_ids_set_policy success\n", __func__);

	return 0;
}

long ioctl_process_ids_reload_policy(unsigned long param)
{
	write_lock(&policy_process_identity_lock);
	clean_policy_list_process_ids();
	policy_tcs_get_process_ids();
	write_unlock(&policy_process_identity_lock);

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], process_ids_reload_policy success\n", __func__);

	return 0;
}

void clean_policy_list_process_roles(void)
{
	struct list_head *pos = NULL, *tmp = NULL;
	struct policy_process_role *p_policy_process_role = NULL;
	int i=0;

	list_for_each_safe(pos, tmp, &g_list_policy_process_role)
	{
		p_policy_process_role = list_entry(pos, struct policy_process_role, list);

		list_del(pos);

		kfree(p_policy_process_role->item.name);
		for (i=0; i<p_policy_process_role->item.member_number; i++)
			kfree(p_policy_process_role->item.members[i]);
		kfree(p_policy_process_role->item.members);

		kfree(p_policy_process_role);
	}

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], process_roles policy clean success\n", __func__);
}

long ioctl_process_roles_set_policy(unsigned long param)
{
	struct tsb_general_policy general_policy;
	char *p_buff = NULL;
	int ret = 0;

	ret =copy_from_user(&general_policy, (void *)param, sizeof(general_policy));
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user process_roles policy error! ret[%d]\n", __func__, ret);
		return -1;
	}
	if (!general_policy.length)
	{
		write_lock(&policy_process_role_lock);
		clean_policy_list_process_roles();
		write_unlock(&policy_process_role_lock);
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], policy length is 0, clean process_roles policy success\n", __func__);
		return 0;
	}

	p_buff = vmalloc(general_policy.length);
	if (!p_buff)
	{
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], vmalloc error! process_roles policy length[%d]\n", __func__, general_policy.length);
		return -1;
	}

	ret =copy_from_user(p_buff, general_policy.data, general_policy.length);
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user dmeasure update policy failed!\n", __func__);
		vfree(p_buff);
		return -1;
	}
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], process_roles_set_policy length[%d]\n", __func__, general_policy.length);

	write_lock(&policy_process_role_lock);
	clean_policy_list_process_roles();
	parse_policy_process_roles(p_buff, general_policy.length);
	write_unlock(&policy_process_role_lock);

	vfree(p_buff);

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], process_roles_set_policy success\n", __func__);

	return 0;
}

long ioctl_process_roles_reload_policy(unsigned long param)
{
	write_lock(&policy_process_role_lock);
	clean_policy_list_process_roles();
	policy_tcs_get_process_roles();
	write_unlock(&policy_process_role_lock);

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], process_roles_reload_policy success\n", __func__);

	//char buf[256]={0};
	//int len;
	//get_process_identity(buf, &len);

	return 0;
}

long ioctl_process_identity_user_interface(unsigned long param)
{
	struct tsb_user_interface_parameter parameter;
	char *p_buff = NULL, *p_process_name=NULL;
	int ret = 0;
	int pid=0;
	int process_name_length = 0;

	ret =copy_from_user(&parameter, (void *)param, sizeof(parameter));
	if (ret || !parameter.length) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user user interface data error! ret[%d] length[%d]\n", __func__, ret, parameter.length);
		return -1;
	}

	p_buff = vmalloc(parameter.length);
	if (!p_buff)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc error! user interface data length[%d]\n", __func__, parameter.length);
		return -1;
	}

	ret =copy_from_user(p_buff, parameter.data, parameter.length);
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user user interface data failed!\n", __func__);
		vfree(p_buff);
		return -1;
	}
	
	switch (parameter.type) {
	case TYPE_PROCESS_IDENTITY_VERIFY:

	      
		pid = *(int *)p_buff;
		p_process_name = p_buff+sizeof(int);

		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], parameter.type[%d] copy_from_user user interface pid[%d] p_process_name[%s]\n", __func__, parameter.type, pid, p_process_name);
		ret = tsb_verify_process(pid, p_process_name);
		break;
	case TYPE_PROCESS_IDENTITY_GET:
	{
		char process_name[256] = { 0 };
		ret = get_process_identity(process_name, &process_name_length);
		if(ret)
		{
			ret = TSB_MEASURE_FAILE;
		}
		else
		{
			int copy_ret_length;
			//注意：返回值为0，才能将数据拷贝到用户空间
			int copy_ret_data =copy_to_user((void *)parameter.data, process_name, strlen(process_name)+1);
			DEBUG_MSG(HTTC_TSB_DEBUG,"copy_data_len %d\n",copy_ret_data);
			copy_ret_length = copy_to_user(&parameter.length, &process_name_length, sizeof(process_name_length));
			DEBUG_MSG(HTTC_TSB_DEBUG,"copy_len %d\n",copy_ret_length);
		}

		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], parameter.type[%d] copy_to_user user process_name[%s] ret[%d]\n", __func__, parameter.type, process_name, ret);
	}
		break;
	case TYPE_PROCESS_IDENTITY_ROLE:   //进程角色判断，1为成功  0为失败
		p_process_name = p_buff;
		ret = is_role_member(p_process_name);
		//if(!ret)
		//	ret = TSB_MEASURE_FAILE;

		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], parameter.type[%d] copy_from_user user p_process_name[%s] ret[%d]\n", __func__, parameter.type, p_process_name, ret);
		break;
	default:
		ret = TSB_MEASURE_FAILE;
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], parameter.type[%d] error!\n", __func__, parameter.type);
		break;
	}

	vfree(p_buff);
	return ret;
}

//#ifdef CONFIG_CSKY
int task_cal_file_hash(char *fullpath, unsigned char *hash)
{
	int ret = 0;
	struct file *fp;

	fp = filp_open(fullpath, O_RDONLY, 0);
	if (IS_ERR(fp) || !fp) {
		DEBUG_MSG(HTTC_TSB_INFO, "filp_open [%s] error! error code[%ld]!\n", fullpath, PTR_ERR(fp));
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
//#else
int task_cal_mem_file_hash(char *fullpath, struct task_struct *task, struct mm_struct *mm, unsigned long from, int length, int file_offset, unsigned char *hash)
{
	int ret = 0;
	int i = 0;
	int plen = 0;
	int npages = 0;
	//u32 crc = 0;
	unsigned int off = 0;
	unsigned char *maddr = NULL;
	struct page **pages = NULL;
	//unsigned char digest[LEN_HASH] = {0};
	sm3_context ctx;
	struct file *file;
	unsigned char *buff = NULL;
	int read_len = 0;
	//int text_len = length;
	loff_t offset = 0;

	file = filp_open(fullpath, O_RDONLY, 0);
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
	// ret =get_user_pages_remote(task, mm, from, npages, FOLL_FORCE, pages, NULL, NULL);
	//#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	// ret = get_user_pages_remote(task, mm, from, npages, FOLL_FORCE, pages, NULL);
#else
	ret = get_user_pages(current, current->mm, from, npages, 0, 0, pages, NULL);
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
//#endif

//存在返回0，不存在返回-1
int qurey_hash_from_process_identity_policy(unsigned char *exe_hash, unsigned char *lib_hash, char *process_identity_name, int len)
{
	struct list_head *pos = NULL;
	struct policy_process_identity *p_policy_process_identity = NULL;
	int i = 0;

	read_lock(&policy_process_identity_lock);
	list_for_each(pos, &g_list_policy_process_identity)
	{
		int hash_length;
		p_policy_process_identity = list_entry(pos, struct policy_process_identity, list);
		 hash_length = p_policy_process_identity->item.hash_length;

		if (memcmp(p_policy_process_identity->item.hash, exe_hash, hash_length) != 0)
			continue;

		for (i=0; i<(p_policy_process_identity->item.lib_number+1); i++)
		{
			if (memcmp(p_policy_process_identity->item.hash+i*hash_length, lib_hash, hash_length) == 0)
			{
				strncpy(process_identity_name, p_policy_process_identity->item.name, len-1);
				read_unlock(&policy_process_identity_lock);
				return 0;
			}
		}
	}

	read_unlock(&policy_process_identity_lock);
	return -1;
}

//static inline unsigned string_hash_key(const __u8 * p, int n)
//{
//	return jhash(p, n, ids_hash_random) & IDS_HASH_TAB_MASK;
//}
static inline int cal_task_hash_func(const struct task_struct *task)
{
	return ((unsigned long)task) % IDS_HASH_TAB_SIZE;
}



void remove_current_task_ids_cache(struct task_struct *tsk)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next;
#endif
	struct ids_hash_cache* p_ids_hash_cache = NULL;
	struct hlist_node *node = NULL;
	struct task_struct *task = current;
	if(tsk)
		task = tsk;

	mutex_lock(&ids_hashtable_mutex);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	//struct hlist_node *next;
	hlist_for_each_entry_safe(p_ids_hash_cache, node, next, process_identity_hashtable + cal_task_hash_func(task), list)
#else
	hlist_for_each_entry_safe(p_ids_hash_cache, node, process_identity_hashtable + cal_task_hash_func(task), list)
#endif
	{
		if(p_ids_hash_cache->pid == task->pid)
		{
			//printk("---------------------remove_current_task_ids_cache, comm[%s]--------------------------\n", task->comm);
			hlist_del(&p_ids_hash_cache->list);
			kfree(p_ids_hash_cache);
		}
	}
	mutex_unlock(&ids_hashtable_mutex);
}




//回调函数
int get_process_identity(unsigned char *process_name,int *process_name_length)
{
	unsigned char hash[LEN_HASH] = {0};
	unsigned char exe_hash[LEN_HASH] = {0};
	char process_identity_name[256] = {0};
	int ret = 0, i = 0, len = 0;
	struct file *exec_file = NULL;
	struct mm_struct *mm;
	char *fullpath = NULL;
	char *fullpath_prev = NULL;
	int vma_idx=0, file_offset = 0;
	struct vm_area_struct *vma = NULL;

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

	fullpath_prev = kzalloc(PATH_MAX,GFP_KERNEL);

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

		vma_idx++;
		fullpath = vfs_get_fullpath((void *)vma->vm_file, TYPE_FILE);
		if (!fullpath)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], fullpath is NULL!\n", __func__);
			ret = -1;
			goto out;
		}
		if ((i==0) && (strcmp(fullpath+strlen(fullpath)-3, ".so")==0)) {
			DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], the first vm_area_struct fullpath[%s] is so\n", __func__, fullpath);
			vfs_put_fullpath(fullpath);
			continue;
		}

		if (strcmp(fullpath_prev, fullpath)!=0) {
			vma_idx=1;
			file_offset = 0;
			strcpy(fullpath_prev, fullpath);
		}

		if (vma_idx==1 && !(vma->vm_flags & VM_EXEC)) {
			file_offset = vma->vm_end - vma->vm_start;
			DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], fullpath[%s] have special section, len[%d]\n", __func__, fullpath, file_offset);
		}

		if ((vma->vm_flags & VM_EXEC) && !(vma->vm_flags & VM_WRITE)) {

			i++;
//			if (i==1)
//			{
//				mutex_lock(&ids_hashtable_mutex);
//				p_ids_hash_cache = query_ids_cache(tsk);
//				if (p_ids_hash_cache)
//				{
//					if (!p_ids_hash_cache->ret)
//					{
//						*process_name_length = strlen(p_ids_hash_cache->process_name)+1;
//						memcpy(process_name, p_ids_hash_cache->process_name, *process_name_length);
//					}
//					ret = p_ids_hash_cache->ret;
//					mutex_unlock(&ids_hashtable_mutex);
//
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
//					up_read(&mm->mmap_lock);
//#else
//					up_read(&mm->mmap_sem);
//#endif
//					fput(exec_file);
//					mmput(mm);
//					kfree(fullpath_prev);
//
//					return ret;
//				}
//				mutex_unlock(&ids_hashtable_mutex);
//			}

			len = vma->vm_end - vma->vm_start;
			DEBUG_MSG(HTTC_TSB_DEBUG, "fullpath[%s] vm_start[%08lx] vm_end[%08lx], len[%d], vm_flags[%lx]\n", fullpath, vma->vm_start, vma->vm_end, len, vma->vm_flags);

			if (is_special_kernel_version())
				ret = task_cal_file_hash(fullpath, hash);
			else
				ret = task_cal_mem_file_hash(fullpath, tsk, mm, vma->vm_start, len, file_offset, hash);
			if (ret)
			{
				DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], fullpath[%s] text section calc hash error!\n", __func__, fullpath);
				vfs_put_fullpath(fullpath);
				ret = -1;
				goto out;
			}
			//保存主程序hash
			if(i==1)
				memcpy(exe_hash, hash, LEN_HASH);
			print_hex(fullpath, hash, LEN_HASH);

			if (i>1 && process_identity_feature.process_verify_lib_mode==PROCESS_VERIFY_MODE_REF_LIB)
			{
				DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], current process_identity hash use whitelist policy, process_verify_lib_mode[%d]\n", __func__, process_identity_feature.process_verify_lib_mode);
				ret = query_process_identity_lib_hash(hash, LEN_HASH);
				if (ret)
				{
					DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], current lib hash donot exist in whitelist policy, return -1\n", __func__);
					ret = -1;
					vfs_put_fullpath(fullpath);
					goto out;
				}
				vfs_put_fullpath(fullpath);
				continue;
			}
			
			memset(process_identity_name, 0, sizeof(process_identity_name));
			ret = qurey_hash_from_process_identity_policy(exe_hash, hash, process_identity_name, 256);
			if (ret)
			{
				DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], current process hash or lib hash donot exist in process_identity_policy, return -1\n", __func__);
				ret = -1;
				vfs_put_fullpath(fullpath);
				goto out;
			}

			//不需要验证动态库
			if (process_identity_feature.process_verify_lib_mode == PROCESS_VERIFY_MODE_NO_LIB) 
			{
				vfs_put_fullpath(fullpath);
				break;
			}
		}
		vfs_put_fullpath(fullpath);
	}

	*process_name_length = strlen(process_identity_name)+1;
	memcpy(process_name, process_identity_name, *process_name_length);
	ret = 0;
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], current process lib hash exist in process_identity_policy, process_identity_name[%s]\n", __func__, process_name);
out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	up_read(&mm->mmap_lock);
#else
	up_read(&mm->mmap_sem);
#endif
	fput(exec_file);
	mmput(mm);
	kfree(fullpath_prev);

//	//将身份认证结果添加到缓存中
//	p_ids_hash_cache = kzalloc(sizeof(struct ids_hash_cache), GFP_KERNEL);
//	memcpy(p_ids_hash_cache->hash, exe_hash, LEN_HASH);
//	if(!ret)
//		strncpy(p_ids_hash_cache->process_name, process_identity_name, sizeof(p_ids_hash_cache->process_name)-1);
//	p_ids_hash_cache->ret = ret;
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
//	ktime_get_real_ts64(&ts);
//#else
//	do_gettimeofday(&ts);
//#endif
//	p_ids_hash_cache->time = ts.tv_sec;
//	p_ids_hash_cache->task = tsk;
//	p_ids_hash_cache->pid = tsk->pid;
//
//	index = cal_task_hash_func(tsk);
//	mutex_lock(&ids_hashtable_mutex);
//	hlist_add_head(&p_ids_hash_cache->list, process_identity_hashtable + index);
//	mutex_unlock(&ids_hashtable_mutex);

	return ret;
}

int is_role_member(const unsigned char *role_name)
{
	int ret = 0, i = 0;
	char process_name[256] = {0};
	int process_name_length = 0;
	struct list_head *pos = NULL;
	struct policy_process_role *p_policy_process_role = NULL;

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], is_role_member role_name[%s]\n", __func__, role_name);

	ret = get_process_identity(process_name, &process_name_length);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], role_name[%s], current process donot exist in process_identity_policy\n", __func__, role_name);
		return 0;
	}

	read_lock(&policy_process_role_lock);
	list_for_each(pos, &g_list_policy_process_role)
	{
		p_policy_process_role = list_entry(pos, struct policy_process_role, list);
		if (strcmp(p_policy_process_role->item.name, role_name) == 0)
		{
			for (i=0; i<p_policy_process_role->item.member_number; i++)
			{
				if(strcmp(p_policy_process_role->item.members[i], process_name) == 0)
				{
					read_unlock(&policy_process_role_lock);
					DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], current process process_identity_name[%s] exist in role_name[%s]\n", __func__, process_name, role_name);
					return 1;
				}
			}
		}
	}
	read_unlock(&policy_process_role_lock);

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], current process process_identity_name[%s] donot exist in role_name[%s]\n", __func__, process_name, role_name);
	return 0;
}

static struct process_identity_callback process_identity_function = {
	.get_process_identity = get_process_identity,
	.is_role_member = is_role_member,
};

void clean_policy_list(void)
{
	struct list_head *pos = NULL, *tmp = NULL;
	struct policy_process_identity *p_policy_process_identity = NULL;
	struct policy_process_role *p_policy_process_role = NULL;
	int i=0;

	list_for_each_safe(pos, tmp, &g_list_policy_process_identity)
	{
		p_policy_process_identity = list_entry(pos, struct policy_process_identity, list);

		list_del(pos);
		kfree(p_policy_process_identity->item.name);
		kfree(p_policy_process_identity->item.hash);
		kfree(p_policy_process_identity);
	}

	pos = NULL, tmp = NULL;
	list_for_each_safe(pos, tmp, &g_list_policy_process_role)
	{
		p_policy_process_role = list_entry(pos, struct policy_process_role, list);

		list_del(pos);

		kfree(p_policy_process_role->item.name);
		for (i=0; i<p_policy_process_role->item.member_number; i++)
			kfree(p_policy_process_role->item.members[i]);
		kfree(p_policy_process_role->item.members);

		kfree(p_policy_process_role);
	}
}

static void update_process_identity_conf(struct global_control_policy* p_global_policy, uint32_t tpcm_feature, int valid_license)
{
	/* set process_identity context */
	if (process_identity_feature.process_verify_lib_mode != p_global_policy->be_process_verify_lib_mode)
	{
		process_identity_feature.process_verify_lib_mode = p_global_policy->be_process_verify_lib_mode;
	}
}

void process_identity_feature_conf_notify_func(void)
{
	int ret = 0;
	struct global_control_policy global_policy = {0};
	uint32_t tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);
	else
		update_process_identity_conf(&global_policy, tpcm_feature, valid_license);
}

int process_identity_init(void)
{
	int ret;
	struct global_control_policy global_policy = {0};
	uint32_t tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);
	else
		update_process_identity_conf(&global_policy, tpcm_feature, valid_license);

	ret = register_feature_conf_notify(FEATURE_PROCESS_IDENTITY, process_identity_feature_conf_notify_func);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], register_feature_conf_notify error ret[%d]!\n",__func__, ret);

	rwlock_init(&policy_process_identity_lock);
	rwlock_init(&policy_process_role_lock);

	policy_tcs_get_process_ids();
	policy_tcs_get_process_roles();

	if (httcsec_io_command_register(COMMAND_SET_PROCESS_IDS_POLICY, (httcsec_io_command_func)ioctl_process_ids_set_policy)) {
		DEBUG_MSG(HTTC_TSB_INFO, "Command NR duplicated %d.\n", COMMAND_SET_PROCESS_IDS_POLICY);
		goto process_ids_set_out;
	}
	if (httcsec_io_command_register(COMMAND_RELOAD_PROCESS_IDS_POLICY, (httcsec_io_command_func)ioctl_process_ids_reload_policy)) {
		DEBUG_MSG(HTTC_TSB_INFO, "Command NR duplicated %d.\n", COMMAND_RELOAD_PROCESS_IDS_POLICY);
		goto process_ids_reload_out;
	}
	if (httcsec_io_command_register(COMMAND_SET_PROCESS_ROLES_POLICY, (httcsec_io_command_func)ioctl_process_roles_set_policy)) {
		DEBUG_MSG(HTTC_TSB_INFO, "Command NR duplicated %d.\n", COMMAND_SET_PROCESS_ROLES_POLICY);
		goto process_roles_set_out;
	}
	if (httcsec_io_command_register(COMMAND_RELOAD_PROCESS_ROLES_POLICY, (httcsec_io_command_func)ioctl_process_roles_reload_policy)) {
		DEBUG_MSG(HTTC_TSB_INFO, "Command NR duplicated %d.\n", COMMAND_RELOAD_PROCESS_ROLES_POLICY);
		goto process_roles_reload_out;
	}
	if (httcsec_io_command_register(COMMAND_PROCESS_IDENTITY_USER_INTERFACE, (httcsec_io_command_func)ioctl_process_identity_user_interface)) {
		DEBUG_MSG(HTTC_TSB_INFO, "Command NR duplicated %d.\n", COMMAND_PROCESS_IDENTITY_USER_INTERFACE);
	}

	//get_random_bytes(&ids_hash_random, sizeof(ids_hash_random));

	ret = register_process_identity_callback(&process_identity_function);
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], register_process_identity_callback [%d] error!\n", __func__, ret);
		goto register_process_identity_callback_out;
	}



	DEBUG_MSG(HTTC_TSB_DEBUG, "process_identity_init success\n");
	ret = 0;
	goto out;

//kthread_run_out:
//	unregister_process_identity_callback(&process_identity_function);
register_process_identity_callback_out:
	httcsec_io_command_unregister(COMMAND_RELOAD_PROCESS_ROLES_POLICY, (httcsec_io_command_func)ioctl_process_roles_reload_policy);
process_roles_reload_out:
	httcsec_io_command_unregister(COMMAND_SET_PROCESS_ROLES_POLICY, (httcsec_io_command_func)ioctl_process_roles_set_policy);
process_roles_set_out:
	httcsec_io_command_unregister(COMMAND_RELOAD_PROCESS_IDS_POLICY, (httcsec_io_command_func)ioctl_process_ids_reload_policy);
process_ids_reload_out:
	httcsec_io_command_unregister(COMMAND_SET_PROCESS_IDS_POLICY, (httcsec_io_command_func)ioctl_process_ids_set_policy);
process_ids_set_out:
	clean_policy_list();
	unregister_feature_conf_notify(FEATURE_PROCESS_IDENTITY, process_identity_feature_conf_notify_func);

out:
	return ret;
}

void process_identity_exit(void)
{
	//if (clear_timeout_ids_cache_task) {
	//	kthread_stop(clear_timeout_ids_cache_task);
	//}
	//clear_timeout_ids_cache_task = NULL;

	httcsec_io_command_unregister(COMMAND_PROCESS_IDENTITY_USER_INTERFACE, (httcsec_io_command_func)ioctl_process_identity_user_interface);
	httcsec_io_command_unregister(COMMAND_RELOAD_PROCESS_ROLES_POLICY, (httcsec_io_command_func)ioctl_process_roles_reload_policy);
	httcsec_io_command_unregister(COMMAND_SET_PROCESS_ROLES_POLICY, (httcsec_io_command_func)ioctl_process_roles_set_policy);
	httcsec_io_command_unregister(COMMAND_RELOAD_PROCESS_IDS_POLICY, (httcsec_io_command_func)ioctl_process_ids_reload_policy);
	httcsec_io_command_unregister(COMMAND_SET_PROCESS_IDS_POLICY, (httcsec_io_command_func)ioctl_process_ids_set_policy);
	unregister_process_identity_callback(&process_identity_function);
	clean_policy_list();
	unregister_feature_conf_notify(FEATURE_PROCESS_IDENTITY, process_identity_feature_conf_notify_func);
	//clear_ids_cache();

	DEBUG_MSG(HTTC_TSB_DEBUG, "process_identity_exit success\n");
	return;
}



/* process identity interface */
struct policy_process_identity *qurey_name(const char *process_identity_name)
{
	struct list_head *pos = NULL;
	struct policy_process_identity *p_policy_process_identity = NULL;

	list_for_each(pos, &g_list_policy_process_identity)
	{
		p_policy_process_identity = list_entry(pos, struct policy_process_identity, list);

		if (strcmp(process_identity_name, p_policy_process_identity->item.name) == 0)
			return p_policy_process_identity;
	}

	return NULL;
}

//存在返回0，不存在返回-1
int qurey_hash(unsigned char *hash, struct policy_process_identity *p_policy_process_identity)
{
	int i = 0, hash_length = 0;

	hash_length = p_policy_process_identity->item.hash_length;
	for (i=0; i<(p_policy_process_identity->item.lib_number+1); i++)
	{
		if (memcmp(p_policy_process_identity->item.hash+i*hash_length, hash, hash_length) == 0)
			return 0;
	}

	return -1;
}

static inline struct task_struct *pid_to_task(pid_t pid)
{
	return pid_task(find_pid_ns(pid, &init_pid_ns), PIDTYPE_PID);
}

int tsb_verify_process(int pid,const char *name)
{
	struct task_struct *task = NULL;
	int ret = 0;
	
	//如果pid=0认证当前进程
	if (!pid)
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
	ret = tsb_verify_process_taskp(task, name);
	put_task_struct(task);

	return ret;
}
EXPORT_SYMBOL(tsb_verify_process);

int tsb_verify_process_taskp(struct task_struct *task,const char *name)
{

	unsigned char hash[LEN_HASH] = {0};
	int ret = 0, i = 0;
	struct file *exec_file = NULL;
	struct mm_struct *mm = NULL;
	char *fullpath = NULL;
	char *fullpath_prev = NULL;
	int vma_idx=0, file_offset = 0;
	struct vm_area_struct *vma = NULL;
	struct policy_process_identity *p_policy_process_identity;

	read_lock(&policy_process_identity_lock);
	p_policy_process_identity = qurey_name(name);
	if (!p_policy_process_identity)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], verify_process name[%s] donot exist in policy\n", __func__, name);
		ret = TSB_ERROR_PROCESS_IDENTITY_POLICY;
		goto err_out;
	}

	fullpath_prev = kzalloc(PATH_MAX,GFP_KERNEL);

	mm = get_task_mm(task);
	if (!mm)
	{
		ret = TSB_ERROR_SYSTEM;
		goto err_out;
	}
	exec_file = get_mm_exe_file(mm);
	if (!exec_file) {
		mmput(mm);
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_mm_exe_file error!\n", __func__);
		ret = TSB_ERROR_SYSTEM;
		goto err_out;
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

		vma_idx++;
		fullpath = vfs_get_fullpath((void *)vma->vm_file, TYPE_FILE);
		if (!fullpath)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], fullpath is NULL!\n", __func__);
			ret = TSB_ERROR_SYSTEM;
			goto out;
		}

		if (strcmp(fullpath_prev, fullpath)!=0) {
			vma_idx=1;
			file_offset = 0;
			strcpy(fullpath_prev, fullpath);
		}

		if (vma_idx==1 && !(vma->vm_flags & VM_EXEC)) {
			file_offset = vma->vm_end - vma->vm_start;
			DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], fullpath[%s] have special section, len[%d]\n", __func__, fullpath, file_offset);
		}

		if ((vma->vm_flags & VM_EXEC) && !(vma->vm_flags & VM_WRITE)) {

			int len = vma->vm_end - vma->vm_start;
			DEBUG_MSG(HTTC_TSB_DEBUG, "fullpath[%s] vm_start[%08lx] vm_end[%08lx], len[%d], vm_flags[%lx]\n", fullpath, vma->vm_start, vma->vm_end, len, vma->vm_flags);

			ret = task_cal_mem_file_hash(fullpath, task, mm, vma->vm_start, len, file_offset, hash);
			if (ret)
			{
				DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], fullpath[%s] text section calc hash error!\n", __func__, fullpath);
				vfs_put_fullpath(fullpath);
				ret = TSB_ERROR_CALC_HASH;
				goto out;
			}
			print_hex(fullpath, hash, LEN_HASH);

			i++;
			if (i>1 && process_identity_feature.process_verify_lib_mode==PROCESS_VERIFY_MODE_REF_LIB)
			{
				ret = query_process_identity_lib_hash(hash, LEN_HASH);
				if (ret)
				{
					DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], current lib hash donot exist in whitelist policy, return -1\n", __func__);
					ret = TSB_MEASURE_FAILE;
					goto out;
				}
				continue;
			}

			ret = qurey_hash(hash, p_policy_process_identity);
			if (ret)
			{
				DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], process[%s] hash or lib hash donot exist in process_identity_policy!\n", __func__, name);
				ret = TSB_MEASURE_FAILE;
				goto out;
			}

			//不需要验证动态库
			if (process_identity_feature.process_verify_lib_mode == PROCESS_VERIFY_MODE_NO_LIB)
				break;
		}
		vfs_put_fullpath(fullpath);
	}

	ret = 0;
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], process[%s] lib hash exist in process_identity_policy\n", __func__, name);
out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	up_read(&mm->mmap_lock);
#else
	up_read(&mm->mmap_sem);
#endif
	fput(exec_file);
	mmput(mm);
err_out:
	read_unlock(&policy_process_identity_lock);
	kfree(fullpath_prev);

	return ret;
}
EXPORT_SYMBOL(tsb_verify_process_taskp);


int tsb_get_process_identity(unsigned char *process_name,int *process_name_length)
{
	return get_process_identity(process_name, process_name_length);
}
EXPORT_SYMBOL(tsb_get_process_identity);

int tsb_is_role_member(const unsigned char *role_name)
{
	return is_role_member(role_name);
}
EXPORT_SYMBOL(tsb_is_role_member);
