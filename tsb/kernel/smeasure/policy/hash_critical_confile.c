#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/version.h>

#include "hash_critical_confile.h"
#include "sec_domain.h"
#include "../encryption/sm3/sm3.h"
#include "utils/debug.h"
#include "function_types.h"
#include "utils/klib_fileio.h"
#include "policy_whitelist_cache.h"
#include "tcsapi/tcs_file_integrity.h"
#include "tpcm_def.h"
#include "flush_dcache.h"
#include "tpcm/tpcmif.h"
#include "policy/feature_configure.h"
#include "tcsapi/tcs_policy_def.h"
#include "tcsapi/tcs_tpcm_error.h"
#include "tsbapi/tsb_measure_kernel.h"
#include "tpcm/tdd.h"
#include "tsbapi/tsb_log_notice.h"
#include "hash_whitelist.h"

static struct hlist_head *critical_confile_hashtable = NULL;
static rwlock_t critical_confile_hashtable_lock;
static atomic_t critical_confile_obj_count;
static unsigned int critical_confile_hash_random;


static void print_hex(const char *name, unsigned char *p, int len)
{
	int i = 0;

	DEBUG_MSG(HTTC_TSB_DEBUG,"name[%s] p[%p] len[%d]\n", name, p, len);
	for (i = 0; i < len; i++) {
		DEBUG_MSG(HTTC_TSB_DEBUG,"%02X", p[i]);
	}
	DEBUG_MSG(HTTC_TSB_DEBUG,"\n");
}

static inline unsigned string_hash_key(unsigned int random, const __u8 * p, int n)
{
	return jhash(p, n, random) & HASH_TAB_MASK;
}

static int critical_confile_path_hash_key(const char *hash, const char *path)
{
	return string_hash_key(critical_confile_hash_random, path, strlen(path));
}

static int critical_confile_path_hash_cmp(struct critical_confile_digest *u_digest, const char *hash, const char *path)
{
	if ((strncmp(u_digest->digest, hash, LEN_HASH)==0) && 
		(strcmp(u_digest->name, path)==0))
		return 0;
	
	return -1;
}

int get_critical_confile_digest(const char *path, unsigned char *hash_buf, int len)
{
	int copy_len=0;
	unsigned hash_table_index;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_digest *digest_info = NULL;

	hash_table_index = critical_confile_path_hash_key(NULL, path);

	read_lock(&critical_confile_hashtable_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_safe(digest_info, node, next, critical_confile_hashtable + hash_table_index, list)
#else
	hlist_for_each_entry_safe(digest_info, node, critical_confile_hashtable + hash_table_index, list)
#endif
	{
		if((copy_len+LEN_HASH) > len)
		{
			DEBUG_MSG(HTTC_TSB_INFO,"unit_get_hash_list hash buff beyond the length!\n");
			break;
		}
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], fullpath[%s] hash_table_index[%u] critical_confile_hash_random[%u]\n", __func__, path, hash_table_index, critical_confile_hash_random);
		memcpy(hash_buf+copy_len, digest_info->digest, LEN_HASH);
		copy_len += LEN_HASH;
	}
	read_unlock(&critical_confile_hashtable_lock);

	return copy_len;
}

long ioctl_critical_confile_reload_policy(unsigned long param)
{
	int count;

	count = atomic_read(&critical_confile_obj_count);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Hash critical_confile mod remove [%d]\n", count);

	load_critical_confile();

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s],  reload critical_confile policy success!\n", __func__);

	return 0;
}

int critical_confile_init()
{
	int idx;
	/*allocte hash table */
	if (!(critical_confile_hashtable = vmalloc(HASH_TAB_SIZE * sizeof(struct hlist_head))))
		return -ENOMEM;

	/*init hash tab */
	for (idx = 0; idx < HASH_TAB_SIZE; idx++) {
		INIT_HLIST_HEAD(&(critical_confile_hashtable[idx]));
	}

	rwlock_init(&critical_confile_hashtable_lock);
	atomic_set(&critical_confile_obj_count, 0);

	/*generate random */
	get_random_bytes(&critical_confile_hash_random, sizeof(critical_confile_hash_random));

	return 0;
}

void critical_confile_exit()
{
	int idx;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct critical_confile_digest *digest_info = NULL;

	int count = atomic_read(&critical_confile_obj_count);
	DEBUG_MSG(HTTC_TSB_DEBUG, "critical_confile remove num [%d]\n", count);

flush_again:
	write_lock(&critical_confile_hashtable_lock);
	for (idx = 0; idx < HASH_TAB_SIZE; idx++) 
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
		hlist_for_each_entry_safe(digest_info, node, next, critical_confile_hashtable + idx, list)
#else
		hlist_for_each_entry_safe(digest_info, node, critical_confile_hashtable + idx, list)
#endif
		{
			hlist_del(&digest_info->list);
			kfree(digest_info);
			atomic_dec(&critical_confile_obj_count);
		}
	}
	write_unlock(&critical_confile_hashtable_lock);

	if (atomic_read(&critical_confile_obj_count) != 0) {
		schedule();
		DEBUG_MSG(HTTC_TSB_INFO,"obj_count[%d], critical_confile clean error!", atomic_read(&critical_confile_obj_count));
		goto flush_again;
	}

	vfree(critical_confile_hashtable);
}

int digest_cal_critical_confile(struct file *file, char *digest, int len)
{
	int ret = -1;
	loff_t i_size, offset = 4; //关键文件策略文件固定偏移四位
	char *rbuf;
	sm3_context ctx;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	i_size = i_size_read(file->f_inode);
#else
	i_size = i_size_read(file->f_path.dentry->d_inode);
#endif

	sm3_init(&ctx);

	rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!rbuf) {
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc error!\n", __func__);
		return -ENOMEM;
	}

	while (offset < i_size) 
	{
		int rbuf_len;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
		rbuf_len = kernel_read(file, rbuf, PAGE_SIZE, &offset);
#else
		rbuf_len = kernel_read(file, offset, rbuf, PAGE_SIZE);
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

	if (offset == i_size) {
		sm3_finish(&ctx, digest);
		ret = 0;
	}

	if (rbuf)
		kfree(rbuf);

	if (!ret) {
		//DEBUG_MSG(HTTC_TSB_DEBUG, "ENTER:[%s], digest SUCCESS!\n", __func__);
		//print_hex(digest, LEN_HASH);
	} else {
		DEBUG_MSG(HTTC_TSB_INFO, "ENTER:[%s],  ERROR!\n", __func__);
	}

	return ret;
}

static int critical_confile_integrity_check(void)
{
	unsigned char tpcm_hash[LEN_HASH];
	unsigned char file_hash[LEN_HASH];
	char file_path[128] = {0};
	unsigned int hash_len = LEN_HASH;
	struct file *file = NULL;
	int ret = 0;

	ret = get_critical_file_integrity_digest(tpcm_hash, &hash_len);
	if (ret==123456)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], soft critical_confile policy, critical_confile_integrity_check skip\n",__func__);
		return 0;
	}
	if (ret || hash_len!=LEN_HASH)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_critical_file_integrity_digest error, ret[%x] hash_len[%d]!\n",__func__, ret, hash_len);
		return 0;
	}

	snprintf(file_path, 128, "%s%s", BASE_PATH, "conf/critical_integrity.data");
	file = filp_open(file_path, O_RDONLY, 0);
	if (IS_ERR(file))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"critical_confile file open error! critical_confile_integrity_check skip\n");
		return -1;
	}

	ret = digest_cal_critical_confile(file, file_hash, LEN_HASH);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], digest_cal error!\n",__func__);
		ret = -1;
		goto out;
	}

	if (memcmp(file_hash, tpcm_hash, LEN_HASH) != 0)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], tpcm_hash and critical_confile file_hash is different, error!\n",__func__);
		print_hex("tpcm_hash", tpcm_hash, LEN_HASH);
		print_hex("file_hash", file_hash, LEN_HASH);
		ret = -1;
		goto out;
	}
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], critical_confile policy file_integrity_check success\n",__func__);

out:
	if(file != NULL)
		filp_close(file, NULL);

	return ret;
}

int critical_confile_tmp_add(struct hlist_head *critical_confile_hashtable_tmp, int *critical_confile_num, char *path, unsigned char *hash)
{
	int len = 0;
	struct critical_confile_digest *u_digest;
	unsigned hash_table_index;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct critical_confile_digest *digest_info = NULL;

	len = sizeof(struct critical_confile_digest) + strlen(path) + 1;
	u_digest = kzalloc(len, GFP_KERNEL);
	if (!u_digest) {
		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc error!\n");
		return -ENOMEM;
	}

	memcpy(&u_digest->digest, hash, LEN_HASH);
	u_digest->len_name = strlen(path);
	memcpy(u_digest->name, path, strlen(path)+1);

	hash_table_index = critical_confile_path_hash_key(hash, path);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_safe(digest_info, node, next, critical_confile_hashtable_tmp + hash_table_index, list)
#else
	hlist_for_each_entry_safe(digest_info, node, critical_confile_hashtable_tmp + hash_table_index, list)
#endif
	{
		if (critical_confile_path_hash_cmp(digest_info, hash, path) == 0) {
			DEBUG_MSG(HTTC_TSB_INFO, "digest %s already exsit!\n", u_digest->name);
			kfree(u_digest);
			return -EEXIST;
		}
	}

	hlist_add_head(&u_digest->list, critical_confile_hashtable_tmp + hash_table_index);
	(*critical_confile_num)++;

	return 0;
}

void critical_confile_tmp_clean(struct hlist_head *critical_confile_hashtable_tmp, int critical_confile_num_tmp)
{
	int idx;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct critical_confile_digest *digest_info = NULL;

flush_again:
	for (idx = 0; idx < HASH_TAB_SIZE; idx++) 
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
		hlist_for_each_entry_safe(digest_info, node, next, critical_confile_hashtable_tmp + idx, list)
#else
		hlist_for_each_entry_safe(digest_info, node, critical_confile_hashtable_tmp + idx, list)
#endif
		{
			hlist_del(&digest_info->list);
			kfree(digest_info);
			critical_confile_num_tmp--;
		}
	}

	if (critical_confile_num_tmp != 0) {
		schedule();
		DEBUG_MSG(HTTC_TSB_INFO,"critical_confile_num_tmp[%d], critical_confile clean error!", critical_confile_num_tmp);
		goto flush_again;
	}
}

int load_critical_confile(void)
{
	int ret = -1;
	char *buff = NULL;
	struct file *file = NULL;
	char path[512] = {0};
	char file_path[128] = {0};
	unsigned char digest[LEN_HASH];
	int read_len=0, len=0, remain_len=0, data_len=0;
	int file_critical_confile_num=0, critical_confile_num=0, critical_confile_num_tmp=0, idx=0;
	loff_t i_size, offset = 4;  //关键文件策略文件固定偏移四位（后续改正）
	char *p;
	struct hlist_head *critical_confile_hashtable_tmp=NULL, *hashtable_tmp=NULL;

	//关键文件hash校验失败，仅发送警告日志即可
	if(critical_confile_integrity_check())
	{
		char buf[128] = {0};
		struct log_warning log_w = {0};
		struct log_n* file_integrity_log = (struct log_n*)buf;

		log_w.warning_type = WARNING_LOG_CRITICAL_CONFILE;

		file_integrity_log->category = LOG_CATEGRORY_WARNING;
		file_integrity_log->type = RESULT_FAIL;
		file_integrity_log->len = sizeof(log_w);
		memcpy(file_integrity_log->data, &log_w, sizeof(log_w));

		kernel_audit_log(file_integrity_log);
		//return ret;
	}

	snprintf(file_path, 128, "%s%s", BASE_PATH, "conf/critical_integrity.data");
	file = filp_open(file_path, O_RDONLY, 0);
	if (IS_ERR(file))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"critical_confile file open error!\n");
		return ret;
	}

	if (!(buff = vmalloc(1024)))
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc error!\n",__func__);
		ret = -ENOMEM;
		goto out;
	}

	if (!(critical_confile_hashtable_tmp = vmalloc(HASH_TAB_SIZE * sizeof(struct hlist_head))))
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc critical_confile_hashtable error!\n",__func__);
		ret = -ENOMEM;
		goto out;
	}
	for (idx = 0; idx < HASH_TAB_SIZE; idx++) {
		INIT_HLIST_HEAD(&(critical_confile_hashtable_tmp[idx]));
	}
	critical_confile_num_tmp = atomic_read(&critical_confile_obj_count);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	i_size = i_size_read(file->f_inode);
#else
	i_size = i_size_read(file->f_path.dentry->d_inode);
#endif

	while(offset < i_size)
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
		read_len = kernel_read(file, buff+remain_len, 1024-remain_len, &offset);
#else
		read_len = kernel_read(file, offset, buff+remain_len, 1024-remain_len);
#endif
		if (read_len <= 0)
			break;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
		offset += read_len;
#endif

		remain_len += read_len;
		p = buff;
		
		while(remain_len > sizeof(struct file_integrity_item))
		{
			struct file_integrity_item *p_item = (struct file_integrity_item *)p;
			p_item->be_path_length = ntohs(p_item->be_path_length);
			data_len = LEN_HASH + p_item->extend_size + p_item->be_path_length;
			BYTE4_ALIGNMENT(data_len);  //处理4字节对齐的问题
			len = sizeof(struct file_integrity_item) + data_len;

			if (remain_len < len)
			{
				p_item->be_path_length = htons(p_item->be_path_length);
				break;
			}
			
			memset(digest, 0, LEN_HASH);
			if (memcmp(p_item->data, digest, LEN_HASH)==0)
			{
				DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], hash format error, skip!\n",__func__);
				p = p+len;
				remain_len = remain_len - len;
				continue;
			}
			memcpy(digest, p_item->data, LEN_HASH);
			memset(path, 0, 512);
			memcpy(path, p_item->data+LEN_HASH+p_item->extend_size, p_item->be_path_length);
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], data_len:%d path_length:%d extend_size:%d path:%s\n", __func__, data_len, p_item->be_path_length, p_item->extend_size, path);

			critical_confile_tmp_add(critical_confile_hashtable_tmp, &critical_confile_num, path, digest);
			file_critical_confile_num++;
			
			p = p+len;
			remain_len = remain_len - len;
		}

		if (remain_len>0)
			memcpy(buff, p, remain_len);

		if (remain_len<0)
			DEBUG_MSG(HTTC_TSB_DEBUG,"-------------------read error----------------------\n");

	}

	if (offset != i_size)
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s],  add critical_confile error! offset[%lld] i_size[%lld]\n", __func__, offset, i_size);
	else
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s],  add critical_confile file_critical_confile_num[%d] critical_confile_num[%d] success\n", __func__, file_critical_confile_num, critical_confile_num);

	write_lock(&critical_confile_hashtable_lock);
	hashtable_tmp = critical_confile_hashtable;
	critical_confile_hashtable = critical_confile_hashtable_tmp;
	critical_confile_hashtable_tmp = hashtable_tmp;
	atomic_set(&critical_confile_obj_count, critical_confile_num);
	write_unlock(&critical_confile_hashtable_lock);

	critical_confile_tmp_clean(critical_confile_hashtable_tmp, critical_confile_num_tmp);
	vfree(critical_confile_hashtable_tmp);

	ret = 0;

out:
	if(file != NULL)
		filp_close(file, NULL);
	if(buff)
		vfree(buff);

	return ret; 
}
