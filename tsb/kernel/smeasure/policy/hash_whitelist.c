#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/random.h>
//#include <linux/netlink.h>
#include <linux/version.h>
#include <linux/uaccess.h>

#include "hash_whitelist.h"
#include "sec_domain.h"
//#include "policy_data.h"
#include "../encryption/sm3/sm3.h"
#include "utils/debug.h"
//#include "../utils/flush_dcache.h"
//#include "tpcmif.h"
#include "function_types.h"
#include "utils/klib_fileio.h"
#include "policy_whitelist_cache.h"
#include "tcsapi/tcs_file_integrity.h"
#include "tpcm_def.h"
#include "flush_dcache.h"
#include "tpcm/tpcmif.h"
//#include "policy/global_policy.h"
#include "policy/feature_configure.h"
#include "tcsapi/tcs_policy_def.h"
#include "tcsapi/tcs_tpcm_error.h"
#include "tsbapi/tsb_measure_kernel.h"
#include "tsbapi/tsb_log_notice.h"
#include "tpcm/tdd.h"

extern struct whitelist_feature_conf whitelist_feature;

int file_integrity_valid = 1;

static struct hlist_head *whitelist_hashtable = NULL;
static rwlock_t whitelist_hashtable_lock;
static atomic_t whitelist_obj_count;
static unsigned int whitelist_hash_random;

//void print_hex(const char *name, unsigned char *p, int len)
//{
//	int i = 0;
//
//	printk("%s: \n", name);
//	for (i = 0; i < len; i++) {
//		printk("%02x", (int)p[i] & 0x000000ff);
//	}
//	printk("\n");
//}
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

static int whitelist_hash_key(const char *hash, const char *path)
{
	//struct k_st_digest *k_digest = (struct k_st_digest *)cp->s;
	return string_hash_key(whitelist_hash_random, hash, LEN_HASH);
}

static int whitelist_hash_cmp(struct whitelist_digest *u_digest, const char *hash, const char *path)
{
	//struct k_st_digest *k_dig1 = (struct k_st_digest *)cp->s;
	//struct k_st_digest *k_dig2 = (struct k_st_digest *)scp->s;

	if ((strncmp(u_digest->digest, hash, LEN_HASH)==0) && 
		(strcmp(u_digest->name, path)==0))
		return 0;

	return -1;
}

static int whitelist_hash_cmp_extension(struct whitelist_digest *u_digest, const char *hash, const char *path)
{
	//struct k_st_digest *k_digest = (struct k_st_digest *)cp->s;

	//只匹配哈希
	//int measure_match_mode = get_whitelist_measure_match_mode();
	if (whitelist_feature.match_mode == PROCESS_MEASURE_MATCH_HASH_ONLY)
		return strncmp(u_digest->digest, hash, LEN_HASH);

	//既匹配哈希，又匹配路径
	if ((strncmp(u_digest->digest, hash, LEN_HASH)==0) 
		&& (strcmp(u_digest->name, path)==0))
		return 0;

	return -1;
}

/* #if defined CHECK_SHA1 */
/* int digest_cal(struct file *file, char *digest, int len) */
/* { */
/* 	int ret = 0; */
/* 	struct sha1_ctx ctx; */
/* 	loff_t i_size, offset = 0; */
/* 	char *rbuf = NULL; */
/* 	int rbuf_len = 0; */

/* 	sha1_init_ctx(&ctx); */

/* 	rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL); */
/* 	if (!rbuf) { */
/* 		return -ENOMEM; */
/* 	} */

/* 	i_size = i_size_read(file->f_path.dentry->d_inode); */
/* 	while (offset < i_size) { */
/* 		rbuf_len = kernel_read(file, offset, rbuf, PAGE_SIZE); */
/* 		if (rbuf_len < 0) { */
/* 			ret = rbuf_len; */
/* 			break; */
/* 		} */
/* 		if (rbuf_len == 0) */
/* 			break; */
/* 		offset += rbuf_len; */

/* 		sha1_process_bytes(rbuf, rbuf_len, &ctx); */
/* 	} */

/* 	if (offset == i_size) { */
/* 		sha1_finish_ctx(&ctx, digest); */
/* 		ret = 0; */
/* 	} */

/* 	if (rbuf) */
/* 		kfree(rbuf); */

/* 	return ret; */
/* } */
/* EXPORT_SYMBOL(digest_cal); */
/* #elif defined DIGEST_SM3 */
int digest_cal(struct file *file, char *digest, int len)
{
	int ret = 0;
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
		if (rbuf_len < 0) {
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
EXPORT_SYMBOL(digest_cal);
/* #endif */

static int get_digest(const char *hash, const char *path)
{
	int ret = -1;
	unsigned hash_table_index;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_digest *digest_info = NULL;

	hash_table_index = whitelist_hash_key(hash, path);

	read_lock(&whitelist_hashtable_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_safe(digest_info, node, next, whitelist_hashtable + hash_table_index, list)
#else
	hlist_for_each_entry_safe(digest_info, node, whitelist_hashtable + hash_table_index, list)
#endif
	{
		if (whitelist_hash_cmp_extension(digest_info, hash, path) == 0) {
			ret = 0;
			goto out;
		}
	}

out:
	read_unlock(&whitelist_hashtable_lock);
	return ret;
}

static int get_digest_no_path(const char *hash)
{
	int ret = -1;
	unsigned hash_table_index;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_digest *digest_info = NULL;

	hash_table_index = whitelist_hash_key(hash, NULL);

	read_lock(&whitelist_hashtable_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_safe(digest_info, node, next, whitelist_hashtable + hash_table_index, list)
#else
	hlist_for_each_entry_safe(digest_info, node, whitelist_hashtable + hash_table_index, list)
#endif
	{
		if (strncmp(digest_info->digest, hash, LEN_HASH) == 0) {
			ret = 0;
			goto out;
		}
	}

out:
	read_unlock(&whitelist_hashtable_lock);
	return ret;
}

/* #if defined (CHECK_SHA1) */
/* int check_module_digest(const void *buf, int len, char *digest) */
/* { */
/* 	int ret = 0; */
/* 	struct sha1_ctx ctx; */

/* 	sha1_init_ctx(&ctx); */
/* 	sha1_process_bytes(buf, len, &ctx); */
/* 	sha1_finish_ctx(&ctx, digest); */

/* 	print_hex("module digest", digest, LEN_HASH); */

/* 	ret = get_digest(digest); */

/* 	return ret; */
/* } */

/* EXPORT_SYMBOL(check_module_digest); */
/* #elif defined (DIGEST_SM3) */
int check_module_digest(const void *buf, int len, char *digest)
{
	int ret = 0;

	sm3_context ctx;

	sm3_init(&ctx);
	sm3_update(&ctx, buf, len);
	sm3_finish(&ctx, digest);

	ret = get_digest_no_path(digest);
/*	if (ret < 0) {  */
/*		print_hex("module digest", digest, LEN_HASH);  */
/*	} */

	return ret;
}
EXPORT_SYMBOL(check_module_digest);
/* #endif */

int digest_check(struct file *file, struct sec_domain *sec_d, int type)
{
	int ret = 0;
	char file_digest[LEN_HASH] = { 0 };

	ret = digest_cal(file, file_digest, LEN_HASH);
	if (ret < 0)
		return DC_ERROR_PASS;

	memcpy(sec_d->sub_hash, file_digest, LEN_HASH);

	ret = get_digest(file_digest, sec_d->obj_name);
	if (ret < 0) {
		ret = DC_FORBID;
		//print_hex_dump(KERN_NOTICE, "TSB sm3 ", DUMP_PREFIX_OFFSET, 16, 1, file_digest, LEN_HASH, true);
	} else {
		ret = DC_PASS;
	}

	return ret;
}

int digest_check_tpcm(struct file *file, struct sec_domain *sec_d, int type)
{
	int ret = 0;
	loff_t i_size, offset = 0;
	char *rbuf = NULL;
	int rbuf_len = 0;
	int pages_sum = 0;
	int i = 0;
	uint32_t tpcmRes = 0;
	uint32_t mrLen = LEN_HASH;
	uint8_t mresult[LEN_HASH] = { 0 };
	typedef struct {
		char *addr;
	} virtaddr;
	virtaddr *virt_addr = NULL;
	struct physical_memory_block *phys_addr = NULL;

	//char digest[LEN_HASH] = {0};
	//sm3_context ctx;
	//sm3_init(&ctx);
	type = convert_intercept_type_for_tpcm(type);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	i_size = i_size_read(file->f_inode);
#else
	i_size = i_size_read(file->f_path.dentry->d_inode);
#endif

	//printk("Enter:[%s], page:[%llu], ex:[%llu], page_size:[%lu]\n", __func__, i_size/(PAGE_SIZE*16), i_size%(PAGE_SIZE*16), PAGE_SIZE*16);

	pages_sum = (int)(i_size / (PAGE_SIZE * 16));
	if (i_size % (PAGE_SIZE * 16))
		pages_sum += 1;

	//printk("Enter:[%s], pages:[%d]\n", __func__, pages_sum);
	virt_addr = kzalloc(sizeof(virtaddr) * pages_sum, GFP_KERNEL);
	if (!virt_addr) {
		ret = DC_ERROR_PASS;
		goto out;
	}
	phys_addr = kzalloc(sizeof(struct physical_memory_block) * pages_sum, GFP_KERNEL);
	if (!phys_addr) {
		ret = DC_ERROR_PASS;
		goto out;
	}

	while (offset < i_size) {
		rbuf = kzalloc(PAGE_SIZE * 16, GFP_KERNEL);
		if (!rbuf) {
			ret = DC_ERROR_PASS;
			goto out1;
		}
		virt_addr[i].addr = rbuf;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
		rbuf_len = kernel_read(file, rbuf, PAGE_SIZE * 16, &offset);
#else
		rbuf_len = kernel_read(file, offset, rbuf, PAGE_SIZE * 16);
#endif
		if (rbuf_len < 0) {
			ret = DC_ERROR_PASS;
			goto out1;
		}
		if (rbuf_len == 0)
			break;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
		offset += rbuf_len;
#endif

		kernel_flush_dcache_area(rbuf, rbuf_len);

		phys_addr[i].physical_addr = tpcm_virt_to_phys(rbuf);
		phys_addr[i].length = rbuf_len;

		i++;
		//sm3_update(&ctx, rbuf, rbuf_len);
	}

	//print_hex_dump(KERN_NOTICE, "phys_addr ", DUMP_PREFIX_OFFSET, 16, 1, (unsigned char *)phys_addr, sizeof (struct physical_memory_block) * pages_sum, true);
	if (offset == i_size) {
again:
		ret = measure_digest_by_tpcm(sec_d->obj_len, sec_d->obj_name, type,
					     pages_sum, phys_addr, &tpcmRes, &mrLen, mresult);
		if (ret == TPCM_ERROR_TIMEOUT || ret == TPCM_ERROR_NO_SPACE) {
			DEBUG_MSG(HTTC_TSB_INFO,			\
				  "tcsk_integrity_measure timeout or no_space, ret[%08x]!\n", ret);
			goto again;
		} else if (ret == 516) {
			ret = digest_check_tpcm_simple(file, sec_d, type);
			DEBUG_MSG(HTTC_TSB_INFO, "tcsk_integrity_measure ret[0x00000204, 516]! cmd is too long. call digest_check_tpcm_simple ret[%d]\n", ret);
			goto out1;
		} else if (ret) {
			DEBUG_MSG(HTTC_TSB_INFO, "tcsk_integrity_measure error, ret[%08x]!\n", ret);
			ret = DC_FORBID;
			goto out1;
		}
		
		//sm3_finish(&ctx, digest);
		//print_hex_dump(KERN_NOTICE, "TSB sm3 ", DUMP_PREFIX_OFFSET, 16, 1, digest, LEN_HASH, true);

		memcpy(sec_d->sub_hash, mresult, LEN_HASH);
		//print_hex_dump(KERN_NOTICE, "TPCM sm3 ", DUMP_PREFIX_OFFSET, 16, 1, mresult, LEN_HASH, true);
		if (tpcmRes == TPCM_SUCCESS) {
			DEBUG_MSG(HTTC_TSB_INFO, "tcsk_integrity_measure, tpcm res is success, [%08x]!\n", tpcmRes);
			ret = DC_PASS;
		} else {
			DEBUG_MSG(HTTC_TSB_INFO, "tcsk_integrity_measure, tpcm res is error, [%08x]!\n", tpcmRes);

			//tpcm度量接口 先判断接口返回值。
			//然后判断高16位 0表示控制模式关闭 1开启
			//低16位表示错误码 0表示放行 其他为具体错误码	
			if(!(tpcmRes & 0xffff0000)){
				ret = DC_EAUDIT_PASS;
				goto out1;
			}

			switch (tpcmRes & 0x0000ffff) {
			case TPCM_LICENSE_INVALID:
			case TPCM_LICENSE_EXPIRED:
				ret = DC_EAUDIT_PASS;
				break;
			default:
				ret = DC_FORBID;
				break;
			}
		}
	} else {
		DEBUG_MSG(HTTC_TSB_INFO, "system error!\n");
		ret = DC_ERROR_PASS;
	}

out1:
	for (i = 0; i < pages_sum; i++) {
		if (virt_addr[i].addr) {
			kfree(virt_addr[i].addr);
		}
	}
out:
	if (phys_addr)
		kfree(phys_addr);
	if (virt_addr)
		kfree(virt_addr);

	return ret;
}
//EXPORT_SYMBOL(digest_check);

int digest_check_tpcm_simple(struct file *file, struct sec_domain *sec_d, int type)
{
	int ret = 0;
	uint32_t tpcmRes = 0;
	char file_digest[LEN_HASH] = { 0 };

	ret = digest_cal(file, file_digest, LEN_HASH);
	if (ret < 0)
		return DC_ERROR_PASS;

	memcpy(sec_d->sub_hash, file_digest, LEN_HASH);

	//ret = get_digest(file_digest);
	//if (ret < 0) {
	//	ret = DC_FORBID;
	//	//print_hex_dump(KERN_NOTICE, "TSB sm3 ", DUMP_PREFIX_OFFSET, 16, 1, file_digest, LEN_HASH, true);
	//} else {
	//	ret = DC_PASS;
	//}
	type = convert_intercept_type_for_tpcm(type);

	ret = measure_digest_by_tpcm_simple(sec_d->obj_len, sec_d->obj_name, type, LEN_HASH, file_digest, &tpcmRes);
	if (ret == TPCM_ERROR_TIMEOUT || ret == TPCM_ERROR_NO_SPACE) {
		DEBUG_MSG(HTTC_TSB_INFO,			\
			"tcsk_integrity_measure_simple timeout or no_space, ret[%08x]!\n", ret);
		goto out1;
	} else if (ret) {
		DEBUG_MSG(HTTC_TSB_INFO, "tcsk_integrity_measure_simple error, ret[%08x]!\n", ret);
		ret = DC_FORBID;
		goto out1;
	}

	if (tpcmRes == TPCM_SUCCESS) {
		DEBUG_MSG(HTTC_TSB_INFO, "tcsk_integrity_measure_simple, tpcm res is success, [%08x]!\n", tpcmRes);
		ret = DC_PASS;
	} else {
		DEBUG_MSG(HTTC_TSB_INFO, "tcsk_integrity_measure_simple, tpcm res is error, [%08x]!\n", tpcmRes);

		//tpcm度量接口 先判断接口返回值。
		//然后判断高16位 0表示控制模式关闭 1开启
		//低16位表示错误码 0表示放行 其他为具体错误码	
		if(!(tpcmRes & 0xffff0000)){
			ret = DC_EAUDIT_PASS;
			goto out1;
		}

		switch (tpcmRes & 0x0000ffff) {
		case TPCM_LICENSE_INVALID:
		case TPCM_LICENSE_EXPIRED:
			ret = DC_EAUDIT_PASS;
			break;
		default:
			ret = DC_FORBID;
			break;
		}
	}

out1:
	return ret;
}

int whitelist_del(char *path, unsigned char *hash)
{
	unsigned hash_table_index;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_digest *digest_info = NULL;

	hash_table_index = whitelist_hash_key(hash, path);

	write_lock(&whitelist_hashtable_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_safe(digest_info, node, next, whitelist_hashtable + hash_table_index, list)
#else
	hlist_for_each_entry_safe(digest_info, node, whitelist_hashtable + hash_table_index, list)
#endif
	{
		if (whitelist_hash_cmp(digest_info, hash, path) == 0) 
		{
			hlist_del(&digest_info->list);
			kfree(digest_info);
			atomic_dec(&whitelist_obj_count);
			write_unlock(&whitelist_hashtable_lock);
			return 0;
		}
	}
	write_unlock(&whitelist_hashtable_lock);

	DEBUG_MSG(HTTC_TSB_INFO, "digest: %s not exist!\n", path);
	return -EINVAL;
}

int whitelist_add(char *path, unsigned char *hash)
{
	int len = 0;
	struct whitelist_digest *u_digest;
	unsigned hash_table_index;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_digest *digest_info = NULL;

	hash_table_index = whitelist_hash_key(hash, path);

	read_lock(&whitelist_hashtable_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_safe(digest_info, node, next, whitelist_hashtable + hash_table_index, list)
#else
	hlist_for_each_entry_safe(digest_info, node, whitelist_hashtable + hash_table_index, list)
#endif
	{
		if (whitelist_hash_cmp(digest_info, hash, path) == 0) {
			DEBUG_MSG(HTTC_TSB_INFO, "digest %s already exsit!\n", path);
			read_unlock(&whitelist_hashtable_lock);
			return -EEXIST;
		}
	}
	read_unlock(&whitelist_hashtable_lock);

	len = sizeof(struct whitelist_digest) + strlen(path) + 1;
	u_digest = kzalloc(len, GFP_KERNEL);
	if (!u_digest) {
		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc error!\n");
		return -ENOMEM;
	}

	memcpy(&u_digest->digest, hash, LEN_HASH);
	u_digest->len_name = strlen(path);
	memcpy(u_digest->name, path, strlen(path)+1);

	write_lock(&whitelist_hashtable_lock);
	hlist_add_head(&u_digest->list, whitelist_hashtable + hash_table_index);
	atomic_inc(&whitelist_obj_count);
	write_unlock(&whitelist_hashtable_lock);

	return 0;
}

long ioctl_whitelist_reload_policy(unsigned long param)
{
	int count;

	policy_whitelist_cache_clean();

	count = atomic_read(&whitelist_obj_count);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Hash whitelist mod remove [%d]\n", count);
	//hash_cleanup(handle_whitelist);

	//ret = httc_hash_init(handle_whitelist);
	//if (ret < 0) {
	//	DEBUG_MSG(HTTC_TSB_INFO, "Whitelist init error!\n");
	//} else {
	//	DEBUG_MSG(HTTC_TSB_DEBUG, "Whitelist init success!\n");
	//}

	load_whitelist();

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s],  reload whitelist policy success!\n", __func__);

	return 0;
}

int whitelist_add_del_policy(int operate, unsigned long param)
{
	unsigned char digest[LEN_HASH];
	char path[512] = {0};
	int  remain_len=0, whitelist_num=0;
	struct tsb_general_policy general_policy;
	char *p_buff = NULL, *p=NULL;

	int ret =copy_from_user(&general_policy, (void *)param, sizeof(general_policy));
	if (ret || !general_policy.length) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user whitelist policy error! ret[%d] policy length[%d]\n", __func__, ret, general_policy.length);
		return -1;
	}

	//update_item.be_item_number = NTOHL(update_item.be_item_number);
	//update_item.be_data_length = NTOHL(update_item.be_data_length);

	p_buff = vmalloc(general_policy.length);
	if (!p_buff)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc error! whitelist policy length[%d]\n", __func__, general_policy.length);
		return -1;
	}

	ret =copy_from_user(p_buff, general_policy.data, general_policy.length);
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s],  copy_from_user whitelist policy file_integrity_item failed!\n", __func__);
		vfree(p_buff);
		return -1;
	}

	remain_len = general_policy.length;
	p = p_buff;

	while(remain_len > 0)
	{
		int len;
		int data_len;
		struct file_integrity_item *p_item = (struct file_integrity_item *)p;
		p_item->be_path_length = ntohs(p_item->be_path_length);
		data_len = LEN_HASH + p_item->extend_size + p_item->be_path_length;
		BYTE4_ALIGNMENT(data_len);  //处理4字节对齐的问题
		len = sizeof(struct file_integrity_item) + data_len;

		if (remain_len < len)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], remain_len[%d] len[%d], whitelist policy format error!\n",__func__, remain_len, len);
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
		//printk("-----data_len:%d path_length:%d extend_size:%d path:%s-------\n", data_len, p_item->be_path_length, p_item->extend_size, path);

		//whitelist_add(path, digest);
		if(operate == 1)
			whitelist_add(path, digest);
		else
			whitelist_del(path, digest);
		whitelist_num++;

		p = p+len;
		remain_len = remain_len - len;
	}

	if (remain_len!=0)
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], whitelist policy format error!\n",__func__);

	vfree(p_buff);

	if(operate == 1)
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s],  add whitelist num[%d] success\n", __func__, whitelist_num);
	else
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s],  del whitelist num[%d] success\n", __func__, whitelist_num);

	return 0;
}

long ioctl_whitelist_del_policy(unsigned long param)
{
	policy_whitelist_cache_clean();
	whitelist_add_del_policy(2, param);

	return 0;
}

long ioctl_whitelist_add_policy(unsigned long param)
{

	whitelist_add_del_policy(1, param);

	return 0;
}

int whitelist_init()
{
	int idx;
	/*allocte hash table */
	if (!(whitelist_hashtable = vmalloc(HASH_TAB_SIZE * sizeof(struct hlist_head))))
		return -ENOMEM;

	/*init hash tab */
	for (idx = 0; idx < HASH_TAB_SIZE; idx++) {
		INIT_HLIST_HEAD(&(whitelist_hashtable[idx]));
	}

	rwlock_init(&whitelist_hashtable_lock);
	atomic_set(&whitelist_obj_count, 0);

	/*generate random */
	get_random_bytes(&whitelist_hash_random, sizeof(whitelist_hash_random));

	return 0;
}

void whitelist_exit()
{
	int idx;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_digest *digest_info = NULL;

	int count = atomic_read(&whitelist_obj_count);
	DEBUG_MSG(HTTC_TSB_INFO, "Hash whitelist mod remove [%d]\n", count);

flush_again:
	write_lock(&whitelist_hashtable_lock);
	for (idx = 0; idx < HASH_TAB_SIZE; idx++) 
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
		hlist_for_each_entry_safe(digest_info, node, next, whitelist_hashtable + idx, list)
#else
		hlist_for_each_entry_safe(digest_info, node, whitelist_hashtable + idx, list)
#endif
		{
			hlist_del(&digest_info->list);
			kfree(digest_info);
			atomic_dec(&whitelist_obj_count);
		}
	}
	write_unlock(&whitelist_hashtable_lock);

	if (atomic_read(&whitelist_obj_count) != 0) {
		schedule();
		DEBUG_MSG(HTTC_TSB_INFO,"obj_count[%d], whitelist clean error!", atomic_read(&whitelist_obj_count));
		goto flush_again;
	}

	vfree(whitelist_hashtable);
}

int file_integrity_check(void)
{
	unsigned char tpcm_hash[LEN_HASH];
	unsigned char file_hash[LEN_HASH];
	char file_path[128] = {0};
	unsigned int hash_len = LEN_HASH;
	struct file *file = NULL;
	int ret = 0;

	ret = get_file_integrity_digest(tpcm_hash, &hash_len);
	if (ret==123456)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], soft whitelist policy, file_integrity_check skip\n",__func__);
		return 0;
	}
	if (ret || hash_len!=LEN_HASH)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_file_integrity_digest error, ret[%x] hash_len[%d]!\n",__func__, ret, hash_len);
		return 1;
	}

	snprintf(file_path, 128, "%s%s", BASE_PATH, "conf/integrity.data");
	file = filp_open(file_path, O_RDONLY, 0);
	if (IS_ERR(file))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"whitelist file open error!\n");
		return 1;
	}

	ret = digest_cal(file, file_hash, LEN_HASH);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], digest_cal error!\n",__func__);
		ret = -1;
		goto out;
	}

	if (memcmp(file_hash, tpcm_hash, LEN_HASH) != 0)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], tpcm_hash and whitelist file_hash is different, error!\n",__func__);
		print_hex("tpcm_hash", tpcm_hash, LEN_HASH);
		print_hex("file_hash", file_hash, LEN_HASH);
		ret = -1;
		goto out;
	}
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], whitelist policy file_integrity_check success\n",__func__);

out:
	if(file != NULL)
		filp_close(file, NULL);

	return ret;
}

int whitelist_tmp_add(struct hlist_head *whitelist_hashtable_tmp, int *whitelist_num, char *path, unsigned char *hash)
{
	int len = 0;
	struct whitelist_digest *u_digest;
	unsigned hash_table_index;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_digest *digest_info = NULL;

	len = sizeof(struct whitelist_digest) + strlen(path) + 1;
	u_digest = kzalloc(len, GFP_KERNEL);
	if (!u_digest) {
		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc error!\n");
		return -ENOMEM;
	}

	memcpy(&u_digest->digest, hash, LEN_HASH);
	u_digest->len_name = strlen(path);
	memcpy(u_digest->name, path, strlen(path)+1);

	hash_table_index = whitelist_hash_key(hash, path);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_safe(digest_info, node, next, whitelist_hashtable_tmp + hash_table_index, list)
#else
	hlist_for_each_entry_safe(digest_info, node, whitelist_hashtable_tmp + hash_table_index, list)
#endif
	{
		if (whitelist_hash_cmp(digest_info, hash, path) == 0) {
			DEBUG_MSG(HTTC_TSB_INFO, "digest %s already exsit!\n", u_digest->name);
			kfree(u_digest);
			return -EEXIST;
		}
	}

	hlist_add_head(&u_digest->list, whitelist_hashtable_tmp + hash_table_index);
	(*whitelist_num)++;

	return 0;
}

void whitelist_tmp_clean(struct hlist_head *whitelist_hashtable_tmp, int whitelist_num_tmp)
{
	int idx;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_digest *digest_info = NULL;

flush_again:
	for (idx = 0; idx < HASH_TAB_SIZE; idx++) 
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
		hlist_for_each_entry_safe(digest_info, node, next, whitelist_hashtable_tmp + idx, list)
#else
		hlist_for_each_entry_safe(digest_info, node, whitelist_hashtable_tmp + idx, list)
#endif
		{
			hlist_del(&digest_info->list);
			kfree(digest_info);
			whitelist_num_tmp--;
		}
	}

	if (whitelist_num_tmp != 0) {
		schedule();
		DEBUG_MSG(HTTC_TSB_INFO,"whitelist_num_tmp[%d], whitelist clean error!", whitelist_num_tmp);
		goto flush_again;
	}
}

int load_whitelist(void)
{
	int ret;
	char *buff = NULL;
	struct file *file = NULL;
	char path[512] = {0};
	char file_path[128] = {0};
	unsigned char digest[LEN_HASH];
	int read_len=0, len=0, remain_len=0, data_len=0;
	int file_whitelist_num=0, whitelist_num=0, whitelist_num_tmp=0, idx=0;
	loff_t i_size, offset = 0;
	char *p;
	struct hlist_head *whitelist_hashtable_tmp=NULL, *hashtable_tmp=NULL;

	//白名单文件hash校验失败，发送警告日志，不加载白名单策略，所有程序不可以被执行
	ret = file_integrity_check();
	if(ret == 1 )
	{
		return -1;
	}
	else if(ret)
	{
		char buf[128] = {0};
		struct log_warning log_w = {0};
		struct log_n* file_integrity_log = (struct log_n*)buf;

		file_integrity_valid = 0;
		log_w.warning_type = WARNING_LOG_WHITELIST;

		file_integrity_log->category = LOG_CATEGRORY_WARNING;
		file_integrity_log->type = RESULT_FAIL;
		file_integrity_log->len = sizeof(log_w);
		memcpy(file_integrity_log->data, &log_w, sizeof(log_w));

		kernel_audit_log(file_integrity_log);
		return ret;
	}

	snprintf(file_path, 128, "%s%s", BASE_PATH, "conf/integrity.data");
	file = filp_open(file_path, O_RDONLY, 0);
	if (IS_ERR(file))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"whitelist file open error!\n");
		return ret;
	}

	if (!(buff = vmalloc(1024)))
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc error!\n",__func__);
		ret = -ENOMEM;
		goto out;
	}

	if (!(whitelist_hashtable_tmp = vmalloc(HASH_TAB_SIZE * sizeof(struct hlist_head))))
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc whitelist_hashtable error!\n",__func__);
		ret = -ENOMEM;
		goto out;
	}
	for (idx = 0; idx < HASH_TAB_SIZE; idx++) {
		INIT_HLIST_HEAD(&(whitelist_hashtable_tmp[idx]));
	}
	whitelist_num_tmp = atomic_read(&whitelist_obj_count);

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
				//DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], hash format error, skip!\n",__func__);
				p = p+len;
				remain_len = remain_len - len;
				continue;
			}
			memcpy(digest, p_item->data, LEN_HASH);
			memset(path, 0, 512);
			memcpy(path, p_item->data+LEN_HASH+p_item->extend_size, p_item->be_path_length);
			//printk("-----data_len:%d path_length:%d extend_size:%d path:%s-------\n", data_len, p_item->be_path_length, p_item->extend_size, path);

			whitelist_tmp_add(whitelist_hashtable_tmp, &whitelist_num, path, digest);
			file_whitelist_num++;
			
			p = p+len;
			//use_len = use_len+len;
			remain_len = remain_len - len;
		}

		if (remain_len>0)
			memcpy(buff, p, remain_len);

		if (remain_len<0)
			DEBUG_MSG(HTTC_TSB_DEBUG,"-------------------read error----------------------\n");
	}

	if (offset != i_size)
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s],  add whitelist error! offset[%lld] i_size[%lld]\n", __func__, offset, i_size);
	else
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s],  add whitelist file_whitelist_num[%d] whitelist_num[%d] success\n", __func__, file_whitelist_num, whitelist_num);

	write_lock(&whitelist_hashtable_lock);
	hashtable_tmp = whitelist_hashtable;
	whitelist_hashtable = whitelist_hashtable_tmp;
	whitelist_hashtable_tmp = hashtable_tmp;
	atomic_set(&whitelist_obj_count, whitelist_num);
	write_unlock(&whitelist_hashtable_lock);

	whitelist_tmp_clean(whitelist_hashtable_tmp, whitelist_num_tmp);
	vfree(whitelist_hashtable_tmp);

	ret = 0;

out:
	if(file != NULL)
		filp_close(file, NULL);
	if(buff)
		vfree(buff);

	return ret; 
}



int query_hash(const char *hash_str, int len)
{
	int ret = -1;
	unsigned hash_table_index;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_digest *digest_info = NULL;

	hash_table_index = whitelist_hash_key(hash_str, NULL);

	read_lock(&whitelist_hashtable_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_safe(digest_info, node, next, whitelist_hashtable + hash_table_index, list)
#else
	hlist_for_each_entry_safe(digest_info, node, whitelist_hashtable + hash_table_index, list)
#endif
	{
		if (strncmp(digest_info->digest, hash_str, LEN_HASH) == 0) {
			ret = 0;
			goto out;
		}
	}

out:
	read_unlock(&whitelist_hashtable_lock);
	return ret;
}

int query_hash_and_path(const char *hash_str, int len, const char *path)
{
	int ret = -1;
	unsigned hash_table_index;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_digest *digest_info = NULL;

	hash_table_index = whitelist_hash_key(hash_str, path);

	read_lock(&whitelist_hashtable_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_safe(digest_info, node, next, whitelist_hashtable + hash_table_index, list)
#else
	hlist_for_each_entry_safe(digest_info, node, whitelist_hashtable + hash_table_index, list)
#endif
	{
		if ((strncmp(digest_info->digest, hash_str, LEN_HASH)==0) &&
			(strcmp(digest_info->name, path)==0)) {
			ret = 0;
			goto out;
		}
	}

out:
	read_unlock(&whitelist_hashtable_lock);
	return ret;
}

int query_process_identity_lib_hash(const char *hash_str, int len)
{
	return query_hash(hash_str, len);
}
EXPORT_SYMBOL(query_process_identity_lib_hash);


/* measure_file and match_file interface */
int tsb_measure_file(const char *path)
{
	struct file *file;

	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"whitelist file open error!\n");
		return TSB_ERROR_FILE;
	}

	return tsb_measure_file_filp(file);
}

int tsb_measure_file_filp(struct file *filp)
{
	int ret = 0;
	char file_digest[LEN_HASH] = { 0 };

	ret = digest_cal(filp, file_digest, LEN_HASH);
	if (ret < 0)
		return TSB_ERROR_CALC_HASH;

	ret = query_hash(file_digest, LEN_HASH);
	if (ret)
		return TSB_MEASURE_FAILE;

	return 0;
}
EXPORT_SYMBOL(tsb_measure_file_filp);

int tsb_measure_file_path(const char *path)
{
	struct file *file;
	int ret = 0;
	char file_digest[LEN_HASH] = { 0 };

	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"whitelist file open error!\n");
		return TSB_ERROR_FILE;
	}

	ret = digest_cal(file, file_digest, LEN_HASH);
	if (ret < 0)
		return TSB_ERROR_CALC_HASH;

	ret = query_hash_and_path(file_digest, LEN_HASH, path);
	if (ret)
		return TSB_MEASURE_FAILE;

	return 0;
}

int tsb_measure_file_path_filp(struct file *filp)
{
	int ret = 0;
	char file_digest[LEN_HASH] = { 0 };
	char *path = NULL, *pathname;

	pathname = kzalloc(PATH_MAX + 11, GFP_KERNEL);
	if (!pathname)
		return TSB_ERROR_SYSTEM;

	path = d_path(&filp->f_path, pathname, PATH_MAX + 11);
	if (IS_ERR(path)) {
		ret = TSB_ERROR_SYSTEM;
		goto out;
	}

	ret = digest_cal(filp, file_digest, LEN_HASH);
	if (ret < 0)
	{
		ret = TSB_ERROR_CALC_HASH;
		goto out;
	}

	ret = query_hash_and_path(file_digest, LEN_HASH, path);
	if (ret)
	{	
		ret = TSB_MEASURE_FAILE;
		goto out;
	}

out:
	if(pathname)
		kfree(pathname);

	return ret;
}
EXPORT_SYMBOL(tsb_measure_file_path_filp);

int tsb_measure_file_specific_path_filp(const char *path,struct file *filp)
{
	int ret = 0;
	char file_digest[LEN_HASH] = { 0 };

	ret = digest_cal(filp, file_digest, LEN_HASH);
	if (ret < 0)
		return TSB_ERROR_CALC_HASH;

	ret = query_hash_and_path(file_digest, LEN_HASH, path);
	if (ret)
		return TSB_MEASURE_FAILE;

	return 0;
}
EXPORT_SYMBOL(tsb_measure_file_specific_path_filp);

int tsb_match_file_integrity(const unsigned char *hash, int hash_length)
{
	int ret = 0;
	ret = query_hash(hash, hash_length);
	if (ret)
		return TSB_MEASURE_FAILE;

	return ret;
}
EXPORT_SYMBOL(tsb_match_file_integrity);

int tsb_match_file_integrity_by_path(const unsigned char *hash, int hash_length, const unsigned char *path, int path_length)
{
	int ret = 0;
	ret = query_hash_and_path(hash, hash_length, path);
	if (ret)
		return TSB_MEASURE_FAILE;

	return ret;
}
EXPORT_SYMBOL(tsb_match_file_integrity_by_path);


long ioctl_whitelist_user_interface(unsigned long param)
{
	struct tsb_user_interface_parameter parameter;
	int ret = 0, hash_len=0, path_len=0, len=0;
	char path[512] = {0};
	unsigned char hash[LEN_HASH] = {0};
	char *p_buff = NULL;

	ret =copy_from_user(&parameter, (void *)param, sizeof(parameter));
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user user interface data error! ret[%d] length[%d]\n", __func__, ret, parameter.length);
		return -1;
	}

	switch (parameter.type) {
	case TYPE_WHITELIST_MEASURE_FILE:
		ret =copy_from_user(path, parameter.data, parameter.length);
		if (ret) 
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user user interface data failed!\n", __func__);
			return TSB_ERROR_SYSTEM;
		}

		ret = tsb_measure_file(path);
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], parameter.type[%d] whitelist measure_file[%s], ret[%d]\n", __func__, parameter.type, path, ret);
		break;
	case TYPE_WHITELIST_MEASURE_FILE_PATH:
		ret =copy_from_user(path, parameter.data, parameter.length);
		if (ret) 
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user user interface data failed!\n", __func__);
			return TSB_ERROR_SYSTEM;
		}

		ret = tsb_measure_file_path(path);
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], parameter.type[%d] whitelist measure_file_path[%s], ret[%d]\n", __func__, parameter.type, path, ret);
		break;
	case TYPE_WHITELIST_MATCH_FILE:
		ret =copy_from_user(hash, parameter.data, LEN_HASH);
		if (ret) 
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user user interface data failed!\n", __func__);
			return TSB_ERROR_SYSTEM;
		}

		ret = tsb_match_file_integrity(hash, LEN_HASH);
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], parameter.type[%d] whitelist match_file hash, ret[%d]\n", __func__, parameter.type, ret);
		break;
	case TYPE_WHITELIST_MATCH_FILE_PATH:
		p_buff = vmalloc(parameter.length);
		if (!p_buff)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc error! user interface data length[%d]\n", __func__, parameter.length);
			return TSB_ERROR_SYSTEM;
		}

		ret =copy_from_user(p_buff, parameter.data, parameter.length);
		if (ret) 
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user user interface data failed!\n", __func__);
			return TSB_ERROR_SYSTEM;
		}

		memcpy(&hash_len, p_buff, sizeof(int));
		len = sizeof(int);
		memcpy(hash, p_buff+len, hash_len);
		len += hash_len;
		memcpy(&path_len, p_buff+len, sizeof(int));
		len += sizeof(int);
		memcpy(path, p_buff+len, path_len);

		ret = tsb_match_file_integrity_by_path(hash, LEN_HASH, path, path_len);
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], parameter.type[%d] whitelist match_file hash path, ret[%d]\n", __func__, parameter.type, ret);
		break;
	default:
		ret = TSB_MEASURE_FAILE;
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], parameter.type[%d] error!\n", __func__, parameter.type);
		break;
	}

	return ret;
}
