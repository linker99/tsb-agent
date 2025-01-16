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

#include "hash_whitelist_path.h"
#include "sec_domain.h"
#include "utils/debug.h"
#include "utils/klib_fileio.h"
#include "msg/command.h"
#include "../smeasure/policy/policy_whitelist_cache.h"
#include "list_fac.h"


static struct hlist_head *whitelist_path_hashtable = NULL;
static rwlock_t whitelist_path_hashtable_lock;
static atomic_t whitelist_path_obj_count;
static unsigned int whitelist_path_hash_random;

/*
static void print_hex(const char *name, unsigned char *p, int len)
{
	int i = 0;

	printk("name[%s] p[%p] len[%d]\n", name, p, len);
	for (i = 0; i < len; i++) {
		printk("%02X", p[i]);
	}
	printk("\n");
}
*/

static inline unsigned string_hash_key(unsigned int random, const __u8 * p, int n)
{
	return jhash(p, n, random) & HASH_TAB_MASK;
}

static int whitelist_path_hash_key(const char *path, int len)
{
	return string_hash_key(whitelist_path_hash_random, path, len);
}

int query_whitelist_path(struct sec_domain *sec_d, int is_file_open)
{
	int ret = -1;
	unsigned hash_table_index;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_path *w_path_bak = NULL;
	unsigned char hash[LEN_HASH] = {0};

	hash_table_index = whitelist_path_hash_key(sec_d->obj_name, strlen(sec_d->obj_name));
	
	read_lock(&whitelist_path_hashtable_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_safe(w_path_bak, node, next, whitelist_path_hashtable + hash_table_index, list) {
#else
	hlist_for_each_entry_safe(w_path_bak, node, whitelist_path_hashtable + hash_table_index, list) {
#endif
		if (strcmp(w_path_bak->path, sec_d->obj_name) == 0) {
			ret = 0;
			goto out;
		}
	}

out:
	read_unlock(&whitelist_path_hashtable_lock);

	if(ret==0) {
		//¼ÆËãÖ÷Ìåhash
		if(calc_sub_hash(sec_d->sub_name, hash, is_file_open)<0)
			DEBUG_MSG(HTTC_TSB_INFO, "[%s], calc_sub_hash err pass!\n", __func__);
		else
			memcpy(sec_d->sub_hash, hash, LEN_HASH);
	}

	return ret;
}
EXPORT_SYMBOL(query_whitelist_path);

int whitelist_path_tmp_add(struct hlist_head *whitelist_path_hashtable_tmp, int *whitelist_path_num, char *path)
{
	int len = 0;
	unsigned hash_table_index;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_path *w_path_bak = NULL;

	//len = sizeof(struct whitelist_digest) + strlen(path) + 1;
	struct whitelist_path *  w_path = kzalloc(sizeof(struct whitelist_path), GFP_KERNEL);
	if (!w_path) {
		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc error!\n");
		return -ENOMEM;
	}

	if((strlen(path)+1) > PATH_LEN) {
		len = PATH_LEN-1;
		DEBUG_MSG(HTTC_TSB_INFO, "path[%s] beyond length!\n", path);
	}
	else {
		len = strlen(path);
	}
	memcpy(w_path->path, path, len);

	hash_table_index = whitelist_path_hash_key(path, len);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_safe(w_path_bak, node, next, whitelist_path_hashtable_tmp + hash_table_index, list)
#else
	hlist_for_each_entry_safe(w_path_bak, node, whitelist_path_hashtable_tmp + hash_table_index, list)
#endif
	{
		if (strcmp(w_path_bak->path, path)==0) {
			DEBUG_MSG(HTTC_TSB_INFO, "path %s already exsit!\n", path);
			kfree(w_path);
			return -EEXIST;
		}
	}

	hlist_add_head(&w_path->list, whitelist_path_hashtable_tmp + hash_table_index);
	(*whitelist_path_num)++;

	return 0;
}

void whitelist_path_tmp_clean(struct hlist_head *whitelist_path_hashtable_tmp, int whitelist_path_num_tmp)
{
	int idx;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_path *w_path_bak = NULL;

flush_again:
	for (idx = 0; idx < HASH_TAB_SIZE; idx++) 
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
		hlist_for_each_entry_safe(w_path_bak, node, next, whitelist_path_hashtable_tmp + idx, list)
#else
		hlist_for_each_entry_safe(w_path_bak, node, whitelist_path_hashtable_tmp + idx, list)
#endif
		{
			hlist_del(&w_path_bak->list);
			kfree(w_path_bak);
			whitelist_path_num_tmp--;
		}
	}

	if (whitelist_path_num_tmp != 0) {
		schedule();
		DEBUG_MSG(HTTC_TSB_INFO, "whitelist_path_num_tmp[%d], whitelist clean error!", whitelist_path_num_tmp);
		goto flush_again;
	}
}

static int load_whitelist_path(void)
{
	int ret = -1;
	char *buff = NULL;
	struct file *file;
	char path[PATH_LEN] = {0};
	char file_path[128] = {0};

	int len=0;
	int file_whitelist_path_num=0, whitelist_path_num=0, whitelist_path_num_tmp=0, idx=0;
	struct hlist_head *whitelist_path_hashtable_tmp=NULL, *hashtable_tmp=NULL;

	snprintf(file_path, 128, "%s%s", BASE_PATH, "conf/path.whitelist");
	file = filp_open(file_path, O_RDONLY, 0);
	if (IS_ERR(file))
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], whitelist_path file open error!\n", __func__);
		return ret;
	}

	if (!(buff = vmalloc(1024)))
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc error!\n",__func__);
		ret = -ENOMEM;
		goto out;
	}

	if (!(whitelist_path_hashtable_tmp = vmalloc(HASH_TAB_SIZE * sizeof(struct hlist_head))))
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc whitelist_path_hashtable error!\n",__func__);
		ret = -ENOMEM;
		goto out;
	}
	for (idx = 0; idx < HASH_TAB_SIZE; idx++) {
		INIT_HLIST_HEAD(&(whitelist_path_hashtable_tmp[idx]));
	}
	whitelist_path_num_tmp = atomic_read(&whitelist_path_obj_count);

	while(klib_fgets(buff, 1024, file)) {
	//while(klib_fgets_enc(buff, 1024, file)) {
		buff[strlen(buff)-1] = '\0';

		if((strlen(buff)+1) > PATH_LEN) {
			len = PATH_LEN-1;
			DEBUG_MSG(HTTC_TSB_INFO, "path[%s] beyond length!\n", path);
		}
		else {
			len = strlen(buff)+1;
		}
		memcpy(path, buff, len);
		//printk("------------buff:%s--[%lu]----------\n", buff, strlen(buff));

		whitelist_path_tmp_add(whitelist_path_hashtable_tmp, &whitelist_path_num, path);
		file_whitelist_path_num++;

		memset(path, 0, PATH_LEN);
		memset(buff, 0, 1024);
	}

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s],  add fac whitelist_path file_whitelist_path_num[%d] whitelist_path_num[%d] success\n", __func__, file_whitelist_path_num, whitelist_path_num);

	write_lock(&whitelist_path_hashtable_lock);
	hashtable_tmp = whitelist_path_hashtable;
	whitelist_path_hashtable = whitelist_path_hashtable_tmp;
	whitelist_path_hashtable_tmp = hashtable_tmp;
	atomic_set(&whitelist_path_obj_count, whitelist_path_num);
	write_unlock(&whitelist_path_hashtable_lock);

	whitelist_path_tmp_clean(whitelist_path_hashtable_tmp, whitelist_path_num_tmp);
	vfree(whitelist_path_hashtable_tmp);

	ret = 0;

out:
	if(file != NULL)
		filp_close(file, NULL);
	if(buff)
		vfree(buff);

	return ret; 
}
/*
int fac_whitelist_path_add(char *full_path)
{
	int len = 0;
	struct whitelist_path *w_path = NULL;
	unsigned hash_table_index;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_path *w_path_bak = NULL;

	len = (strlen(full_path) < PATH_LEN) ? strlen(full_path) : PATH_LEN;

	hash_table_index = whitelist_path_hash_key(full_path, len);

	read_lock(&whitelist_path_hashtable_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_safe(w_path_bak, node, next, whitelist_path_hashtable + hash_table_index, list) {
#else
	hlist_for_each_entry_safe(w_path_bak, node, whitelist_path_hashtable + hash_table_index, list) {
#endif
		if (strcmp(w_path_bak->path, full_path)==0) {
			DEBUG_MSG(HTTC_TSB_INFO, "path %s already exsit!\n", full_path);
			read_unlock(&whitelist_path_hashtable_lock);
			goto out;
		}
	}
	read_unlock(&whitelist_path_hashtable_lock);

	w_path = kzalloc(sizeof(struct whitelist_path), GFP_KERNEL);
	if (!w_path) {
		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc error!\n");
		goto out;
	}
	memcpy(w_path->path, full_path, len);

	write_lock(&whitelist_path_hashtable_lock);
	hlist_add_head(&w_path->list, whitelist_path_hashtable + hash_table_index);
	atomic_inc(&whitelist_path_obj_count);
	write_unlock(&whitelist_path_hashtable_lock);

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s],  add fac whitelist_path [%s] success\n", __func__, w_path->path);

out:
	return 0;
}
*/

long ioctl_fac_whitelist_path_del_policy(unsigned long param)
{
	struct tsb_general_policy general_policy;
	char *p_buff = NULL;

	int len = 0;
	unsigned hash_table_index;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_path *w_path_bak = NULL;

	int ret =copy_from_user(&general_policy, (void *)param, sizeof(general_policy));
	if (ret || !general_policy.length) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user fac whitelist_path policy error! ret[%d] policy length[%d]\n", __func__, ret, general_policy.length);
		return -1;
	}

	p_buff = vmalloc(general_policy.length);
	if (!p_buff)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc error! fac whitelist_path policy length[%d]\n", __func__, general_policy.length);
		return -1;
	}

	ret =copy_from_user(p_buff, general_policy.data, general_policy.length);
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user fac whitelist_path policy failed!\n", __func__);
		vfree(p_buff);
		return -1;
	}

	if(general_policy.length > PATH_LEN) {
		len = PATH_LEN-1;
		DEBUG_MSG(HTTC_TSB_INFO, "path[%s] beyond length!\n", p_buff);
	}
	else {
		len = strlen(p_buff);
	}

	hash_table_index = whitelist_path_hash_key(p_buff, len);

	write_lock(&whitelist_path_hashtable_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_safe(w_path_bak, node, next, whitelist_path_hashtable + hash_table_index, list)
#else
	hlist_for_each_entry_safe(w_path_bak, node, whitelist_path_hashtable + hash_table_index, list)
#endif
	{
		if (strcmp(w_path_bak->path, p_buff)==0) 
		{
			hlist_del(&w_path_bak->list);
			kfree(w_path_bak);
			atomic_dec(&whitelist_path_obj_count);
			write_unlock(&whitelist_path_hashtable_lock);
			policy_whitelist_cache_clean();
			DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s],  del fac whitelist_path[%s] success\n", __func__, p_buff);
			goto out;
		}
	}
	write_unlock(&whitelist_path_hashtable_lock);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s],  fac whitelist_path[%s] not exist!\n", __func__, p_buff);

out:
	vfree(p_buff);
	return 0;
}

long ioctl_fac_whitelist_path_add_policy(unsigned long param)
{
	struct tsb_general_policy general_policy;
	char *p_buff = NULL;

	int len = 0;
	struct whitelist_path *w_path = NULL;
	unsigned hash_table_index;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_path *w_path_bak = NULL;

	int ret =copy_from_user(&general_policy, (void *)param, sizeof(general_policy));
	if (ret || !general_policy.length) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user fac whitelist_path policy error! ret[%d] policy length[%d]\n", __func__, ret, general_policy.length);
		return -1;
	}

	p_buff = vmalloc(general_policy.length);
	if (!p_buff)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc error! fac whitelist_path policy length[%d]\n", __func__, general_policy.length);
		return -1;
	}

	ret =copy_from_user(p_buff, general_policy.data, general_policy.length);
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user fac whitelist_path policy failed!\n", __func__);
		vfree(p_buff);
		return -1;
	}

	if(general_policy.length > PATH_LEN) {
		len = PATH_LEN-1;
		DEBUG_MSG(HTTC_TSB_INFO, "path[%s] beyond length!\n", p_buff);
	}
	else {
		len = strlen(p_buff);
	}

	hash_table_index = whitelist_path_hash_key(p_buff, len);

	read_lock(&whitelist_path_hashtable_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_safe(w_path_bak, node, next, whitelist_path_hashtable + hash_table_index, list) {
#else
	hlist_for_each_entry_safe(w_path_bak, node, whitelist_path_hashtable + hash_table_index, list) {
#endif
		if (strcmp(w_path_bak->path, p_buff)==0) {
			DEBUG_MSG(HTTC_TSB_INFO, "path %s already exsit!\n", p_buff);
			read_unlock(&whitelist_path_hashtable_lock);
			goto out;
		}
	}
	read_unlock(&whitelist_path_hashtable_lock);

	w_path = kzalloc(sizeof(struct whitelist_path), GFP_KERNEL);
	if (!w_path) {
		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc error!\n");
		goto out;
	}
	memcpy(w_path->path, p_buff, len);

	write_lock(&whitelist_path_hashtable_lock);
	hlist_add_head(&w_path->list, whitelist_path_hashtable + hash_table_index);
	atomic_inc(&whitelist_path_obj_count);
	write_unlock(&whitelist_path_hashtable_lock);

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s],  add fac whitelist_path [%s] success\n", __func__, w_path->path);
out:
	vfree(p_buff);
	return 0;
}

long ioctl_fac_whitelist_path_reload_policy(unsigned long param)
{
	int count;

	policy_whitelist_cache_clean();

	count = atomic_read(&whitelist_path_obj_count);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Hash fac whitelist_path mod remove [%d]\n", count);

	load_whitelist_path();
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s],  reload fac whitelist_path policy success!\n", __func__);

	return 0;
}

int whitelist_path_init()
{
	int idx;
	/*allocte hash table */
	if (!(whitelist_path_hashtable = vmalloc(HASH_TAB_SIZE * sizeof(struct hlist_head))))
		return -ENOMEM;

	/*init hash tab */
	for (idx = 0; idx < HASH_TAB_SIZE; idx++) {
		INIT_HLIST_HEAD(&(whitelist_path_hashtable[idx]));
	}

	rwlock_init(&whitelist_path_hashtable_lock);
	atomic_set(&whitelist_path_obj_count, 0);

	/*generate random */
	get_random_bytes(&whitelist_path_hash_random, sizeof(whitelist_path_hash_random));

	load_whitelist_path();

	if (httcsec_io_command_register(COMMAND_ADD_FAC_WHITELIST_PATH_POLICY, (httcsec_io_command_func)ioctl_fac_whitelist_path_add_policy)) {
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n", COMMAND_ADD_FAC_WHITELIST_PATH_POLICY);
	}
	if (httcsec_io_command_register(COMMAND_DELETE_FAC_WHITELIST_PATH_POLICY, (httcsec_io_command_func)ioctl_fac_whitelist_path_del_policy)) {
		DEBUG_MSG(HTTC_TSB_INFO, "Command NR duplicated %d.\n", COMMAND_DELETE_FAC_WHITELIST_PATH_POLICY);
	}
	if (httcsec_io_command_register(COMMAND_RELOAD_FAC_WHITELIST_PATH_POLICY, (httcsec_io_command_func)ioctl_fac_whitelist_path_reload_policy)) {
		DEBUG_MSG(HTTC_TSB_INFO, "Command NR duplicated %d.\n", COMMAND_RELOAD_FAC_WHITELIST_PATH_POLICY);
	}

	return 0;
}

void whitelist_path_exit()
{
	int idx;
	struct hlist_node *node = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *next = NULL;
#endif
	struct whitelist_path *w_path_bak = NULL;

	int count = atomic_read(&whitelist_path_obj_count);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Hash fac whitelist_path mod remove [%d]\n", count);

	httcsec_io_command_unregister(COMMAND_ADD_FAC_WHITELIST_PATH_POLICY, (httcsec_io_command_func)ioctl_fac_whitelist_path_add_policy);
	httcsec_io_command_unregister(COMMAND_DELETE_FAC_WHITELIST_PATH_POLICY, (httcsec_io_command_func)ioctl_fac_whitelist_path_del_policy);
	httcsec_io_command_unregister(COMMAND_RELOAD_FAC_WHITELIST_PATH_POLICY, (httcsec_io_command_func)ioctl_fac_whitelist_path_reload_policy);

flush_again:
	write_lock(&whitelist_path_hashtable_lock);
	for (idx = 0; idx < HASH_TAB_SIZE; idx++) 
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
		hlist_for_each_entry_safe(w_path_bak, node, next, whitelist_path_hashtable + idx, list)
#else
		hlist_for_each_entry_safe(w_path_bak, node, whitelist_path_hashtable + idx, list)
#endif
		{
			hlist_del(&w_path_bak->list);
			kfree(w_path_bak);
			atomic_dec(&whitelist_path_obj_count);
		}
	}
	write_unlock(&whitelist_path_hashtable_lock);

	if (atomic_read(&whitelist_path_obj_count) != 0) {
		schedule();
		DEBUG_MSG(HTTC_TSB_INFO,"obj_count[%d], fac whitelist_path clean error!", atomic_read(&whitelist_path_obj_count));
		goto flush_again;
	}

	vfree(whitelist_path_hashtable);
}
