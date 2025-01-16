#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/jhash.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/uaccess.h>

#include "log.h"
#include "log_impl.h"
#include "../msg/command.h"
#include "../utils/klib_fileio.h"
#include "../utils/debug.h"
#include "common.h"
#include "../tpcm/tpcmif.h"
#include "../policy/log_config_policy.h"
#include "tsbapi/tsb_log_notice.h"

const char * CATEGORY_NAMES[] = {
		0,"Measure","Control","System","Other"
};

const char * TYPE_NAMES[] = {
		0,"Intercept","Timer","Auth","Other"
};

const char * ACTION_NAMES[] = {
		0,"Exec","Read","Write","Send","Receive","Device","Schedule","Other"
};

const char * RESULT_NAMES[] = {
		"Reject","Pass","Other"
};
const char * LEVEL_NAMES[] = {
		0,"Debug","Normal","Warning","Fatal"
};

const char * MEASURE_TARGET_TYPE_NAMES[] = {
		0,"File","Network","Device","Kernel","Module","KData","Process","Lib","PData","Other"
};

#define DEFAULT_HASH_LEN 1024

static struct log_buffer log_buf;
static  struct hlist_head hastables[DEFAULT_HASH_LEN + DEFAULT_HASH_LEN];

struct log_data
{
	int repeats;
	long long time;
	unsigned long id;
	int length;
	struct list_head node;
	struct hlist_node hnode;
	char data[];
};

struct audit_msg 
{
	unsigned int magic;
	unsigned int type;
	unsigned int operate;
	unsigned int result;
	unsigned int user;
	int pid;
	int repeat_num;
	long time;
	int total_len;
	int len_sub;
	int len_obj;
	char sub_hash[LEN_HASH];
	char data[0];
} __attribute__ ((packed));

struct log_memory{
	struct list_head list;
	int len;
	char data[0];
};
LIST_HEAD(g_list_log_memory);
//static int log_memory_number;
atomic_t log_sum;
wait_queue_head_t log_queue;

static struct file *log_file  = NULL;
static DEFINE_MUTEX(log_file_mutex);
static int stopped;
//#define LOG_FILE "/usr/local/httcsec/tsb/tsb.log"
static int switch_log_file(void)
{
#ifdef LOG_MEM
	return 0;
#else
	int r = 0;
	static struct file *file;
	char log_path[128] = {0};

	snprintf(log_path, 128, "%s%s", BASE_PATH, "log/tsb.log");

	DEBUG_MSG(HTTC_TSB_DEBUG, "Call switch_log_file path %s\n", log_path);
	mutex_lock(&log_file_mutex);
	if(log_file)
    		filp_close(log_file,0);

	if(!stopped)
	{
		file = filp_open(log_path, O_RDWR | O_CREAT | O_APPEND , 0600);
		DEBUG_MSG(HTTC_TSB_DEBUG,"File %p.\n",file);
		if(IS_ERR(file))
		{
			r = PTR_ERR(file);
			if(!r)r = -1;
			log_file = 0;
			DEBUG_MSG(HTTC_TSB_INFO,"Open log write file failed.\n");
		}
		else
		{
			log_file =  file;
		}
	}
	mutex_unlock(&log_file_mutex);
	return r;
#endif
}

static const char * FORMAT = "%lld;%s;%s;%s;%s;" /* 日期,类别,类型;模块;来源 */
		"%s;%s;%s;"			/* 行为,结果,级别 */
		"%s;%s;%u;%u;"			/* 进程名称,路径，PID,UID */
		"%s;%s;%s;"			/* 客体,度量函数名,度量目标类型, */
		"%s;%s;%s;";			/* 度量目标,内容，消息 */
		/* "%lu";*/ /* 顺序号, */
static struct log_data *log_create(const struct long_param *param)
{
	struct log_data *buffer = kmalloc(PAGE_SIZE,GFP_KERNEL);
	if(!buffer)
		return 0;

	buffer->repeats = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
		buffer->time =ktime_get_real_seconds();
#else

	buffer->time = get_seconds();
#endif
	buffer->id = 0;
	
	buffer->length = snprintf(buffer->data,PAGE_SIZE - sizeof(struct log_data),FORMAT,
				buffer->time,CATEGORY_NAMES[param->category],
				TYPE_NAMES[param->type],param->module,param->source,
				ACTION_NAMES[param->action],RESULT_NAMES[param->result],LEVEL_NAMES[param->level],
				current->comm,param->exec,current_uid(),task_pid_nr(current),
				param->object,param->measure_name,MEASURE_TARGET_TYPE_NAMES[param->measure_target_type],
				param->measure_target,param->measure_content,param->message);
	return buffer;
}

static inline int hash_func(const void *data, int size)
{
	return jhash(data, size, 0) % DEFAULT_HASH_LEN;
}

struct log_data * log_get_existed(struct log_data *data,int hash)
{
	struct log_data *tpos;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *node;
	hlist_for_each_entry(tpos, node, log_buf.cache_hash + hash, hnode)
#else
	hlist_for_each_entry(tpos, log_buf.cache_hash + hash, hnode)
#endif
	{
		if(tpos->time == data->time
		&& tpos->length == data->length
		&& !memcmp(data->data,tpos->data,tpos->length))
		{
			return tpos;
		}
	}
	return 0;
}

static int log_cache_clean(void)
{	
	int i;
	long long curtime;
	struct hlist_node *hpos,*hn;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
        curtime =ktime_get_real_seconds();
#else
	curtime = get_seconds();
#endif
	for(i=0; i < WORKING_HASH_SIZE; i++)
	{
		hlist_for_each_safe(hpos,hn,log_buf.cache_hash + i)
		{
			struct log_data *plog;
			plog = container_of(hpos, struct log_data, hnode);
			if((curtime - plog->time) > 2)   /* clear cached data 2 seconds ago */
			{
				hlist_del(hpos);
				list_del(&plog->node);
				log_buf.cache_number--;
				kfree(plog);	
			}
		}
	}
	return 0;
}

static int add_log_cache(struct log_data *data, struct log_data *new_data, int hash)
{
	if ( data == NULL )
	{
		kfree(new_data);
		return -1;
	}

        memcpy(new_data, data, sizeof(struct log_data)+data->length);

	log_buf.cache_number++;
	hlist_add_head( &new_data->hnode, log_buf.cache_hash + hash );
	list_add_tail( &new_data->node, &log_buf.log_cache );
	return 0;
}

static unsigned long cur_log_id = 1;
static int log_out_buffer(struct log_data *data)
{
	int hash;
	struct log_data *existed = NULL;
	struct log_data *new_data = NULL;
	hash = hash_func(data->data, data->length);

	if ( data->length > 4096 )
		return -1;

        new_data = kzalloc( sizeof(struct log_data) + data->length, GFP_ATOMIC );
        if ( new_data == NULL )
                return -1;

	log_lock(&log_buf);
	if(!stopped)
	{
		existed  = log_get_existed(data,hash);
		if(existed)
		{
			existed->repeats++;
			kfree(new_data);
			kfree(data);
		}
		else
		{
			add_log_cache(data, new_data, hash);
			data->id = cur_log_id++;
			log_buf.working_number++;
			list_add_tail(&data->node,&log_buf.working);
			wake_up(&log_buf.log_event);

			if(log_buf.cache_number > CACHE_MAX_NUM )
				log_cache_clean();
		}
	}
	else
	{
		kfree(new_data);
	}

	log_unlock(&log_buf);
	return 0;
}

#ifndef LOG_MEM
static int write_log(struct list_head *p)
{
	struct log_data *log;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	loff_t pos=0;
#endif
	log = list_entry(p,struct log_data,node);
	DEBUG_MSG(HTTC_TSB_DEBUG,"call write log len[%d]\n",log->length);
	mutex_lock(&log_file_mutex);
	if(!stopped && log_file)
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
		kernel_write(log_file, log->data, log->length, &pos);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
		kernel_write(log_file, log->data, log->length, 0);
#else
		klib_fwrite(log->data, log->length, log_file);
#endif
	}
	mutex_unlock(&log_file_mutex);
	return 0;
}
#endif

static int free_log_data(struct list_head *p)
{
	struct log_data *log = list_entry(p,struct log_data,node);
	kfree(log);
	return 0;
}

#ifdef LOG_MEM
static int write_log_to_memory(struct list_head *p)
{
	struct log_data *log;
	struct log_memory *log_m = NULL;
	struct log_memory *list_log_memory_node = NULL;

	log = list_entry(p,struct log_data,node);
	DEBUG_MSG(HTTC_TSB_DEBUG,"call write log to memory len[%d]\n",log->length);

	if(!stopped)
	{
		log_m = kzalloc(sizeof(struct log_memory)+log->length, GFP_KERNEL);
		if (log_m == NULL)
			return -1;
		log_m->len = log->length;
		memcpy(log_m->data, log->data, log->length);

		mutex_lock(&log_file_mutex);
		atomic_inc(&log_sum);
		if (atomic_read(&log_sum) > 10000)
		{
			//struct audit_msg *p = NULL;
			list_log_memory_node = list_first_entry(&g_list_log_memory, struct log_memory, list);
			//p = (struct audit_msg*)list_log_memory_node->data;
			DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], memory log num>10000, delete one log\n", __func__);

			list_del(&list_log_memory_node->list);
			kfree(list_log_memory_node);
			list_log_memory_node = NULL;
			atomic_dec(&log_sum);
		}
		list_add_tail(&log_m->list, &g_list_log_memory);
		wake_up(&log_queue);
		mutex_unlock(&log_file_mutex);
	}

	return 0;
}

static void clear_mem_log(void)
{
	struct log_memory *list_log_memory_node = NULL, *list_log_memory_node_tmp = NULL;

	//mutex_lock(&log_file_mutex);
	list_for_each_entry_safe(list_log_memory_node, list_log_memory_node_tmp, &g_list_log_memory, list)
	{
		atomic_dec(&log_sum);

		list_del(&list_log_memory_node->list);
		kfree(list_log_memory_node);
		list_log_memory_node = NULL;
	}
	//mutex_unlock(&log_file_mutex);
}
#endif

static long ioctl_tsb_read_inmem_log(unsigned long param)
{
	int ret = 0;
	int data_len=0, hasmore=0, user_buf_len=0;
	struct tsb_user_read_memory_log_parameter parameter;
	struct log_memory *list_log_memory_node = NULL, *list_log_memory_node_tmp = NULL;

	ret = wait_event_interruptible(log_queue, (atomic_read(&log_sum) > 0));
	if (ret == -ERESTARTSYS)
		return -ERESTARTSYS;

	ret = copy_from_user(&parameter, (void *)param, sizeof(parameter));
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_to_user tsb log param failed!\n", __func__);
		return -1;
	}
	ret = copy_from_user(&user_buf_len, parameter.length, sizeof(user_buf_len));
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user tsb log user_buf_len failed!\n", __func__);
		return -1;
	}

	mutex_lock(&log_file_mutex);
	list_for_each_entry_safe(list_log_memory_node, list_log_memory_node_tmp, &g_list_log_memory, list)
	{
		if (user_buf_len < (data_len+list_log_memory_node->len))
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], user log buffer len[%d], smaller read log len[%d] and next log len[%d], read complete\n", __func__, user_buf_len, data_len, list_log_memory_node->len);
			hasmore = 1;
			break;
		}
		
		ret = copy_to_user((char *)parameter.data+data_len, list_log_memory_node->data, list_log_memory_node->len);
		if ( ret )
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_to_user tsb log data failed!\n", __func__);
			mutex_unlock(&log_file_mutex);
			return -1;
		}

		data_len += list_log_memory_node->len;
		atomic_dec(&log_sum);

		list_del(&list_log_memory_node->list);
		kfree(list_log_memory_node);
		list_log_memory_node = NULL;
	}
	mutex_unlock(&log_file_mutex);

	ret = copy_to_user((void *)parameter.length, &data_len, sizeof(data_len));
	if ( ret )
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_to_user tsb log length failed!\n", __func__);
		return -1;
	}
	ret = copy_to_user((void *)parameter.hasmore, &hasmore, sizeof(hasmore));
	if ( ret )
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_to_user tsb log hasmore failed!\n", __func__);
		return -1;
	}

	return ret;
}

static long ioctl_tsb_read_inmem_log_nonblock(unsigned long param)
{
	int ret = 0;
	int data_len=0, hasmore=0, user_buf_len=0;
	struct tsb_user_read_memory_log_parameter parameter;
	struct log_memory *list_log_memory_node = NULL, *list_log_memory_node_tmp = NULL;

	ret = copy_from_user(&parameter, (void *)param, sizeof(parameter));
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user tsb log param failed!\n", __func__);
		return -1;
	}
	ret = copy_from_user(&user_buf_len, parameter.length, sizeof(user_buf_len));
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user tsb log user_buf_len failed!\n", __func__);
		return -1;
	}

	if (atomic_read(&log_sum) <= 0)
	{
		ret = copy_to_user((void *)parameter.length, &data_len, sizeof(data_len));
		if ( ret )
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_to_user tsb log length failed!\n", __func__);
			return -1;
		}
		ret = copy_to_user((void *)parameter.hasmore, &hasmore, sizeof(hasmore));
		if ( ret )
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_to_user tsb log hasmore failed!\n", __func__);
			return -1;
		}
		return 0;
	}

	mutex_lock(&log_file_mutex);
	list_for_each_entry_safe(list_log_memory_node, list_log_memory_node_tmp, &g_list_log_memory, list)
	{
		if (user_buf_len < (data_len+list_log_memory_node->len))
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], user log buffer len[%d], smaller read log len[%d] and next log len[%d], read complete\n", __func__, user_buf_len, data_len, list_log_memory_node->len);
			hasmore = 1;
			break;
		}

		ret = copy_to_user((char*)parameter.data+data_len, list_log_memory_node->data, list_log_memory_node->len);
		if ( ret )
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_to_user tsb log data failed!\n", __func__);
			mutex_unlock(&log_file_mutex);
			return -1;
		}

		data_len += list_log_memory_node->len;
		atomic_dec(&log_sum);

		list_del(&list_log_memory_node->list);
		kfree(list_log_memory_node);
		list_log_memory_node = NULL;
	}
	mutex_unlock(&log_file_mutex);

	ret = copy_to_user((void *)parameter.length, &data_len, sizeof(data_len));
	if ( ret )
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_to_user tsb log length failed!\n", __func__);
		return -1;
	}
	ret = copy_to_user((void *)parameter.hasmore, &hasmore, sizeof(hasmore));
	if ( ret )
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_to_user tsb log hasmore failed!\n", __func__);
		return -1;
	}

	return ret;
}


int log_out(const struct long_param *param)
{
	struct log_data *data = 0;

	if(stopped)
		return 0;

	data = log_create(param);
	if(!data)
	{
		DEBUG_MSG(HTTC_TSB_INFO,"log failed!\n");
		return -1;
	}
	else
	{
		return log_out_buffer(data);
	}
	return  0;
}
EXPORT_SYMBOL(log_out);

int keraudit_log(int type, int operate, int result, struct sec_domain *sec_d, unsigned int user, int pid)
{
	struct log_data *data = NULL;
	char *p = NULL;
	struct audit_msg *p_log_msg = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	struct timespec64 ts;
#else
	struct timeval ts;
#endif
	int ret = 0;
	int len_sub = 0;
	int len_obj = 0;
	int total_len = 0;

	if(stopped)
		return 0;

	/* 动态度量失败时，需要改变可信状态 */
	if ((type==TYPE_DMEASURE) && (result==RESULT_FAIL))
		sync_trust_status(0);
	
	ret = get_log_config_policy(type, result, sec_d);
	if (ret == 0) 
	{
		//DEBUG_MSG(HTTC_TSB_INFO,"log_config policy check refuse type:[%d][%d]!\n", type, result);
		return 0;
	}

	total_len = sizeof(struct audit_msg) + strlen(sec_d->sub_name)+1 + strlen(sec_d->obj_name)+1;
	if(total_len > PAGE_SIZE)
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s] log length[%d] error!\n", __func__, total_len);
		return -1;
	}

	data = kmalloc(PAGE_SIZE,GFP_KERNEL);
	if(!data)
		return -1;
	memset(data, 0, PAGE_SIZE);
	data->repeats = 0;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
        data->time =ktime_get_real_seconds();
#else
	data->time = get_seconds();
#endif


	data->id = 0;
	
	p = (char*)data;
	p += sizeof(struct log_data);

	p_log_msg = (struct audit_msg *)p;
	p_log_msg->magic = 0xCCA1B2DD;
	p_log_msg->type = type;
	p_log_msg->operate = operate;
	p_log_msg->result = result;
	p_log_msg->user = user;
	p_log_msg->pid = pid;
	p_log_msg->repeat_num = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	ktime_get_real_ts64(&ts);
#else
	do_gettimeofday(&ts);
#endif
	p_log_msg->time = ts.tv_sec;
	memcpy(p_log_msg->sub_hash, sec_d->sub_hash, LEN_HASH);

	len_sub = strlen(sec_d->sub_name);
	if (len_sub > 0)
	{
		len_sub++;
		memcpy(p_log_msg->data, sec_d->sub_name, len_sub);
	}
	p_log_msg->len_sub = len_sub;

	len_obj = strlen(sec_d->obj_name);
	if (len_obj > 0)
	{
		len_obj++;
		memcpy(p_log_msg->data+len_sub, sec_d->obj_name, len_obj);
	}
	p_log_msg->len_obj = len_obj;

	p_log_msg->total_len = sizeof(struct audit_msg) + len_sub + len_obj;

	data->length = p_log_msg->total_len;

	return log_out_buffer(data);
}
EXPORT_SYMBOL(keraudit_log);

int keraudit_log_from_tpcm(const struct tpcm_audit_log *tpcm_audit, struct sec_domain *sec_d, unsigned int user, int pid)
{
	struct log_data *data = NULL;
	char *p = NULL;
	struct audit_msg *p_log_msg = NULL;
	int ret = 0;
	int len_sub = 0;
	int len_obj = 0;
	int total_len = 0;

	if(stopped)
		return 0;

	ret = get_log_config_policy(tpcm_audit->type, tpcm_audit->result, sec_d);
	if (ret == 0) 
	{
		DEBUG_MSG(HTTC_TSB_INFO,"tpcm log_config policy check refuse type:[%d][%d]!\n", tpcm_audit->type, tpcm_audit->result);
		return 0;
	}

	total_len = sizeof(struct audit_msg) + strlen(sec_d->sub_name)+1 + strlen(sec_d->obj_name)+1;
	if(total_len > PAGE_SIZE)
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s] log length[%d] error!\n", __func__, total_len);
		return -1;
	}

	data = kmalloc(PAGE_SIZE,GFP_KERNEL);
	if(!data)
		return -1;
	memset(data, 0, PAGE_SIZE);
	data->repeats = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
        data->time =ktime_get_real_seconds();
#else
        data->time = get_seconds();
#endif


	data->id = 0;

	p = (char*)data;
	p += sizeof(struct log_data);

	p_log_msg = (struct audit_msg *)p;
	p_log_msg->magic = 0xCCA1B2DD;
	p_log_msg->type = tpcm_audit->type;
	p_log_msg->operate = tpcm_audit->operate;
	p_log_msg->result = tpcm_audit->result;
	p_log_msg->user = user;
	p_log_msg->pid = pid;
	p_log_msg->repeat_num = 0;
	p_log_msg->time = tpcm_audit->t_sec;
	memcpy(p_log_msg->sub_hash, sec_d->sub_hash, LEN_HASH);

	len_sub = strlen(sec_d->sub_name);
	if (len_sub > 0)
	{
		len_sub++;
		memcpy(p_log_msg->data, sec_d->sub_name, len_sub);
	}
	p_log_msg->len_sub = len_sub;

	len_obj = strlen(sec_d->obj_name);
	if (len_obj > 0)
	{
		len_obj++;
		memcpy(p_log_msg->data+len_sub, sec_d->obj_name, len_obj);
	}
	p_log_msg->len_obj = len_obj;

	p_log_msg->total_len = sizeof(struct audit_msg) + len_sub + len_obj;

	data->length = p_log_msg->total_len;

	return log_out_buffer(data);
}

int kernel_audit_log(const struct log_n *log_audit)
{
	struct log_data *data = NULL;
	char *p = NULL;
	struct audit_msg *p_log_msg = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	struct timespec64 ts;
#else
	struct timeval ts;
#endif
	//int ret = 0;
	int total_len = 0;

	if(stopped)
		return 0;

	//ret = get_log_config_policy(log_audit->category, log_audit->type);
	//if (ret == 0) 
	//{
	//	DEBUG_MSG(HTTC_TSB_INFO,"trusted_conn log_config policy check refuse type:[%d][%d]!\n", log_audit->category, log_audit->type);
	//	return 0;
	//}

	total_len = sizeof(struct audit_msg) + log_audit->len;
	if(total_len > PAGE_SIZE)
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s] log length[%d] error!\n", __func__, total_len);
		return -1;
	}

	data = kmalloc(PAGE_SIZE, GFP_ATOMIC );
	if(!data)
		return -1;
	memset(data, 0, PAGE_SIZE);
	data->repeats = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
        data->time =ktime_get_real_seconds();
#else
        data->time = get_seconds();
#endif


	data->id = 0;

	p = (char*)data;
	p += sizeof(struct log_data);

	p_log_msg = (struct audit_msg *)p;
	p_log_msg->magic = 0xCCA1B2DD;
	p_log_msg->type = log_audit->category;
	p_log_msg->operate = 0;
	p_log_msg->result = log_audit->type;
	p_log_msg->user = 0;
	p_log_msg->pid = 0;
	p_log_msg->repeat_num = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	ktime_get_real_ts64(&ts);
#else
	do_gettimeofday(&ts);
#endif
	p_log_msg->time = ts.tv_sec;
	memset(p_log_msg->sub_hash, 0, LEN_HASH);

	p_log_msg->len_sub = 0/*log_audit->len*/;
	memcpy(p_log_msg->data, log_audit->data, log_audit->len);
	p_log_msg->len_obj = 0;

	p_log_msg->total_len = sizeof(struct audit_msg) + log_audit->len;

	data->length = p_log_msg->total_len;

	return log_out_buffer(data);
}
EXPORT_SYMBOL(kernel_audit_log);

long ioctl_write_user_log(unsigned long param)
{
	struct tsb_general_policy general_policy;
	char *p_buff = NULL;
	int ret = 0;

	ret =copy_from_user(&general_policy, (void *)param, sizeof(general_policy));
	if (ret || !general_policy.length) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user write_trusted_conn_log error! ret[%d] policy length[%d]\n", __func__, ret, general_policy.length);
		return -1;
	}

	p_buff = vmalloc(general_policy.length);
	if (!p_buff)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc error! write_trusted_conn_log length[%d]\n", __func__, general_policy.length);
		return -1;
	}

	ret =copy_from_user(p_buff, general_policy.data, general_policy.length);
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user dmeasure update policy failed!\n", __func__);
		vfree(p_buff);
		return -1;
	}

	kernel_audit_log((struct log_n *)p_buff);

	vfree(p_buff);

	return 0;
}

long ioctl_write_user_info_log(unsigned long param)
{
	struct tsb_general_policy general_policy;
	struct log_n* user_info_log = NULL;
	int ret = 0;

	ret =copy_from_user(&general_policy, (void *)param, sizeof(general_policy));
	if (ret || !general_policy.length) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user write_trusted_conn_log error! ret[%d] policy length[%d]\n", __func__, ret, general_policy.length);
		return -1;
	}

	user_info_log = vmalloc(sizeof(struct log_n)+general_policy.length);
	if (!user_info_log)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc error! write_trusted_conn_log length[%d]\n", __func__, general_policy.length);
		return -1;
	}

	ret =copy_from_user(user_info_log->data, general_policy.data, general_policy.length);
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user dmeasure update policy failed!\n", __func__);
		vfree(user_info_log);
		return -1;
	}
	user_info_log->len = general_policy.length;
	user_info_log->category = LOG_CATEGRORY_USER_INFO;

	kernel_audit_log(user_info_log);

	vfree(user_info_log);

	return 0;
}

int log_init(void)
{
	int  r;
#ifdef LOG_MEM
	log_buffer_init(&log_buf,hastables,DEFAULT_HASH_LEN,1,write_log_to_memory,free_log_data);
#else
	log_buffer_init(&log_buf,hastables,DEFAULT_HASH_LEN,1,write_log,free_log_data);
#endif

	r = switch_log_file();
	if(r)
		return r;

	atomic_set(&log_sum, 0);
	init_waitqueue_head(&log_queue);

	if ((r =httcsec_io_command_register(COMMAND_SWITCH_LOG_FILE, (httcsec_io_command_func) switch_log_file)))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n",COMMAND_SWITCH_LOG_FILE);
		goto out;
	}

	if ((r =httcsec_io_command_register(COMMAND_WRITE_USER_LOG, (httcsec_io_command_func) ioctl_write_user_log)))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n",COMMAND_WRITE_USER_LOG);
		goto out;
	}

	if ((r =httcsec_io_command_register(COMMAND_WRITE_USER_INFO_LOG, (httcsec_io_command_func) ioctl_write_user_info_log)))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n",COMMAND_WRITE_USER_INFO_LOG);
		goto out;
	}

	if ((r = httcsec_io_command_register(COMMAND_READ_MEM_LOG, (httcsec_io_command_func) ioctl_tsb_read_inmem_log)))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n", COMMAND_READ_MEM_LOG);
		goto out;
	}

	if ((r = httcsec_io_command_register(COMMAND_READ_MEM_LOG_NONBLOCK, (httcsec_io_command_func) ioctl_tsb_read_inmem_log_nonblock)))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n", COMMAND_READ_MEM_LOG_NONBLOCK);
		goto out;
	}

	r=log_config_policy_init();
	if (r)
	{
		DEBUG_MSG(HTTC_TSB_INFO,"log_config_policy_init error!\n");
	}

	r = tpcm_log_init();
	if (r)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], tpcm_log_init error!\n", __func__);
		//goto out;
	}

	r = log_buffer_start(&log_buf,"httcsec_log");
	if(r)
		goto out;

	return 0;
out:
	if(log_file)filp_close(log_file,0);
	return r;
}

void log_exit(void)
{
	struct file *tmp = NULL;
	stopped = 1;

	DEBUG_MSG(HTTC_TSB_DEBUG, "log_exit begin.\n");
	tpcm_log_exit();
	log_config_policy_exit();
	httcsec_io_command_unregister(COMMAND_SWITCH_LOG_FILE, (httcsec_io_command_func) switch_log_file);
	httcsec_io_command_unregister(COMMAND_WRITE_USER_LOG, (httcsec_io_command_func) ioctl_write_user_log);
	httcsec_io_command_unregister(COMMAND_WRITE_USER_INFO_LOG, (httcsec_io_command_func) ioctl_write_user_info_log);
	httcsec_io_command_unregister(COMMAND_READ_MEM_LOG, (httcsec_io_command_func) ioctl_tsb_read_inmem_log);
	httcsec_io_command_unregister(COMMAND_READ_MEM_LOG_NONBLOCK, (httcsec_io_command_func) ioctl_tsb_read_inmem_log_nonblock);
	log_buffer_stop(&log_buf);
	log_buffer_empty(&log_buf);
	mutex_lock(&log_file_mutex);
#ifdef LOG_MEM
	clear_mem_log();
#else
	tmp = log_file;
	mb();
	log_file = 0;
#endif
	mutex_unlock(&log_file_mutex);
	if(tmp)filp_close(tmp,0);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Log existed.\n");
}

