#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/time.h>
#include <linux/module.h>

#include "memdebug.h"
#include "debug.h"
#include "kutils.h"
#include "version.h"
#include "tdd.h"
#include "tcs_tpcm.h"
#include "tcs_tpcm_error.h"
#include "tcs_kernel.h"
#include "tcs_notice.h"
#include "tcs_attest_def.h"
#include "tpcm_command.h"

static DEFINE_SPINLOCK(notify_lock);
static volatile unsigned int notify_type;
struct task_struct *log_thread;
static int stoping;
static DEFINE_MUTEX(log_mutex);
//typedef void (*log_call_back)(struct tpcm_log *log);
static log_call_back log_back_func;


static volatile int log_thread_cond = 0;
static wait_queue_head_t log_thread_wq;

static DEFINE_SPINLOCK(notify_fun_lock);
static notify_call_back notify_back_func[MAX_NOTIFY_CALL_BACK];

extern uint32_t gui_trust_status;
extern uint32_t dmeasure_trust_status;
extern uint32_t intercept_trust_status;

void test_log_call_back(struct tpcm_log *log){
	printk("log data type=%d,length=%d,log= %p\n",log->type,log->length,log->log);
}
//void read_log(void){
//	struct tpcm_log log;
//	printk("Reading logs!\n");
//	__set_current_state(TASK_UNINTERRUPTIBLE);
//	schedule_timeout(1 *HZ);
//	printk("Reading logs finished!\n");
//	log.log = "Log sssssssssssssssss \n";
//	log_back_func(&log);
//}
#pragma pack(push, 1)
//typedef struct{
//	uint32_t uiNum;
//	uint8_t  log[0];
//}tpcmlog_st;

typedef struct{
	uint32_t uiType;
	uint32_t uiLength;
	uint32_t uiRelativeSec;
	uint32_t uiRelativeMsec;
	uint8_t log[0];
}log_st;

#pragma pack(pop)

int get_log_real_time(struct timeval *res ,uint32_t Sec, uint32_t Msec)
{
	long a = 0;
	struct timeval now;
	
	httc_gettimeofday(&now);
	a = now.tv_usec - (Msec * 1000);
	
#ifdef NOTIFY_DEBUG
	printk ("dmLog->uiRelativeMsec: %u, D-value: %ld\n", Msec, a);
#endif

	if(a < 0){
		res->tv_sec = now.tv_sec - Sec - 1;
		res->tv_usec = 1000000 + now.tv_usec - (Msec * 1000);
		return 0;		
	}
	res->tv_sec = now.tv_sec - Sec;
	res->tv_usec = a;
	return 0;	
}

int read_log (void)
{
	int ret = 0;
	uint32_t logLen = 4096 - sizeof(tpcm_rsp_header_st);
	unsigned char  *log = NULL;
	uint32_t tpcmRes = 0;
	uint32_t offLog = 0;
	struct tpcm_log real_log;
	log_st *dmLog;
	if (NULL == (log = httc_kmalloc (logLen, GFP_KERNEL))){
		printk ("[%s:%d] Tpcm Log alloc hter\n", __func__, __LINE__);
		return -1;
	}
	do{
		offLog = 0;
		logLen = 4096 - sizeof(tpcm_rsp_header_st);
		ret = tcsk_get_tpcm_log (&logLen, (uint8_t*)log, &tpcmRes);
#ifdef NOTIFY_DEBUG
		printk ("[%s:%d] ret: 0x%08x, tpcmRes: 0x%08x\n", __func__, __LINE__, ret, tpcmRes);
#endif
		if (ret || (tpcmRes && (tpcmRes != TPCM_OUT_SIZE_EXCEEDED))){
			httc_kfree (log);
			return -1;
		}
#ifdef NOTIFY_DEBUG
		httc_util_dump_hex ("tpcm_log_parse dump", log, logLen);
#endif

		while (offLog + sizeof(log_st) < logLen) {
			dmLog = (log_st*)(log + offLog);
			get_log_real_time (&real_log.time, ntohl(dmLog->uiRelativeSec), ntohl(dmLog->uiRelativeMsec));
			real_log.type = ntohl(dmLog->uiType);
			real_log.length = ntohl(dmLog->uiLength);
			real_log.log = (char *)dmLog;

			if (offLog + real_log.length > logLen){
				printk ("[%s:%d] log length is too large (%d > %d)\n", __func__, __LINE__, offLog + real_log.length, logLen);
				break;
			}

#ifdef NOTIFY_DEBUG
			httc_util_dump_hex ("real_log dump", real_log.log, real_log.length);
#endif
			if(real_log.length > 0)log_back_func(&real_log);
			offLog += httc_align_size (real_log.length, 4);
		}		
	}while (tpcmRes == TPCM_OUT_SIZE_EXCEEDED);

	httc_kfree (log);
	return 0;
}
int tcsk_register_log_callback (log_call_back log_back_func_n)
{
	mutex_lock(&log_mutex);
	if(log_back_func != 0){
		printk("multiple registration!\n");		
		mutex_unlock(&log_mutex);
		return -1;
	}
	log_back_func = log_back_func_n;
	mutex_unlock(&log_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(tcsk_register_log_callback);

int tcsk_unregister_log_callback (log_call_back log_back_func_n)
{
	mutex_lock(&log_mutex);
	if(log_back_func_n == log_back_func) log_back_func = 0;
	else{
		printk("invalid unregistration func addr = %p\n",log_back_func_n);
	}
	mutex_unlock(&log_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(tcsk_unregister_log_callback);

int tcsk_register_notify_callback(notify_call_back notify_back_func_n)
{
	int i = 0;
	
	spin_lock_irq (&notify_fun_lock);
	for(i = 0; i < MAX_NOTIFY_CALL_BACK; i++){
		if(notify_back_func[i] == 0){			
			notify_back_func[i] = notify_back_func_n;
			spin_unlock_irq (&notify_fun_lock);
			return 0;			
		}else if(notify_back_func[i] != 0 && notify_back_func[i] == notify_back_func_n){
			printk("multiple registration!\n");		
			spin_unlock_irq (&notify_fun_lock);
			return -1;			
		}		
	}
	printk("Maximum exceeded!\n");		
	spin_unlock_irq (&notify_fun_lock);
	return -1;
}
EXPORT_SYMBOL_GPL(tcsk_register_notify_callback);

int tcsk_unregister_notify_callback(notify_call_back notify_back_func_n)
{
	int i = 0;

	spin_lock_irq (&notify_fun_lock);
	for(i = 0; i < MAX_NOTIFY_CALL_BACK; i++){
		if(notify_back_func[i] != 0 && notify_back_func[i] == notify_back_func_n){			
			notify_back_func[i] = 0;
			spin_unlock_irq (&notify_fun_lock);
			return 0;			
		}		
	}
	
	printk("invalid unregistration func addr = %p\n",notify_back_func_n);
	spin_unlock_irq (&notify_fun_lock);
	return 0;
}
EXPORT_SYMBOL_GPL (tcsk_unregister_notify_callback);

#define is_notify_log_flag_set()				(notify_type & TPCM_NOTIFY_TYPE_LOG)
#define is_notify_trusted_status_flag_set()		(notify_type & TPCM_NOTIFY_TYPE_TRUSTED_STATUS)
#define is_notify_license_flag_set()			(notify_type & TPCM_NOTIFY_TYPE_LICENSE)
#define is_notify_policies_version_flag_set()	(notify_type & TPCM_NOTIFY_TYPE_POLICIES_VERSION)

#define notify_log_flag_clear()					(notify_type &= (~TPCM_NOTIFY_TYPE_LOG))
#define notify_trusted_status_flag_clear()		(notify_type &= (~TPCM_NOTIFY_TYPE_TRUSTED_STATUS))
#define notify_license_flag_clear()				(notify_type &= (~TPCM_NOTIFY_TYPE_LICENSE))
#define notify_policies_version_flag_clear()	(notify_type &= (~TPCM_NOTIFY_TYPE_POLICIES_VERSION))


static int notfiy_thread_func (void *data)
{
	unsigned int i;
	int ret = 0;
	uint32_t tpcmRes = 0;
	struct timeval now;
	unsigned int local_notify = 1;

	for(i=0;!kthread_should_stop();i++){		
		mutex_lock(&log_mutex);
 		spin_lock_irq(&notify_lock);	
		if(is_notify_log_flag_set())	local_notify = 1;
		notify_log_flag_clear ();
		if(!log_back_func || !local_notify){
			if(!stoping) log_thread_cond = 0;
			//__set_current_state(TASK_UNINTERRUPTIBLE);
		}
		spin_unlock_irq(&notify_lock);

		if(local_notify && log_back_func){
			read_log();
			local_notify = 0;
			mutex_unlock(&log_mutex);
		}
		else{
			mutex_unlock(&log_mutex);
#ifdef NOTIFY_DEBUG
			printk("Notify thread goto sleep!\n");
#endif
			wait_event_timeout(log_thread_wq,  log_thread_cond,  60 * HZ);		
			local_notify = 1;//try to read when 2 minutes;
#ifdef NOTIFY_DEBUG
			printk("Notify thread wakeup!\n");
#endif
			if (!stoping){
				httc_gettimeofday (&now);
				ret = tcsk_set_system_time (now.tv_sec, &tpcmRes);
				if (ret || tpcmRes){
					printk ("[%s:%d] SetSystemTime hter: ret(0x%08x),tpcmRes(0x%08x)\n", __func__, __LINE__, ret, tpcmRes);
				}
			}
		}
	}
	return 0;
}

void tpcm_notifier(unsigned int pnotify_type,unsigned long param)
{

	int i = 0;
	struct tpcm_notify notify;
	unsigned long flag;
#ifdef NOTIFY_DEBUG
	printk("Notify type received: 0x%x\n", pnotify_type);
#endif
 	spin_lock_irqsave(&notify_lock,flag);	
 	notify_type |= pnotify_type;	
	
	if (is_notify_trusted_status_flag_set ()){
		gui_trust_status = STATUS_UNTRUSTED;
		notify.type = NOTICE_TRUSTED_STATUS_CHANGED;
		notify.length = sizeof(uint32_t);
		tpcm_memcpy(notify.notify,&gui_trust_status,sizeof(uint32_t));
		for(i = 0; i < MAX_NOTIFY_CALL_BACK; i++){
			spin_lock (&notify_fun_lock);
			if(notify_back_func[i] != 0) notify_back_func[i](&notify);
			spin_unlock (&notify_fun_lock);
		}		
		notify_trusted_status_flag_clear ();
	}else if(is_notify_license_flag_set()){		
		notify.type = NOTICE_LICENSE_STATUS_CHANGED;
		notify.length = 0;
		for(i = 0; i < MAX_NOTIFY_CALL_BACK; i++){
			spin_lock (&notify_fun_lock);
			if(notify_back_func[i] != 0) notify_back_func[i](&notify);
			spin_unlock (&notify_fun_lock);
		}
		notify_license_flag_clear();
	}

 	if(!stoping && notify_type){
		 log_thread_cond = 1;
		 wake_up(&log_thread_wq);
	}
	spin_unlock_irqrestore(&notify_lock,flag);
}


int notify_start(void)
{
	init_waitqueue_head(&log_thread_wq); 
	log_thread = kthread_run(notfiy_thread_func,0,"tpcm_thread");
	if (IS_ERR(log_thread)){
		return -1;
	}
	tdd_register_notifiy_handler (tpcm_notifier);
//	tpcm_register_log_callback(test_log_call_back);
	return 0;
}

void notify_stop(void)
{
	tdd_unregister_notifiy_handler (tpcm_notifier);
	spin_lock_irq(&notify_lock);
	stoping = 1;
	log_thread_cond = 1;
	wake_up(&log_thread_wq);
	spin_unlock_irq(&notify_lock);
	if (!IS_ERR(log_thread)){
		 kthread_stop(log_thread);
	}
}

//void tpcm_log_notifier(unsigned int pnotify_type,unsigned long param){
//	printk("Notify  received! %d\n",pnotify_type);
//	spin_lock(&notify_lock);
//	notify_type = pnotify_type;
//	if(!stoping && pnotify_type)wake_up_process(log_thread);
//	spin_unlock(&notify_lock);
//}
