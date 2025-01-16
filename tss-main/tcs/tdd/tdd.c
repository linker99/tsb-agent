#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <asm/cacheflush.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/kallsyms.h>
#include <linux/namei.h>
#include "tdd.h"
#include "msg.h"
#include "comm_driver.h"
#include "tdd_tpcm.h"
#include "tpcm_command.h"
#include "tcs_attest_def.h"

#define HTONS(h)	htons(h)
#define HTONL(h)	htonl(h)
#define NTOHS(n)	ntohs(n)
#define NTOHL(n)	ntohl(n)

#define TPCM_COMMAND_BUFFER_LIMIT	0x200000	/** 2M */

//#define TPML_CMD_LEN_LIMIT (1U << 12)
//#define TPML2PSP_CMD(id)   (0x90 | (id))
#define NOTIFY_DATA_MASK 0xffff
#define NOTIFY_SIMPLE_MASK 0xffff0000
struct notify_info{
	int notify_type;
	unsigned long notify_sequence;
	char buffer[0];
}__attribute__((packed));
enum{
	
	//NOTIFY_TYPE_SYNC_FINISHED =  0,//同步命令处理完成通知,不会通知上层
	NOTIFY_TYPE_CMD_FINISHED =  1,//异步命令处理完成通知,不会通知上层
};
#define TPCM_COMM_COMMAND 1
#define SENT_CMD_HASH 64
#define TPCM_CMD_TIMEOUT  (20 * HZ)
//#define MAX_NOTIFY_LENGTH 1024
int shm_init(void);
void shm_exit(void);
int netlink_init(void);
void netlink_exit(void);
static atomic64_t current_seq = ATOMIC64_INIT(0);
struct hlist_head sent_array[SENT_CMD_HASH];
static DEFINE_SPINLOCK(wait_lock);

static notifiy_func notifier;
struct cmd_node{
	struct cmd_header *header;
	struct hlist_node node;
	struct task_struct *task;
	volatile int out_length;
	volatile int out_return;
	volatile int handled;
	unsigned long timestamp;
	unsigned long cmd_sequnce;
};

int httcsec_messsage_prot = NETLINK_HTTCSEC_PROT;

static unsigned long proxypid = 0;

int is_main_task(const struct task_struct * tsk)
{
        return (tsk->pid == tsk->tgid);
}

struct task_struct * find_task(unsigned long pid)
{
        struct task_struct * task;

        // --
        rcu_read_lock();

        task = pid_task(find_pid_ns(pid, &init_pid_ns), PIDTYPE_PID);
        if(task){
                get_task_struct(task);
                // -- put_task_struct
        }

        rcu_read_unlock();

        return task;
}

static int __get_process_name(char * exe_path, int length, long pid)
{
        int retval = -1;
        struct path path;
        char link[128];
        char *ptr;
        int err = 0;

        exe_path[0] = 0;
        snprintf(link, sizeof(link), "/proc/%lu/exe", pid);

        err = kern_path(link, LOOKUP_FOLLOW, &path);

        if(err){
                return -1;
        }


        ptr = d_path(&path, exe_path, length);
        path_put(&path);

        if (!IS_ERR(ptr)) {
                retval = 0;
                exe_path[length - 1] = 0;
                strcpy(exe_path, ptr);
        }

        return retval;
}


int get_process_exe_name(char * exe_path, int length, long pid)
{
        return __get_process_name(exe_path, length, pid);
}

// return 0 not found;  pid found;
unsigned long check_process(char *path)
{
        int ret = 0;
        struct task_struct *tsk = NULL;
        //char *taskpath = NULL;

        if(path == NULL){
                printk("httc check_process param null!\n");
                ret = -1;
                goto out;
        }

        for_each_process(tsk){
                if(!is_main_task(tsk)){
                        continue;
                }

                if(strstr(tsk->comm,path)){
                        //taskpath = get_fullpath_from_task(tsk);
                        //printk("name %s, pid %lu, realpath %s\n",tsk->comm,tsk->tgid,taskpath);
                        ret = tsk->tgid;
                }

        }
out:
        return ret;
}

//0 should trans;else
int compare_proxy(unsigned long pid,int flag)
{
        int ret = 0;
        char task_path[512] = {0};
        struct task_struct *tsk = NULL;

        if(pid == 0){
                if(flag == PROXY_START_CHECK){
                        proxypid = check_process("tpcmproxy");
                        goto out;
                }else {
                        goto error_out;
                }
        }

        tsk = find_task(pid);
        if(tsk){
                get_process_exe_name(task_path,sizeof(task_path),pid);
                if(strstr(task_path,"tpcmproxy")){
                        goto out;
                }else{
                        printk("tttt 121 proxypid is %lu\n",pid);
                        ret = 121;
                }
        }else{

                printk("tttt 122 proxypid is %lu\n",pid);
                ret = 122;
        }

out:
        return ret;

error_out:
        return  ++ret;
}


unsigned long get_proxy_pid(void)
{
        return proxypid;
}


#ifdef TDD_DEBUG
static void tdd_util_dump_hex (unsigned char *name, void *p, int bytes)
{
    int i = 0;
    uint8_t *data = p;
    int hexlen = 0;
    int chrlen = 0;
    uint8_t hexbuf[128] = {0};
    uint8_t chrbuf[128] = {0};
    uint8_t dumpbuf[128] = {0};

    printk ("%s length=%d:\n", name, bytes);

    for (i = 0; i < bytes; i ++){
        hexlen += sprintf (&hexbuf[hexlen], "%02X ", data[i]);
        chrlen += sprintf (&chrbuf[chrlen], "%c", ((data[i] >= 33) && (data[i] <= 126)) ? (unsigned char)data[i] : '.');
        if (i % 16 == 15){
            sprintf (&dumpbuf[0], "%08X: %s %s", i / 16 * 16, hexbuf, chrbuf);
            printk ("%s\n", dumpbuf);
            hexlen = 0;
            chrlen = 0;
        }
    }

    if (i % 16 != 0){
        sprintf (&dumpbuf[0], "%08X: %-48s %s", i / 16 * 16, hexbuf, chrbuf);
        printk ("%s\n", dumpbuf);
    }
}
#endif

static int tdd_cmd_handle(void *buffer,int length,void *outbuffer,int *pout_length)
{
	int r = 0;
	get_tdd_info_req *p_req = (get_tdd_info_req *)buffer;
	get_tdd_info_rsp *p_rsp = (get_tdd_info_rsp *)outbuffer;
	if ( p_req && (TPCM_ORD_GetTddStatus == NTOHL(p_req->uiCmdCode)) && (TPCM_TAG_REQ_COMMAND == NTOHL(p_req->uiCmdTag)) && (sizeof(get_tdd_info_req) == NTOHL(p_req->uiCmdLength)) && p_rsp)
	{
		*pout_length = sizeof(get_tdd_info_rsp);
		p_rsp->uiRspTag = HTONL(TPCM_TAG_RSP_COMMAND);
		p_rsp->uiRspLength = HTONL(*pout_length);
		p_rsp->uiRspRet = 0;
		p_rsp->info.be_tdd_type = HTONL(TDD_TYPE_SIMULATOR);
		r = 1;
		printk("[%s:%d] be_tdd_type = %d, *pout_length = %d, r = %d \n" , __func__, __LINE__, NTOHL(p_rsp->info.be_tdd_type), *pout_length, r );
	}
	return r;
}

//static void (* pflush_dcache_all)(void) = 0xffffffc0000966c0;
int tdd_send_command(unsigned int cmd_category,void *buffer,int length,void *outbuffer,int *pout_length){
	int r;
	int tpcm_ret = 0;
	struct cmd_header *cmd = NULL;
	struct cmd_node *node = NULL;
	unsigned long sequnce;
	int wait = 0;
	int waitTimes = 5;

	if(compare_proxy(proxypid,PROXY_START_CHECK)){
		return 0;
	}

	r = tdd_cmd_handle(buffer, length, outbuffer, pout_length);
	if (r)
	{
		r = 0;
		return r;
	}
	cmd = tdd_alloc_cmd_header();

	if (length > TPCM_COMMAND_BUFFER_LIMIT){
		printk ("[%s:%d] cmd is too long (%d > %d)\n", __func__, __LINE__, length, TPCM_COMMAND_BUFFER_LIMIT);
		return TPCM_ERROR_EXCEED;
	}

	if (*pout_length > TPCM_COMMAND_BUFFER_LIMIT){
		printk ("[%s:%d] rsp buffer is too long (%d > %d)\n", __func__, __LINE__, *pout_length, TPCM_COMMAND_BUFFER_LIMIT);
		return TPCM_ERROR_EXCEED;
	}
	
#ifdef TDD_DEBUG
 	printk("[%s:%d] Cmd address: %lx\n", __func__, __LINE__, (unsigned long)cmd);
#endif

	if(!cmd){
		printk ("[%s:%d] cmd alloc  hter!\n", __func__, __LINE__);
		return TPCM_ERROR_NOMEM;
	}
	if(cmd_category >=  TDD_CMD_CATEGORY_ASYNC_START){
		node = kzalloc(sizeof(struct cmd_node), GFP_KERNEL);
 		if(!node){
			printk ("[%s:%d] node alloc  hter!\n", __func__, __LINE__);
			tdd_free_cmd_header(cmd);
			return TPCM_ERROR_NOMEM;
		}
		node->header = cmd;
	}
	cmd->input_addr = tdd_get_phys_addr(buffer);
	cmd->input_length = length;
	if(outbuffer)cmd->output_addr = tdd_get_phys_addr(outbuffer);
	if(pout_length)cmd->output_maxlength = *pout_length;

//	printk("input length");
	//cmd->cmd_sequnce = //need lock
	sequnce =   atomic64_inc_return(&current_seq);
	//flush_cache_all();
#ifdef TDD_DEBUG
	printk("[%s:%d] input addr = %lx,input length = %d \n" , __func__, __LINE__, (unsigned long)cmd->input_addr,cmd->input_length );
	printk("[%s:%d] out addr = %lx,out max length = %d \n" , __func__, __LINE__, (unsigned long)cmd->output_addr,cmd->output_maxlength );
	printk("[%s:%d] phy addr = %lx\n", __func__, __LINE__, tdd_get_phys_addr(cmd));
#endif
	//pflush_dcache_all();
	//__flush_dcache_area(cmd,sizeof(struct cmd_header));
	mb();
#ifdef TDD_DEBUG
	tdd_util_dump_hex ("Tdd Send to TPCM", cmd, sizeof (struct cmd_header));
#endif

	if(cmd_category < TDD_CMD_CATEGORY_ASYNC_START){
		r = send_command(cmd_category,sizeof(struct cmd_header), sequnce, tdd_get_phys_addr(cmd),&tpcm_ret);
		if(r){
			printk ("[%s:%d] [ft_send_command] r: 0x%08X", __func__, __LINE__, r);
			tdd_free_cmd_header(cmd);
			return TPCM_ERROR_SEND_FAIL;
		}
		if (tpcm_ret){
			printk ("[%s:%d] [ft_send_command] tpcm_ret: %d", __func__, __LINE__, tpcm_ret);
			tdd_free_cmd_header(cmd);
			return tpcm_ret;
		}

#ifdef TDD_DEBUG
		tdd_util_dump_hex ("Tdd recv from TPCM", cmd, sizeof (struct cmd_header));
#endif
		if(cmd->out_length > *pout_length ){
			printk ("[%s:%d] rsp from tpcm is too long (%d > %d)\n", __func__, __LINE__, cmd->out_length, *pout_length);
			r = TPCM_ERROR_EXCEED;
		}else{
			*pout_length = cmd->out_length;
		}
		tdd_free_cmd_header(cmd);
		return r;
	}
	else{//async cmd,add to list and wait
		//int sleep = 0;
		int index;
		//unsigned long flags;
		//struct cmd_node *node = (struct cmd_node *)cmd;
		spin_lock_irq(&wait_lock);
		node->task = current;
		node->cmd_sequnce = sequnce;
		index = sequnce & (SENT_CMD_HASH - 1);
		hlist_add_head(&node->node,sent_array + index);
		spin_unlock_irq(&wait_lock);
		r = send_command(cmd_category,sizeof(struct cmd_header), sequnce, tdd_get_phys_addr(cmd),&tpcm_ret);
		if(r){
			printk ("[%s:%d] [ft_send_command] r: 0x%08X", __func__, __LINE__, r);
			tdd_free_cmd_header(cmd);
			hlist_del(&node->node);
			kfree(node);
			return TPCM_ERROR_SEND_FAIL;
		}
		if (tpcm_ret){
			printk ("[%s:%d] [ft_send_command] tpcm_ret: %d", __func__, __LINE__, tpcm_ret);
			tdd_free_cmd_header(cmd);
			hlist_del(&node->node);
			kfree(node);
			return tpcm_ret;
		}
		
		while(waitTimes){
#ifdef TDD_DEBUG
			printk ("[%s:%d] waitTimes: %d, node->handled: %d\n",
					__func__, __LINE__, waitTimes, node->handled);
#endif
			spin_lock_irq(&wait_lock);
			if(!node->handled){
				__set_current_state(TASK_UNINTERRUPTIBLE);
				wait =1;
			}
			else{
				wait = 0;
				hlist_del(&node->node);
			}
			spin_unlock_irq(&wait_lock);
			if(!wait)break;
			schedule_timeout(TPCM_CMD_TIMEOUT);
			waitTimes--;
		}
		if(waitTimes == 0){
			spin_lock_irq(&wait_lock);
			if(!node->handled){
				r = TPCM_ERROR_TIMEOUT;
				printk("Time out async command %ld\n",sequnce);
			}
			hlist_del(&node->node);
			spin_unlock_irq(&wait_lock);
		}

		//mb();
		if(!r){

#ifdef TDD_DEBUG
			tdd_util_dump_hex ("Tdd recv from TPCM", cmd, sizeof (struct cmd_header));
#endif
			r = cmd->out_return;
			if (!r){
				if(cmd->out_length > *pout_length ){
					printk ("[%s:%d] rsp from tpcm is too long (%d > %d)\n", __func__, __LINE__, cmd->out_length, *pout_length);
					r = TPCM_ERROR_EXCEED;
				}else{
					*pout_length = cmd->out_length;
				}
			}
		}
		tdd_free_cmd_header(cmd);
		kfree(node);

		return r;
	}
}
EXPORT_SYMBOL_GPL(tdd_send_command);




static int notify(void *input,int length,void *output,int *olen){
	struct cmd_node *tpos;
	//int notify_type = *(int *)input;
	//unsigned long notify_sequence = *(unsigned long *)((char *)input + sizeof(notify_type));
	struct notify_info *info = (struct notify_info *)input;
	if(length < sizeof(struct notify_info)){
		return -1;
	}
	printk ("[%s:%d] notify_type: %d\n", __func__, __LINE__, info->notify_type);
	printk ("[%s:%d] notify_sequence: %lu\n", __func__, __LINE__, info->notify_sequence);
	
	
	
	if(info->notify_type == NOTIFY_TYPE_CMD_FINISHED){
		int index = info->notify_sequence & (SENT_CMD_HASH - 1);
		spin_lock_irq(&wait_lock);
		hlist_for_each_entry(tpos,sent_array + index,node){
			if(tpos->cmd_sequnce == info->notify_sequence){
				tpos->handled = 1;
				wake_up_process(tpos->task);
				break;
			}
		}
		spin_unlock_irq(&wait_lock);
	}
	else{
		spin_lock_irq(&wait_lock);
		if(notifier)notifier(info->notify_type,info->notify_sequence);
		spin_unlock_irq(&wait_lock);
	}
	*(int *)output = 0;
	* olen = sizeof(int);
	return 0;
}


int tdd_register_notifiy_handler(notifiy_func func){
	int r = 0;
	spin_lock_irq(&wait_lock);
	if(notifier)r = -1;
	else notifier  = func;
	spin_unlock_irq(&wait_lock);
	return r;
}
EXPORT_SYMBOL_GPL(tdd_register_notifiy_handler);

int tdd_unregister_notifiy_handler(notifiy_func func){
	int r = 0;
	spin_lock_irq(&wait_lock);
	if(notifier == func)notifier =0;
	else r = -1;
	spin_unlock_irq(&wait_lock);
	return r;
};
EXPORT_SYMBOL_GPL(tdd_unregister_notifiy_handler);

//MODULE_AUTHOR("HTTC");
//MODULE_LICENSE("GPL");
//MODULE_VERSION("0.1");
//MODULE_DESCRIPTION("The TPCM Driver for Simulator");

int shm_init(void);
void shm_exit(void);


int comm_init(void);
void comm_exit(void);
static int __init tdd_init(void)
{
	int ret = 0;
	
	if( (ret = shm_init())){
		printk("[%s:%d]shm_init hter %d\n",__func__, __LINE__,ret);
		goto out;
	}

	if( (ret = comm_init())){
			printk("[%s:%d]comm_init hter %d\n",__func__, __LINE__,ret);
			goto comm_out;
	}
	if( (ret = netlink_init())){
			printk("[%s:%d]netlink_init hter %d\n",__func__, __LINE__,ret);
			goto netlink_out;
	}
	if( (ret = httcsec_io_command_register_nl(TPCM_COMM_COMMAND,notify))){
			printk("[%s:%d]httcsec_io_command_register_nl hter %d\n",__func__, __LINE__,ret);
			goto register_nl;
	}

	printk("tpcm comm dirver inited\n");
	goto out;
//test_out:
	httcsec_io_command_unregister_nl(TPCM_COMM_COMMAND);
register_nl:
	netlink_exit();
netlink_out:
	comm_exit();
comm_out:
	shm_exit();
out:
//vaddr = kallsyms_lookup_name ("sys_call_table");
//vaddr &= ~0xFFFF;
//padrr = virt_to_phys((void *)vaddr);//syscall table
//	printk ("syscall pyhs = 0x%llx,vir=0x%llx\n",(unsigned long long)padrr,(unsigned long long)vaddr);
	return ret;
}

static void __exit tdd_exit(void)
{
	httcsec_io_command_unregister_nl(TPCM_COMM_COMMAND);
	netlink_exit();
	comm_exit();
	shm_exit();
	printk("tpcm exit\n");

}

module_init(tdd_init);
module_exit(tdd_exit);

module_param(httcsec_messsage_prot, uint, S_IRUGO | S_IWUSR);

MODULE_AUTHOR("HTTC");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("The TPCM Driver for Simulator");



