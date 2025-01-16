#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include "msg.h"
#include "tdd.h"
#include "tdd_tpcm.h"
#include "cmd_man.h"
#define PID 1

struct share_memory * share_memory_begin;

static DEFINE_MUTEX(mutex);

int send_command(int cmd_type,int cmd_length,unsigned long cmd_sequence, unsigned long cmd_addr_phys, int *cmd_ret){
   
	//u32 pid = PID;
	//int length;
	int r;
	int i;
	unsigned long proxypid = 0;

	mutex_lock (&mutex);
	share_memory_begin = (struct share_memory *)sharemem_base;
//	while(share_memory_begin->cmd_handled){
//		printk("There are orders not processed\n");
//		mdelay(1);
//	}
	share_memory_begin->cmd_type = cmd_type;
	share_memory_begin->cmd_length = cmd_length;
	share_memory_begin->cmd_sequence = cmd_sequence;
	share_memory_begin->cmd_addr_phys = cmd_addr_phys;
	share_memory_begin->cmd_handled = 0;


	r = httcsec_io_send_message(&cmd_addr_phys,sizeof(cmd_addr_phys), 1);
	if(r){
		mutex_unlock (&mutex);
		return r;
	}
	for(i=0;i<600;i++){
		if(share_memory_begin->cmd_handled){
			mutex_unlock (&mutex);
			return 0;
		}
		schedule_timeout_uninterruptible(HZ);


		if(i%10 == 0){
			if(proxypid == 0){
				proxypid = get_proxy_pid();
			}

			if(compare_proxy(proxypid,PROXY_RUNNING_CHECK) != 0){
				mutex_unlock (&mutex);
				return 0;
			}
		}
	}

	mutex_unlock (&mutex);
	return 1;
	//share_memory_begin->cmd_ret = *cmd_ret;


	//length = sizeof(&cmd_addr_phys);
	//send_netlink_back_data(pid, (void *)&cmd_addr_phys, length, 1);
	//return 0;
}
EXPORT_SYMBOL_GPL(send_command);

