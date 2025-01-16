#include <linux/kernel.h>
#include <linux/module.h>

#include "tdd.h"
#include "tcs_tpcm.h"
#include "tcs_notice.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("notify test");

int update_status(uint32_t status){

	int ret = 0;
	printk("\n\nStatus is %d\n",status);
	return ret;
}


int licnese_notify(void){

	int ret = 0;
	printk("\n\nGet license notify\n");
	return ret;
}

void notify_bak (struct tpcm_notify *notify){

	int ret = 0;
	uint32_t status = 0;
	
	if(notify->type == NOTICE_TRUSTED_STATUS_CHANGED){
		memcpy(&status,notify->notify,notify->length);
		ret = update_status(status);
	}else if(notify->type == NOTICE_LICENSE_STATUS_CHANGED){
		ret = licnese_notify();
	}

}

int get_notify_init(void)
{
	int r;	

	printk("[%s:%d] success!\n", __func__, __LINE__);	
	r = tcsk_register_notify_callback(notify_bak);
	if(r){
		printk("tpcm_register_log_callback fail\n");
		return -EINVAL;
	}

	return 0;
}

void get_notify_exit(void)
{	
	tcsk_unregister_notify_callback(notify_bak);
	printk("[%s:%d] success!\n", __func__, __LINE__);
}

module_init(get_notify_init);
module_exit(get_notify_exit);



