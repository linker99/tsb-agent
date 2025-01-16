#include <linux/module.h>
#include <asm-generic/ioctl.h>
#include <linux/mutex.h>
#include "../utils/debug.h"
#include "command.h"

#define HTTCSEC_MISC_DEVICE_TYPE  0xAF
httcsec_io_command_func  cmd_array[MAX_COMMAND_NR];
static atomic_t cmd_ref_nums[MAX_COMMAND_NR];
//volatile int cmd_ref_nums[MAX_COMMAND_NR];
static DEFINE_SPINLOCK(command_lock);

long httcsec_miscdev_ioctl(struct file *filp, unsigned int cmd,
		unsigned long param)
{
	unsigned long r = -ENOTTY;
	httcsec_io_command_func func;
	int nr = _IOC_NR(cmd);
	//pr_dev("io command %llx\n", (unsigned long long)cmd);
	//pr_dev("io command dir %llx ,type %llx,nr %d \n", (unsigned long long)_IOC_DIR(cmd),(unsigned long long)_IOC_TYPE(cmd),_IOC_NR(cmd));
	//spin_lock(&command_lock);
	if(_IOC_TYPE(cmd) == HTTCSEC_MISC_DEVICE_TYPE){

		if(nr < MAX_COMMAND_NR){
			atomic_inc(cmd_ref_nums + nr);//确保不能注销
			mb();
			//spin_lock(&command_lock);
			func = cmd_array[nr];
			//spin_unlock(&command_lock);
			if(func){
				r = func(param, filp);
			}
			mb();
			//spin_lock(&command_lock);
			atomic_dec(cmd_ref_nums + nr);
			//spin_unlock(&command_lock);
			//r = cmd_array[nr](param);
		}
	}
	//pr_dev("invoke command = %x r=%lx\n", cmd,(unsigned long)r);
	return r;

}

int httcsec_io_command_register(int nr,httcsec_io_command_func func){
	int r = 0;
	spin_lock(&command_lock);
	if(nr < 0 || nr >= MAX_COMMAND_NR || cmd_array[nr]){
		pr_dev("Rregister fail\n");
		r = -EPERM;
	}
	else{
		cmd_array[nr] = func;
	}
	spin_unlock(&command_lock);
	return r;
}
int httcsec_io_command_unregister(int nr,httcsec_io_command_func func){
	//while(1){
	int r = 0;
	spin_lock(&command_lock);
	if(func == cmd_array[nr])
		cmd_array[nr] = 0;
	else{
		r = -EPERM;
		pr_dev("Unregister fail\n");
	}
	spin_unlock(&command_lock);
	//}

	if(!r){
		while(atomic_read(cmd_ref_nums + nr) > 0){
			pr_dev("Waiting for IOCTL %d complete\n",nr);
			schedule_timeout_uninterruptible(HZ/10);
		}
	}
	return r;
}

EXPORT_SYMBOL(httcsec_io_command_register);
EXPORT_SYMBOL(httcsec_io_command_unregister);
