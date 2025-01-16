#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/mutex.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/suspend.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>

#include "memdebug.h"
#include "debug.h"
#include "kutils.h"
#include "version.h"
#include "tcs_error.h"
#include "tcs_tpcm_error.h"
#include "tpcm_command.h"

#include "tdd.h"
#include "tddl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tpcm transmit device");

unsigned int sync = 0;
unsigned int suspend_waiting = 0;

TDDL_IOCTL_PROC tpcm_ioctl_process = NULL;
static struct platform_device *tddl_pdev;

static DEFINE_MUTEX(tpcm_ioctl_mutex);



static pm_call_back  tpcm_s3_off_fun,
					 tpcm_s3_on_fun,
					 tpcm_s4_off_fun,
					 tpcm_s4_on_fun;



int tpcm_ioctl_proc_register (TDDL_IOCTL_PROC func)
{
	if (func){
		mutex_lock (&tpcm_ioctl_mutex);
		tpcm_ioctl_process = func;
		mutex_unlock (&tpcm_ioctl_mutex);
		printk ("[%s:%d] success!\n", __func__, __LINE__);
		return 0;
	}
	else{
		printk ("[%s:%d] func is NULL\n", __func__, __LINE__);
		return -1;
	}
}
EXPORT_SYMBOL_GPL(tpcm_ioctl_proc_register);

int tpcm_ioctl_proc_unregister (TDDL_IOCTL_PROC func)
{
	mutex_lock (&tpcm_ioctl_mutex);
	if (tpcm_ioctl_process == func){
		tpcm_ioctl_process = NULL;
		printk ("[%s:%d] success!\n", __func__, __LINE__);
	}
	else{
		printk ("[%s:%d] func is not found\n", __func__, __LINE__);
	}
	mutex_unlock (&tpcm_ioctl_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(tpcm_ioctl_proc_unregister);

static inline char* tddl_memcpy(void __iomem *dst, const void *src, int size)
{
	int i = 0;
	char *s = dst;
	char *pdst = dst;
	const char *psrc = src;
	while (i < size)
	{
		*(pdst + i) = *(psrc + i);
		i ++;
	}
	return s;
}

int tpcm_transmit_cmd (unsigned int category, void *command, int length, void *result, int *rlength)
{
	int ok = 0;
	int res = 0;

	if (suspend_waiting && (TPCM_ORD_PowerManage != tpcmReqCmd(command))){
		printk ("[%s:%d] Suspending: forbid tcm && tcm commands (0x%08x)\n", __func__, __LINE__, tpcmReqCmd(command));	
		return TPCM_NOSPACE;
	}
	
	httc_util_dump_hex ("Send", command, (length < 1024) ? length : 1024);
	if (0 != (ok = tdd_send_command (
				category, command, length, result, rlength))){
		printk ("[%s:%d] tdd_send_command hter: 0x%08x(%d)!\n", __func__, __LINE__, ok, ok);
		goto out;
	}
	httc_util_dump_hex ("Recv", result, (*rlength < 1024) ? *rlength : 1024);

out:
#if 1
	if (ok){
		httc_util_dump_hex_exec ("[hter] Send", command, (length < 1024) ? length : 1024);
	}
	else{
		res = *((uint32_t *)((uint8_t *)result + 8));
		if (res){
			httc_util_dump_hex_exec ("[hter] Send", command, (length < 1024) ? length : 1024);
			httc_util_dump_hex_exec ("[hter] Recv", result, (*rlength < 1024) ? *rlength : 1024);
		}
	}
#endif
	if (!ok && !res){
		if (tpcmRspLength(result) != *rlength){
			printk ("[%s:%d] rsp->len(%d) != *rlength(%d)\n", __func__, __LINE__, tpcmRspLength(result), *rlength);
			return TSS_ERR_BAD_RESPONSE;
		}
	}

	return ok;
}

int tpcm_tddl_transmit_cmd (void *command, int length, void *result, int *rlength){
	return tpcm_transmit_cmd (sync ? TDD_CMD_CATEGORY_TPCM : TDD_CMD_CATEGORY_TPCM_ASYNC, command, length, result, rlength);
}
EXPORT_SYMBOL (tpcm_tddl_transmit_cmd);


#pragma pack(push, 1)
struct tddl_buffer
{
	int cmd_len;
	int rsp_len;
	int rsp_maxlen;
	uint32_t res;
	unsigned char buffer[0];
};
#pragma pack(pop)

#define IOCTL_PROC_TRANSMIT		1
#define IOCTL_PROC_SPEC			2

#define ioctlProc(cmd)	((cmd>>2)&0x03)

int tpcm_tddl_open(struct inode *inode, struct file *filp)
{
	return 0;
}

int tpcm_tddl_release(struct inode *inode, struct file *filp)
{	
	return 0;
}

static long tpcm_tddl_ioctl(struct file *filp, unsigned int command, unsigned long arg)
{
	int ret = 0;
	uint32_t msg_len = 0;
	uint32_t rsp_len = 0;
	struct tddl_buffer gst_tddl_msg_tmp;
	struct tddl_buffer *gst_tddl_msg = NULL;
	struct tddl_buffer *gst_tddl_rsp = NULL;
 	uint32_t cmd_category = (sync ? TDD_CMD_CATEGORY_TPCM : TDD_CMD_CATEGORY_TPCM_ASYNC);

	if (0 != (ret = copy_from_user (&gst_tddl_msg_tmp,
			(int __user *)arg, httc_align_size (sizeof (gst_tddl_msg_tmp), 8)))){
		printk ("[%s:%d]copy_from_user hter, total: %ld, left: %d\n", __func__, __LINE__, (long int)httc_align_size (sizeof (gst_tddl_msg_tmp), 8), ret);
		return -EIO;
	}

	msg_len = httc_align_size (gst_tddl_msg_tmp.cmd_len + sizeof (struct tddl_buffer), 8);
	rsp_len = httc_align_size (gst_tddl_msg_tmp.rsp_maxlen + sizeof (struct tddl_buffer), 8);
	
	if (NULL == (gst_tddl_rsp = tdd_alloc_data_buffer (rsp_len))){
		printk ("[%s:%d]gst_tddl_rsp alloc hter!\n", __func__, __LINE__);
		return -ENOMEM;
	}
	gst_tddl_rsp->rsp_len = gst_tddl_msg_tmp.rsp_maxlen;
	
	switch(ioctlProc (command))
	{
		case IOCTL_PROC_TRANSMIT:
			if (NULL == (gst_tddl_msg = tdd_alloc_data_buffer (msg_len))){
				printk ("[%s:%d]gst_tddl_msg alloc hter!\n" ,__func__, __LINE__);
				gst_tddl_rsp->res = TSS_ERR_NOMEM;
				break;
			}

			if (0 != (ret = copy_from_user (gst_tddl_msg, (int __user *)arg, msg_len))){
				printk ("[%s:%d]copy_from_user hter, total: %d, left: %d\n",  __func__, __LINE__,msg_len, ret);
				ret = -EIO;
				if (gst_tddl_msg && (0 != tdd_free_data_buffer (gst_tddl_msg))){
					printk ("[%s:%d]gst_tddl_msg free hter!\n" ,__func__, __LINE__);
				}
				goto out;
			}

			if (0 != (gst_tddl_rsp->res = tpcm_transmit_cmd (cmd_category,
							gst_tddl_msg->buffer, gst_tddl_msg->cmd_len,
							gst_tddl_rsp->buffer, &gst_tddl_rsp->rsp_len))){
				printk ("[%s:%d] gst_tddl_rsp->res: 0x%08x\n", __func__, __LINE__, gst_tddl_rsp->res);
			}


			if (gst_tddl_msg){
				if (0 != tdd_free_data_buffer (gst_tddl_msg)){
					printk ("[%s:%d]gst_tddl_msg free hter!\n", __func__, __LINE__);
				} 
				gst_tddl_msg = NULL;
			}
			break;

		case IOCTL_PROC_SPEC:
			if (NULL == (gst_tddl_msg = httc_vmalloc (msg_len))){
				printk ("[%s:%d]gst_tddl_msg alloc hter!\n",__func__, __LINE__);
				gst_tddl_rsp->res = TSS_ERR_NOMEM;
				break;
			}

			if (0 != (ret = copy_from_user (gst_tddl_msg, (int __user *)arg, msg_len))){
				printk ("[%s:%d]copy_from_user hter, total: %d, left: %d\n", __func__, __LINE__, msg_len, ret);
				ret = -EIO;
				if (gst_tddl_msg)	httc_vfree(gst_tddl_msg);
				goto out;
			}
			mutex_lock (&tpcm_ioctl_mutex);
			if (tpcm_ioctl_process){
				if (0 != (gst_tddl_rsp->res = tpcm_ioctl_process (
						gst_tddl_msg->buffer, gst_tddl_msg->cmd_len,
						gst_tddl_rsp->buffer, &gst_tddl_rsp->rsp_len))){
					printk ("[%s:%d] gst_tddl_rsp->res: 0x%08x\n", __func__, __LINE__, gst_tddl_rsp->res);
				}
			}else{
				printk (KERN_NOTICE "Unavailable ioctl process\n");
				gst_tddl_rsp->res = TSS_ERR_IO;
			}
			mutex_unlock (&tpcm_ioctl_mutex);

			if (gst_tddl_msg)	httc_vfree(gst_tddl_msg);
			break;

		default:
			printk (KERN_NOTICE "Process default \n");
			gst_tddl_rsp->res = TSS_ERR_ITEM_NOT_FOUND;
			break;	
	}

 	if (0 != (ret = copy_to_user ((int __user *)arg, gst_tddl_rsp, rsp_len))){
		printk ("[%s:%d]copy_to_user hter, total: %d, left: %d\n", __func__, __LINE__, rsp_len, ret);
		ret = -EIO;
	}

out:
	if (gst_tddl_rsp && (0 != tdd_free_data_buffer (gst_tddl_rsp))){
			printk ("[%s:%d]gst_tddl_rsp free hter!\n", __func__, __LINE__);
	}
	return ret;
}

#define TPCM_TDDL_CDEV_MAJOR 502

struct cdev tpcm_cdev;	
static int tpcm_tddl_cdev_major = TPCM_TDDL_CDEV_MAJOR;
struct class *tpcm_tddl_cdev_class;
struct device *tpcm_tddl_cdev_device;

static const struct file_operations tpcm_tddl_fops =
{
	.unlocked_ioctl = tpcm_tddl_ioctl,
	.owner = THIS_MODULE,
	.open = tpcm_tddl_open,
	.release = tpcm_tddl_release,
};

int tpcm_pm_callback_register(pm_call_back call_back_fun, int pm_type){
	if (call_back_fun){
		mutex_lock (&tpcm_ioctl_mutex);
		switch (pm_type)
			{
			case S3_ON:
				tpcm_s3_on_fun = call_back_fun;
				break;
			case S3_OFF:
				tpcm_s3_off_fun = call_back_fun;
				break;
			case S4_ON:
				tpcm_s4_on_fun = call_back_fun;
				break;
			case S4_OFF:
				tpcm_s4_off_fun = call_back_fun;
				break;				
			}
		mutex_unlock (&tpcm_ioctl_mutex);
		printk ("[%s:%d] success!\n", __func__, __LINE__);
		return 0;
	}
	else{
		printk ("[%s:%d] func is NULL\n", __func__, __LINE__);
		return -1;
	}
	
}
EXPORT_SYMBOL_GPL(tpcm_pm_callback_register);


int tpcm_pm_callback_unregister(pm_call_back call_back_fun, int pm_type){
	if (call_back_fun){
		mutex_lock (&tpcm_ioctl_mutex);
		switch (pm_type)
			{
			case S3_ON:
				if(tpcm_s3_on_fun == call_back_fun){
					tpcm_s3_on_fun = NULL;
					printk ("[%s:%d] success!\n", __func__, __LINE__);
				}
				else{
					printk ("[%s:%d] func is not found\n", __func__, __LINE__);
				}
				break;
			case S3_OFF:
				if(tpcm_s3_off_fun == call_back_fun){
					tpcm_s3_off_fun = NULL;
					printk ("[%s:%d] success!\n", __func__, __LINE__);
				}
				else{
					printk ("[%s:%d] func is not found\n", __func__, __LINE__);
				}
				break;
			case S4_ON:
				if(tpcm_s4_on_fun == call_back_fun){
					tpcm_s4_on_fun = NULL;
					printk ("[%s:%d] success!\n", __func__, __LINE__);
				}
				else{
					printk ("[%s:%d] func is not found\n", __func__, __LINE__);
				}
				break;
			case S4_OFF:
				if(tpcm_s4_off_fun == call_back_fun){
					tpcm_s4_off_fun = NULL;
					printk ("[%s:%d] success!\n", __func__, __LINE__);
				}
				else{
					printk ("[%s:%d] func is not found\n", __func__, __LINE__);
				}
				break;				
			}
		mutex_unlock (&tpcm_ioctl_mutex);
		return 0;
	}
	else{
		printk ("[%s:%d] func is NULL\n", __func__, __LINE__);
		return -1;
	}
	
}
EXPORT_SYMBOL_GPL(tpcm_pm_callback_unregister);

/** pm function **/
static int tddl_suspend(struct device *dev){
	int ret = 0;
	mutex_lock (&tpcm_ioctl_mutex);
	suspend_waiting = 1;
	if(tpcm_s3_off_fun) ret = tpcm_s3_off_fun();
	mutex_unlock (&tpcm_ioctl_mutex);
	if(!ret){
		printk ("[%s:%d] success!\n", __func__, __LINE__);
		ret = 0;
	}else{
		printk("[%s:%d] hter!\n", __func__, __LINE__);
	}	
	
	return ret;
}
static int tddl_resume(struct device *dev){

	int ret = 0;
	mutex_lock (&tpcm_ioctl_mutex);
	suspend_waiting = 0;
	if(tpcm_s3_on_fun) ret = tpcm_s3_on_fun();
	mutex_unlock (&tpcm_ioctl_mutex);
	if(!ret){
		printk ("[%s:%d] success!\n", __func__, __LINE__);
	}else{
		printk("[%s:%d] hter!\n", __func__, __LINE__);
	}	
	
	return ret;
}
static int tddl_freeze(struct device *dev){

	int ret = 0;
	mutex_lock (&tpcm_ioctl_mutex);
	suspend_waiting = 1;
	if(tpcm_s4_off_fun) ret = tpcm_s4_off_fun();
	mutex_unlock (&tpcm_ioctl_mutex);
	if(!ret){
		printk ("[%s:%d] success!\n", __func__, __LINE__);
	}else{
		printk("[%s:%d] hter!\n", __func__, __LINE__);
	}	
	
	return ret;
}
	
static int tddl_restore(struct device *dev){

	int ret = 0;
	mutex_lock (&tpcm_ioctl_mutex);
	suspend_waiting = 0;
	if(tpcm_s4_on_fun) ret = tpcm_s4_on_fun();
	mutex_unlock (&tpcm_ioctl_mutex);
	if(!ret){
		printk ("[%s:%d] success!\n", __func__, __LINE__);
	}else{
		printk("[%s:%d] hter!\n", __func__, __LINE__);
	}	
	
	return ret;
}

static const struct dev_pm_ops tddl_pm = {
	.suspend = tddl_suspend,
	.resume = tddl_resume,
	.freeze = tddl_freeze,
	.restore = tddl_restore,
};

static int tddl_probe(struct platform_device *pdev)
{	
	int ret = 0;
	dev_t devno;
	//struct file *filp = NULL;
	//struct inode *inode = NULL;

	devno = MKDEV (tpcm_tddl_cdev_major, 0);
	ret = register_chrdev_region(devno, 1, "tpcm_ttd");
	if(ret){
		printk ("[%s:%d]register_chrdev_region hter!\n", __func__, __LINE__);
		return ret; 
	}

	cdev_init(&tpcm_cdev, &tpcm_tddl_fops);
	tpcm_cdev.owner = THIS_MODULE;

	ret = cdev_add(&tpcm_cdev, devno, 1);
	if(ret){
		printk ("[%s:%d]cdev_add hter (%d)!\n", __func__, __LINE__, ret);
		unregister_chrdev(tpcm_tddl_cdev_major, "tpcm_ttd");	 
		goto cdev_err;
		return ret; 
	}

	tpcm_tddl_cdev_class = class_create (THIS_MODULE, "tpcm_ttd");
	if(IS_ERR (tpcm_tddl_cdev_class)){  
		ret = PTR_ERR(tpcm_tddl_cdev_class); 
		printk ("[%s:%d]class_create hter (%d)!\n", __func__, __LINE__, ret); 
		goto class_err; 
	}
	
	tpcm_tddl_cdev_device = device_create(tpcm_tddl_cdev_class, NULL, devno, NULL, "tpcm_ttd");
	if(IS_ERR (tpcm_tddl_cdev_device)){	
		ret = PTR_ERR(tpcm_tddl_cdev_device); 
		printk ("[%s:%d]device_create hter (%d)!\n",  __func__, __LINE__,ret); 
		goto device_err; 
	}



	printk("[%s:%d] success!\n", __func__, __LINE__);
	return 0;

device_err:   
	class_destroy (tpcm_tddl_cdev_class);
class_err:
	cdev_del(&tpcm_cdev);
cdev_err:
	unregister_chrdev_region(MKDEV(tpcm_tddl_cdev_major, 0), 1);
	return ret;
}

static int tddl_remove(struct platform_device *pdev)
{

	device_destroy(tpcm_tddl_cdev_class, MKDEV(tpcm_tddl_cdev_major, 0));
   	class_destroy(tpcm_tddl_cdev_class);
   	cdev_del(&tpcm_cdev);
   	unregister_chrdev_region(MKDEV(tpcm_tddl_cdev_major, 0), 1);
    printk("[%s:%d] success!\n", __func__, __LINE__);
	return 0;
}

static struct platform_driver tddl_drv = {
	.driver = {
		.name = "tddl",
		.owner = THIS_MODULE,
		.pm = &tddl_pm,
	},
	.probe = tddl_probe,
	.remove = tddl_remove,	
};

int tcm_tddl_init(void);
void tcm_tddl_exit(void);

static int tddldev_init(void)
{
	int ret;

	ret = tcm_tddl_init();
	if(ret){
		return ret;
	}
	tddl_pdev = platform_device_alloc("tddl", -1);
	if (!tddl_pdev)
		return -ENOMEM;

	ret = platform_device_add(tddl_pdev);
	if (ret) {
		platform_device_put(tddl_pdev);
		return ret;
	}
	ret = platform_driver_register(&tddl_drv);
	if (ret) {
		platform_device_unregister(tddl_pdev);
		platform_device_put(tddl_pdev);		
		return ret;
	}

	return 0;
}
module_init(tddldev_init);

static void tddldev_exit(void)
{
	tcm_tddl_exit();
	platform_driver_unregister(&tddl_drv);
	platform_device_unregister(tddl_pdev);
}
module_exit(tddldev_exit);

module_param(sync, uint, S_IRUGO | S_IWUSR);

