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
#include <linux/wait.h>

#include "debug.h"
#include "kutils.h"
#include "version.h"
#include "tcs_error.h"
#include "tcs_tpcm_error.h"
#include "tpcm_command.h"
#include "tdd.h"
#include "tddl.h"
#include "tcs_config.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcm transmit device");

extern unsigned int sync;
extern unsigned int suspend_waiting;

#pragma pack(push,1)
typedef struct{
	uint16_t tag;
	uint32_t returnSize;
	uint32_t returnCode;
}tcm_rsp_header_st;
#pragma pack(pop)

static char* tddl_memcpy(void __iomem *dst, const void *src, int size)
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

static  int index_check(void *command){
	int ret = 1;
	char *temp = NULL;
	if(command == NULL) return  ret;
	temp = (char *) command;
	if (temp[8]==0x80 && temp[9]==0xCF){
		if((temp[12]==((NV_READ_INDEX_BLOCK>>8) & 0xFF)) && (temp[13]==(NV_READ_INDEX_BLOCK & 0xFF))) ret = 0;
	}
	return  ret;
}

int tcm_transmit_cmd (unsigned int category, void *command, int length, void *result, int *rlength)
{
	int ok = 0;
	int res = 0;
	tcm_rsp_header_st header;
	if (suspend_waiting){
		printk ("[%s:%d] Suspending: forbid tcm && tcm commands \n", __func__, __LINE__); 
		return TSS_ERR_IO;
	}

	httc_util_dump_hex ("Send", command, (length < 1024) ? length : 1024);
	if (0 != (ok = tdd_send_command (
		category, command, length, result, rlength))){
		printk ("[%s:%d] tdd_send_command hter: 0x%08x(%d)!\n",  __func__,__LINE__,ok, ok);
		goto out;
	}
	httc_util_dump_hex ("Recv", result, (*rlength < 1024) ? *rlength : 1024);
	tddl_memcpy(&header,result,sizeof(header));
out:

	if (ok){
		httc_util_dump_hex_exec ("[hter] Send", command, (length < 1024) ? length : 1024);
	}
	else{
		res = ntohl (header.returnCode);
		if (res){
			if(index_check(command)){	
				httc_util_dump_hex_exec ("[hter] Send", command, (length < 1024) ? length : 1024);
				httc_util_dump_hex_exec ("[hter] Recv", result, (*rlength < 1024) ? *rlength : 1024);
			}
		}
	}
	if (!ok && !res){
		if (ntohl(header.returnSize) != *rlength){
			printk ("[%s:%d] rsp->len(%d) != *rlength(%d)\n", __func__, __LINE__, ntohl(header.returnSize), *rlength);
			return TSS_ERR_BAD_RESPONSE;
		}
	}
	return ok;
}

int tcm_tddl_transmit_cmd (void *command, int length, void *result, int *rlength){
	return tcm_transmit_cmd (sync ? TDD_CMD_CATEGORY_TCM : TDD_CMD_CATEGORY_TCM_ASYNC, command, length, result, rlength);
}
EXPORT_SYMBOL (tcm_tddl_transmit_cmd);

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

volatile int tcm_count = 0;
static DECLARE_WAIT_QUEUE_HEAD(tcm_wq);
static DEFINE_SPINLOCK(tcm_lock);
static inline int tcm_available (void){
	int r;
	spin_lock (&tcm_lock);
	r = tcm_count;
	spin_unlock(&tcm_lock);
	return !r;
}

int tcm_tddl_open(struct inode *inode, struct file *filp)
{
	int ok = 0;
	while (1){
		spin_lock(&tcm_lock);
		if(tcm_count == 0){
			tcm_count ++;
			ok = 1;
		}
		spin_unlock(&tcm_lock);
		if(ok)break;
		if (filp->f_flags & O_NONBLOCK) return -EAGAIN;
		if (wait_event_interruptible (tcm_wq, tcm_available())) return -ERESTARTSYS; /* tell the fs layer to handle it */
	}
	return 0;
}

int tcm_tddl_release(struct inode *inode, struct file *filp)
{
	spin_lock(&tcm_lock);
	tcm_count--;
	spin_unlock(&tcm_lock);
	wake_up_interruptible(&tcm_wq); /* awake other uid's */
	return 0;
}

#define ioctlProc(cmd)	((cmd>>2)&0x03)
static long tcm_tddl_ioctl(struct file *filp, unsigned int command, unsigned long arg)
{
	int ret = 0;
	uint32_t msg_len = 0;
	uint32_t rsp_len = 0;
	struct tddl_buffer gst_tddl_msg_tmp;
	struct tddl_buffer *gst_tddl_msg = NULL;
	struct tddl_buffer *gst_tddl_rsp = NULL;
 	uint32_t cmd_category = (sync ? TDD_CMD_CATEGORY_TCM : TDD_CMD_CATEGORY_TCM_ASYNC); 			
			
	if (0 != (ret = copy_from_user (&gst_tddl_msg_tmp,
			(int __user *)arg, httc_align_size (sizeof (gst_tddl_msg_tmp), 8)))){
		printk ("[%s:%d]copy_from_user hter, total: %ld, left: %d\n", __func__,__LINE__,(long int)httc_align_size (sizeof (gst_tddl_msg_tmp), 8), ret);
		return -EIO;
	}

	msg_len = httc_align_size (gst_tddl_msg_tmp.cmd_len + sizeof (struct tddl_buffer), 8);
	rsp_len = httc_align_size (gst_tddl_msg_tmp.rsp_maxlen + sizeof (struct tddl_buffer), 8);
	
	if (NULL == (gst_tddl_rsp = tdd_alloc_data_buffer (rsp_len))){
		printk ("[%s:%d]gst_tddl_rsp alloc hter!\n", __func__,__LINE__);
		return -ENOMEM;
	}
	gst_tddl_rsp->rsp_len = gst_tddl_msg_tmp.rsp_maxlen;

	switch(ioctlProc (command)){
	
		case IOCTL_PROC_TRANSMIT:
			if (NULL == (gst_tddl_msg = tdd_alloc_data_buffer (msg_len))){
				printk ("[%s:%d]gst_tddl_msg alloc hter!\n",__func__,__LINE__);
				gst_tddl_rsp->res = TSS_ERR_NOMEM;
				break;
			}

			if (0 != (ret = copy_from_user (gst_tddl_msg, (int __user *)arg, msg_len))){
				printk ("[%s:%d]copy_from_user hter, total: %d, left: %d\n",__func__,__LINE__,msg_len, ret);
				ret = -EIO;
				if (gst_tddl_msg && (0 != tdd_free_data_buffer (gst_tddl_msg))){
					printk ("[%s:%d]gst_tddl_msg free hter!\n", __func__, __LINE__);
				}
				goto out;
			}

			if (0 != (gst_tddl_rsp->res = tcm_transmit_cmd (cmd_category,
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
		default:
			printk (KERN_NOTICE "Process default \n");
			gst_tddl_rsp->res = TSS_ERR_ITEM_NOT_FOUND;
			break;
	}

 	if (0 != (ret = copy_to_user ((int __user *)arg, gst_tddl_rsp, rsp_len))){
		printk ("[%s:%d] copy_to_user hter, total: %d, left: %d\n",  __func__, __LINE__,rsp_len, ret);
		ret = -EIO;
	}

out:
	if (gst_tddl_rsp && (0 != tdd_free_data_buffer (gst_tddl_rsp))){
			printk ("[%s:%d] gst_tddl_rsp free hter!\n", __func__, __LINE__);
	}
	return ret;
}

#define TCM_TDDL_CDEV_MAJOR 501

struct cdev tcm_cdev;	
static int tcm_tddl_cdev_major = TCM_TDDL_CDEV_MAJOR;
struct class *tcm_tddl_cdev_class;
struct device *tcm_tddl_cdev_device;

static const struct file_operations tcm_tddl_fops =
{
	.unlocked_ioctl = tcm_tddl_ioctl,
	.owner = THIS_MODULE,
	.open = tcm_tddl_open,
	.release = tcm_tddl_release,
};

int tcm_tddl_init(void)
{
	int ret = 0;
	dev_t devno;
	//struct file *filp = NULL;
	//struct inode *inode = NULL;

	devno = MKDEV (tcm_tddl_cdev_major, 0);
	ret = register_chrdev_region(devno, 1, "tcm_ttd");
	if(ret){
		printk ("[%s:%d]register_chrdev_region hter!\n", __func__, __LINE__);
		return ret; 
	}

	cdev_init(&tcm_cdev, &tcm_tddl_fops);
	tcm_cdev.owner = THIS_MODULE;

	ret = cdev_add(&tcm_cdev, devno, 1);
	if(ret){
		printk ("[%s:%d]cdev_add hter (%d)!\n", __func__, __LINE__,ret);
		unregister_chrdev(tcm_tddl_cdev_major, "tcm_ttd");	 
		goto cdev_err;
		return ret; 
	}

	tcm_tddl_cdev_class = class_create (THIS_MODULE, "tcm_ttd");
	if(IS_ERR (tcm_tddl_cdev_class)){  
		ret = PTR_ERR(tcm_tddl_cdev_class); 
		printk ("[%s:%d]class_create hter (%d)!\n", __func__, __LINE__, ret); 
		goto class_err; 
	}
	
	tcm_tddl_cdev_device = device_create(tcm_tddl_cdev_class, NULL, devno, NULL, "tcm_ttd");
	if(IS_ERR (tcm_tddl_cdev_device)){	
		ret = PTR_ERR(tcm_tddl_cdev_device); 
		printk ("[%s:%d]device_create hter (%d)!\n", __func__, __LINE__, ret); 
		goto device_err; 
	}

	printk("[%s:%d] success!\n", __func__, __LINE__);
	return 0;

device_err:   
	class_destroy (tcm_tddl_cdev_class);
class_err:
	cdev_del(&tcm_cdev);
cdev_err:
	unregister_chrdev_region(MKDEV(tcm_tddl_cdev_major, 0), 1);
	return ret;
}

void tcm_tddl_exit(void)
{
	device_destroy(tcm_tddl_cdev_class, MKDEV(tcm_tddl_cdev_major, 0));
   	class_destroy(tcm_tddl_cdev_class);
   	cdev_del(&tcm_cdev);
   	unregister_chrdev_region(MKDEV(tcm_tddl_cdev_major, 0), 1);
    printk("[%s:%d] success!\n", __func__, __LINE__);
}

