#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/spinlock_types.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <asm/io.h>
#include "comm_driver.h"
#include "tdd_tpcm.h"
#include "tdd.h"
#include "cmd_man.h"

static atomic_t open_flag = ATOMIC_INIT(0);


static int tpcm_comm_open(struct inode *inode, struct file *file)
{
	int r = 0;
	//struct mm_struct *mm = current->mm;
	if(atomic_xchg(&open_flag,1))r = -EBUSY;
//	printk("client: %s (%d)\n", current->comm, current->pid);
//	printk("code  section: [0x%lx   0x%lx]\n", mm->start_code, mm->end_code);
//	printk("data  section: [0x%lx   0x%lx]\n", mm->start_data, mm->end_data);
//	printk("brk   section: s: 0x%lx, c: 0x%lx\n", mm->start_brk, mm->brk);
//	printk("mmap  section: s: 0x%lx\n", mm->mmap_base);
//	printk("stack section: s: 0x%lx\n", mm->start_stack);
//	printk("arg   section: [0x%lx   0x%lx]\n", mm->arg_start, mm->arg_end);
//	printk("env   section: [0x%lx   0x%lx]\n", mm->env_start, mm->env_end);
	printk("file busy status %d\n", r);


	return r;
}
static int tpcm_comm_release(struct inode *inode, struct file *filp)
{
	//struct mm_struct *mm = current->mm;
	atomic_set(&open_flag,0);
	printk("release client: %s (%d)\n", current->comm, current->pid);
//	printk("code  section: [0x%lx   0x%lx]\n", mm->start_code, mm->end_code);
//	printk("data  section: [0x%lx   0x%lx]\n", mm->start_data, mm->end_data);
//	printk("brk   section: s: 0x%lx, c: 0x%lx\n", mm->start_brk, mm->brk);
//	printk("mmap  section: s: 0x%lx\n", mm->mmap_base);
//	printk("stack section: s: 0x%lx\n", mm->start_stack);
//	printk("arg   section: [0x%lx   0x%lx]\n", mm->arg_start, mm->arg_end);
//	printk("env   section: [0x%lx   0x%lx]\n", mm->env_start, mm->env_end);
	return 0;
}
static int tpcm_comm_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long virt_start = (unsigned long)sharemem_base + (unsigned long)(vma->vm_pgoff << PAGE_SHIFT);
	unsigned long pfn_start = (unsigned long)vmalloc_to_pfn((void *)virt_start);
	unsigned long size = vma->vm_end - vma->vm_start;
	int ret = 0;
	unsigned long vmstart = vma->vm_start;
	int i = 0;

	printk("phy: 0x%lx, offset: 0x%lx, size: 0x%lx\n", pfn_start << PAGE_SHIFT, offset, size);

	while (size > 0) {
		ret = remap_pfn_range(vma, vmstart, pfn_start, PAGE_SIZE, vma->vm_page_prot);
		if (ret) {
			printk("%s:%d: remap_pfn_range hter at [0x%lx  0x%lx]\n",
				__func__,__LINE__ ,vmstart, vmstart + PAGE_SIZE);
			ret = -ENOMEM;
			goto err;
		} else
			printk("%s: map 0x%lx (0x%lx) to 0x%lx , size: 0x%lx, number: %d\n", __func__, virt_start,
				pfn_start << PAGE_SHIFT, vmstart, PAGE_SIZE, ++i);

		if (size <= PAGE_SIZE)
			size = 0;
		else {
			size -= PAGE_SIZE;
			vmstart += PAGE_SIZE;
			virt_start += PAGE_SIZE;
			pfn_start = vmalloc_to_pfn((void *)virt_start);
		}
	}

	return 0;
err:
	return ret;
}

struct map_req{
	unsigned long paddr;
	void *buffer;
	int length;
}__attribute__((packed));
long httcsec_miscdev_ioctl(struct file *filp, unsigned int cmd,
		unsigned long param)
{
	long r = 0;//-ENOTTY;
	struct map_req req;
	void *req_data = NULL; 
	
	//printk("io command %lx %lx\n", (unsigned long)cmd,param);
	//printk("io command dir %llx ,type %llx,nr %d \n", (unsigned long long)_IOC_DIR(cmd),(unsigned long long)_IOC_TYPE(cmd),_IOC_NR(cmd));

	if( (r = copy_from_user(&req, (void *)param, sizeof(struct map_req)))){
		printk("[%s:%d]Read request hter %ld\n",__func__,__LINE__ ,r);
		return r;
	}
	//printk("address padrr=%lx,buffer=%lx,length=%d\n",req.paddr,(unsigned long)req.buffer,req.length);

	if(_IOC_NR(cmd) == 1){
		if (NULL == (req_data = kmalloc (req.length, GFP_KERNEL))){
			printk ("[%s:%d]Alloc for req data hter!\n",__func__,__LINE__ );
			return -ENOMEM;
		}
		memcpy (req_data, (void*)req.paddr, req.length);

		if( (r= copy_to_user((void *)req.buffer, req_data, req.length))){
			printk("[%s:%d]Copy to user hter %ld\n",__func__,__LINE__ ,r);
			kfree (req_data);
			return r;
		}
	}
	else if(_IOC_NR(cmd) == 2){
		if (NULL == (req_data = kmalloc (req.length, GFP_KERNEL))){
					printk ("[%s:%d]Alloc for update data hter!\n",__func__,__LINE__);
					return -ENOMEM;
				}


		if( (r= copy_from_user( req_data, (void *)req.buffer,req.length))){
			printk("[%s:%d]Copy from user hter %ld\n",__func__,__LINE__ ,r);
			kfree (req_data);
			return r;
		}
		memcpy ( (void*)req.paddr, req_data, req.length);
	}
	//	mutex_lock(&command_lock);
//	if(_IOC_TYPE(cmd) == HTTCSEC_MISC_DEVICE_TYPE){
//		int nr = _IOC_NR(cmd);
//		if(nr < MAX_COMMAND_NR && cmd_array[nr]){
//			r = cmd_array[nr](param);
//		}
//	}
//	mutex_unlock(&command_lock);
//	pr_dev("invoke command = %x r=%lx\n", cmd,(unsigned long)r);
	kfree (req_data);
	return r;

}

static const struct file_operations tpcm_comm = {
	.owner = THIS_MODULE,
	.open = tpcm_comm_open,
	.mmap = tpcm_comm_mmap,
	.release = tpcm_comm_release,
	.unlocked_ioctl = httcsec_miscdev_ioctl,
	.compat_ioctl = httcsec_miscdev_ioctl
};

static struct miscdevice tpcm_comm_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "tpcm_comm",
	.fops = &tpcm_comm,
};

int comm_init(void)
{
	printk("mmap kbuff:0x%lx\n", (unsigned long)sharemem_base);
	return misc_register(&tpcm_comm_misc);
}

void comm_exit(void)
{
	misc_deregister(&tpcm_comm_misc);


}


