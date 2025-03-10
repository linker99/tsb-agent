#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/kdev_t.h>
#include <asm/io.h>

MODULE_LICENSE("Dual BSD/GPL");

static unsigned int major = 222;
static unsigned int minor = 0;
static dev_t dev_no;
static struct class* cls = NULL;
static struct device* cls_dev = NULL;

static unsigned long addr     = 0x0;
static unsigned long len      = 0x0;
static unsigned long per_len  = 1024;

void test_func(void)
{
    printk(KERN_ALERT "you call me\n");
}

int static memread_dev_open(struct inode *inode, struct file *file)
{
    printk(KERN_NOTICE "file open in memread_dev_open......finished!\n");
    return 0;
}

int static memread_dev_release(struct inode *inode, struct file *file)
{
    printk(KERN_NOTICE "file release in memread_dev_release......finished!\n");
    return 0;
}

ssize_t memread_dev_read(struct file *file, char __user *buf,size_t count, loff_t *offset)
{
  if (addr == 0 || len == 0) {
    return -1;
  }

  unsigned char *buffer = vmalloc(len);
  int i = 0;
  int res;
  unsigned char *ptr = (unsigned char *)addr;

  memset(buffer, 0, len);
 #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
  long ret = copy_from_kernel_nofault(buffer, ptr, len);
 #elif
  long ret = probe_kernel_read(buffer, ptr, len);
 #endif
  if (ret != 0) {
    vfree(buffer);
    return -1;
  }

  res = copy_to_user((char *)buf, buffer, len);
  vfree(buffer);
  if(res == 0)
    return res;
  else
    return -1;
}

ssize_t memread_dev_write(struct file *file, const char __user *buf, size_t count, loff_t *offset)
{
  return 0;
}

static long memread_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
        case 0:
            addr = arg;
            break;
        case 1:
            len = arg;
            break;
        default:
            break;
    }

    return 0;
}

static struct cdev memread_dev;

static struct file_operations fops ={
    .owner = THIS_MODULE,
    .open  = memread_dev_open,
    .release = memread_dev_release,
    .read = memread_dev_read,
    .write = memread_dev_write,
    .unlocked_ioctl = memread_dev_ioctl
};


static int memread_init(void)
{
  int result = 0;

    printk(KERN_NOTICE "memread ko init!\n");

    dev_no = MKDEV(major, minor);

    result = register_chrdev(major, "hello", &fops);
    if (result < 0) {
        printk(KERN_NOTICE "register chrdev failed! result: %d\n", result);
        return result;
    }

    cls = class_create(THIS_MODULE, "memread_cls");
    if (IS_ERR(cls) != 0) {
        printk(KERN_NOTICE "class create failed!");
        result = PTR_ERR(cls);
        goto err_1;
    }

    cls_dev = device_create(cls, NULL, dev_no, NULL, "memread_dev");
    if (IS_ERR(cls_dev) != 0) {
        printk(KERN_NOTICE "device create failed!");
        result = PTR_ERR(cls_dev);
        goto err_2;
    }

    return 0;

err_2:
    class_destroy(cls);
err_1:
    unregister_chrdev(major, "hello");
    return result;
}

void memread_exit(void)
{
  printk(KERN_NOTICE "goodbye\n");
  device_destroy(cls, dev_no);
  class_destroy(cls);
  unregister_chrdev(major, "hello");
  return;
}

module_init(memread_init);
module_exit(memread_exit);
EXPORT_SYMBOL(test_func);
