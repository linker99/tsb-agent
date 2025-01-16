#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/hash.h>
#include <linux/random.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include "../utils/debug.h"

#define HTTCSEC_MSG_MAXBUFFERSIZE 4096
wait_queue_head_t httcsec_msg_poll_wait;
wait_queue_head_t httcsec_msg_wait;
char *httcsec_msg_base;
char *httcsec_msg_head;
char *httcsec_msg_tail;
DEFINE_MUTEX( httcsec_msg_mutex);
atomic_t httcsec_num_miscdev_opens;

extern long tsb_destroy_notify_read_queue(struct file *filp);
/**
 *httcsec_miscdev_poll
 * @file: dev file (ignored)
 * @pt: dev poll table (ignored)
 *
 * Returns the poll mask
 */
static unsigned int httcsec_miscdev_poll(struct file *file, poll_table *pt)
{
//	/structhttcsec_daemon *daemon;
	unsigned int mask = 0;
	poll_wait(file, &httcsec_msg_poll_wait, pt);
	mutex_lock(&httcsec_msg_mutex);
	if (httcsec_msg_head != httcsec_msg_tail)
		mask |= POLLIN | POLLRDNORM;
	mutex_unlock(&httcsec_msg_mutex);
	pr_dev("poll = %x", mask);
	return mask;
}

/**
 *httcsec_miscdev_open
 * @inode: inode of miscdev handle (ignored)
 * @file: file for miscdev handle (ignored)
 *
 * Returns zero on success; non-zero otherwise
 */
static int httcsec_miscdev_open(struct inode *inode, struct file *file)
{

	int rc;
	rc = try_module_get(THIS_MODULE);

	if (rc == 0)
	{
		rc = -EIO;
		DEBUG_MSG(HTTC_TSB_INFO,"%s: Error attempting to increment module use "
			"count; rc = [%d]\n", __func__, rc);
	}
	else
	{
		rc = 0;
		atomic_inc(&httcsec_num_miscdev_opens);
	}
	return rc;
}

/**
 *httcsec_miscdev_release
 * @inode: inode of fs/efs/euid handle (ignored)
 * @file: file for fs/efs/euid handle (ignored)
 *
 * This keeps the daemon registered until the daemon sends another
 * ioctl to fs/efs/ctl or until the kernel module unregisters.
 *
 * Returns zero on success; non-zero otherwise
 */
static int httcsec_miscdev_release(struct inode *inode, struct file *file)
{
	module_put(THIS_MODULE);
	atomic_dec(&httcsec_num_miscdev_opens);
	tsb_destroy_notify_read_queue(file);	
	return 0;
}

/**
 *httcsec_miscdev_read - format and send message from queue
 * @file: fs/efs/euid miscdevfs handle (ignored)
 * @buf: User buffer into which to copy the next message on the daemon queue
 * @count: Amount of space available in @buf
 * @ppos: Offset in file (ignored)
 *
 * Pulls the most recent message from the daemon queue, formats it for
 * being sent via a miscdevfs handle, and copies it into @buf
 *
 * Returns the number of bytes copied into the user buffer
 */
static ssize_t httcsec_miscdev_read(struct file *file, char __user *buf,
		size_t count,loff_t *ppos)
{
	return -1;
}

static ssize_t httcsec_miscdev_write(struct file *file, const char __user *buf,
	size_t count, loff_t *ppos)
{
	return count;
}

long httcsec_miscdev_ioctl(struct file *filp, unsigned int cmd,
	unsigned long param);

static const struct file_operations httcsec_miscdev_fops =
	{
		.open = httcsec_miscdev_open,
		.poll = httcsec_miscdev_poll,
		.read =	httcsec_miscdev_read,
		.write = httcsec_miscdev_write,
		.release =	httcsec_miscdev_release,
		.unlocked_ioctl = httcsec_miscdev_ioctl,
		.compat_ioctl = httcsec_miscdev_ioctl
	};

static struct miscdevice httcsec_miscdev =
	{
			.minor = MISC_DYNAMIC_MINOR,
			.name = "httcsec",
			.fops =	&httcsec_miscdev_fops
	};

/**
 *httcsec_init_httcsec_miscdev
 *
 * Messages sent to the userspace daemon from the kernel are placed on
 * a queue associated with the daemon. The next read against the
 * miscdev handle by that daemon will return the oldest message placed
 * on the message queue for the daemon.
 *
 * Returns zero on success; non-zero otherwise
 */
int miscdev_init(void)
{
	int rc;

	init_waitqueue_head(&httcsec_msg_poll_wait);
	atomic_set(&httcsec_num_miscdev_opens, 0);

	httcsec_msg_head = httcsec_msg_tail = httcsec_msg_base = dvmalloc(
			HTTCSEC_MSG_MAXBUFFERSIZE);
	if (!httcsec_msg_base)
	{
		return -ENOMEM;
	}

	rc = misc_register(&httcsec_miscdev);
	if (rc)
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Failed to register miscellaneous device "
				"for communications with userspace processs.rc = [%d]\n",
				rc);
		dvfree(httcsec_msg_base);
		return rc;

	}

	return rc;
}

/**
 *httcsec_miscdev_exit
 *
 * All of the daemons must be exorcised prior to calling this
 * function.
 */
void miscdev_exit(void)
{

	BUG_ON(atomic_read(&httcsec_num_miscdev_opens) != 0);
	misc_deregister(&httcsec_miscdev);
	dvfree(httcsec_msg_base);
}
