#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/timer.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/module.h>
#include "../msg/command.h"
#include "../utils/debug.h"
#include "notify.h"
#include "ring_array.h"

struct notify_head 
{
	int ident;
	int inuse;
	int curcount;
	atomic_t notify_sum;
	wait_queue_head_t notify_queue;
};

static struct notify_head dev_list[MAX_CONCURR_PROCESS];

DEFINE_SPINLOCK(notify_lock);

struct ring_queue *queue = NULL;
struct httc_notify *tsb_get_notify(struct notify_head *phead);

#ifdef TSB_NOTIFY_DEBUG
struct timer_list timer;    
void timer_handler(void);
void timer_init(void);
#endif

static long ioctl_tsb_set_queue_num(unsigned long param, struct file *filp)
{
	unsigned long queue_length;
	int ret;
	int pos;
	struct ring_queue *new_queue = NULL;
	struct ring_queue *old_queue = NULL;
	struct notify_head *phead = NULL;

	ret = copy_from_user( &queue_length, (void __user *) param, sizeof(long));
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user cache length failed!\n", __func__);
		return -1;
	}

	if ( queue_length > MAX_BUF_ITEMS_NUM)
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s] queue length [%ld] is out of range[100~1000] \n", __func__,queue_length);

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s],set cache length [%ld]!\n", __func__, queue_length);

	if (queue_length == queue->queue_length)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], same queue length!\n", __func__);
		return -1;
	}

	new_queue = create_queue(queue_length);
	if (new_queue == NULL)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s] create queue failed\n", __func__);
		return -1;
	}

	spin_lock_irq(&notify_lock);

	bitmap_copy( new_queue->queue_mask, queue->queue_mask, MAX_CONCURR_PROCESS );
	phead = dev_list;
	old_queue = queue;
	copy_queue(queue, new_queue);

	queue = new_queue;
	for_each_set_bit(pos, queue->queue_mask, MAX_CONCURR_PROCESS )
	{
		 int count = get_channel_num(queue, pos);
		atomic_set(&phead[pos].notify_sum, count);
	}

	destory_queue(old_queue);
	spin_unlock_irq(&notify_lock);

	return 0;
}

static long ioctl_tsb_send_notify(unsigned long param, struct file *filp)
{
	struct notify entry;
	int ret;

	memset(&entry, 0, sizeof(struct notify));

	ret = copy_from_user( &entry, (void __user *) param, sizeof (struct notify));
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user tsb notify failed!\n", __func__);
		return -1;
	}

	ret = tsb_put_notify(&entry);
	if(ret != 0)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], added to list failed!\n", __func__);
		return ret;	
	}

	return 0;
}

static int exist_notify_head( struct notify_head *phead )
{
	int i;
	struct notify_head *point;
	point = dev_list;
	for ( i = 0; i < MAX_CONCURR_PROCESS; i++ )
	{
		if( point == phead )
			return 1;
		point++;	
	}
	return 0;	
}

static long ioctl_tsb_create_notify_queue(unsigned long param, struct file *filp)
{
	int i;
	struct notify_head *phead = NULL;

	if ( filp == NULL )
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], filp %p private_data %p\n", __func__, filp, filp->private_data);
		return -2;
	}

	if ( queue == NULL )
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], queue %p is invalid\n", __func__, queue);
		return -1;
	}

	phead = dev_list;

	spin_lock_irq(&notify_lock);
	for (i = 0; i < MAX_CONCURR_PROCESS; i++)
	{
		if (phead[i].inuse == 0)
		{
			phead[i].ident = i;
			phead[i].inuse = 1;
			filp->private_data = (void *)&phead[i];
			set_bit(i, queue->queue_mask);
			atomic_set(&phead[i].notify_sum, 0);
			break;
		}
	}
	spin_unlock_irq(&notify_lock);

	DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], filp %p private_data %p id %d\n", __func__, filp, filp->private_data, i);

	if (i >= MAX_CONCURR_PROCESS)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], filp %p private_data %p i %d\n", __func__, filp, filp->private_data, i);
		return -1;	/* not found free resource */
	}
	else
		return 0;	/* success */
}

long tsb_destroy_notify_read_queue( struct file *filp )
{
	struct notify_head *phead = NULL;
	int ret = 0;

	if ( filp->private_data == NULL )
		return -1;

	phead = filp->private_data;

	ret = exist_notify_head( phead );
	if( ret == 0 )
	{
		return -1;
	}

	if ( queue == NULL )
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], queue %p is invalid\n", __func__, queue);
		return -1;
	}

	spin_lock_irq(&notify_lock);
	phead->inuse = 0;
	clear_bit(phead->ident, queue->queue_mask);
	clear_queue_bit(queue, phead->ident);
	atomic_set(&phead->notify_sum, 0);
	spin_unlock_irq(&notify_lock);

	return ret;
}

static long ioctl_tsb_get_notify_block(unsigned long param, struct file *filp)
{
	int ret = 0;
	struct notify_head *phead;
	struct httc_notify *notify_item = NULL;
	struct notify __user* ptemp = NULL;
	int count = 0;

	phead = filp->private_data;
	ret = exist_notify_head( phead );
	if(ret == 0)
		return -1;

	ret = wait_event_interruptible( phead->notify_queue,
					(atomic_read(&phead->notify_sum) > 0) );

	if (ret == -ERESTARTSYS)
	{
		return -ERESTARTSYS;
	}

	ptemp = (struct notify __user*)param;

	do
	{
		spin_lock_irq(&notify_lock);
		notify_item = retrieve_queue( queue, phead->ident );
		spin_unlock_irq(&notify_lock);
		if (notify_item == NULL)
			break;

		atomic_dec(&phead->notify_sum);
		count++;

		if(unlikely(atomic_read(&phead->notify_sum) < 0))
			atomic_set(&phead->notify_sum, 0);

                ret = copy_to_user((char __user *)ptemp, &notify_item->notify_item, sizeof (struct notify));
                if (ret)
                {
                        DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_to_user tsb notify failed!\n", __func__);
                        return -1;
		}
		ptemp++;

	} while(notify_item != NULL);

	return count;
}

static long ioctl_tsb_get_notify_noblock(unsigned long param, struct file *filp)
{
	int ret = 0;
	struct notify_head *phead;
	struct httc_notify *notify_item = NULL;
	struct notify __user* ptemp;
	int count = 0;

	phead = filp->private_data;
	ret = exist_notify_head( phead );
	if(ret == 0)
		return -1;

	if (atomic_read(&phead->notify_sum) <= 0)
	{
		return 0;
	}

	ptemp = (struct notify  __user*)param;

	do
	{
		spin_lock_irq(&notify_lock);
		notify_item = retrieve_queue( queue, phead->ident );
		spin_unlock_irq(&notify_lock);
		if (notify_item == NULL)
			break;

		atomic_dec(&phead->notify_sum);
		count++;

		if(unlikely(atomic_read(&phead->notify_sum) < 0))
			atomic_set(&phead->notify_sum, 0);

                ret = copy_to_user((char __user *)ptemp, &notify_item->notify_item, sizeof (struct notify));
                if (ret)
                {
                        DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_to_user tsb notify failed!\n", __func__);
                        return -1;
		}
		ptemp++;

	} while(notify_item != NULL);

	return count;
}

int tsb_put_notify(struct notify *entry)
{
	struct notify_head *phead;
	unsigned long flags;
	
	phead = dev_list;

	if (entry->length > MAX_NOTICE_SIZE)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], length is out of range!\n", __func__);
		return -1;
	}

	spin_lock_irqsave(&notify_lock,flags);
	if( bitmap_weight(queue->queue_mask, MAX_CONCURR_PROCESS) != 0 )
	{
		int pos = 0;

		if(is_full_queue(queue) == 1 )
		{
			get_queue(queue); /* delet old data */ 
		}

		put_queue( queue, entry );

		for_each_set_bit(pos, queue->queue_mask, MAX_CONCURR_PROCESS )
		{
			if(atomic_read(&phead[pos].notify_sum) < (queue->queue_length-1))
				atomic_inc(&phead[pos].notify_sum);
			wake_up(&phead[pos].notify_queue);
		}
	}
	spin_unlock_irqrestore(&notify_lock,flags);

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], bits num[%d] type[%d]\n", __func__ ,bitmap_weight(queue->queue_mask, MAX_CONCURR_PROCESS),entry->type);

	return 0;
}

EXPORT_SYMBOL(tsb_put_notify);

void tsb_free_notifylist(void)
{
	struct notify_head *phead;

	phead = dev_list;
	if(phead == NULL)
		return;

	spin_lock_irq(&notify_lock);

	destory_queue(queue);

	spin_unlock_irq(&notify_lock);
}

int tsb_notify_init(void)
{
	int ret = 0;
	int i;
	struct notify_head *phead;

	memset(dev_list, 0, sizeof (struct notify_head) * MAX_CONCURR_PROCESS);
	phead = dev_list;

	queue = create_queue(DEFAULT_BUF_ITEMS_NUM);
	if (queue == NULL)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s] create queue failed\n", __func__);
		return -1;
	}

	for (i = 0; i < MAX_CONCURR_PROCESS; i++)
	{
		init_waitqueue_head(&phead[i].notify_queue);
	}

	ret = httcsec_io_command_register(COMMAND_SEND_NOTIFY_PKG,
					  (httcsec_io_command_func) ioctl_tsb_send_notify);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], Command NR duplicated %d. \n", __func__,
			  COMMAND_SEND_NOTIFY_PKG);
	}

	ret = httcsec_io_command_register(COMMAND_CREATE_NOTIFY_QUEUE,
					  (httcsec_io_command_func) ioctl_tsb_create_notify_queue);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], Command NR duplicated %d. \n", __func__,
			  COMMAND_CREATE_NOTIFY_QUEUE);
		goto exit1;
	}

	ret = httcsec_io_command_register(COMMAND_GET_NOTIFY_INFO_BLOCK,
					  (httcsec_io_command_func) ioctl_tsb_get_notify_block);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], Command NR duplicated %d. \n", __func__,
			  COMMAND_GET_NOTIFY_INFO_BLOCK);
		goto exit2;
	}

	ret = httcsec_io_command_register(COMMAND_GET_NOTIFY_INFO_NOBLOCK,
					(httcsec_io_command_func) ioctl_tsb_get_notify_noblock);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], Command NR duplicated %d. \n", __func__,
			  COMMAND_GET_NOTIFY_INFO_NOBLOCK);
		goto exit3;
	}

	ret = httcsec_io_command_register( COMMAND_SET_NOTIFY_QUEUE_NUM,
					(httcsec_io_command_func) ioctl_tsb_set_queue_num );
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], Command NR duplicated %d. \n", __func__,
			  COMMAND_SET_NOTIFY_QUEUE_NUM);
		goto exit4;
	}

#ifdef TSB_NOTIFY_DEBUG
	timer_init();
#endif
	goto out;
exit4:
	httcsec_io_command_unregister(COMMAND_GET_NOTIFY_INFO_NOBLOCK,
				      (httcsec_io_command_func) ioctl_tsb_get_notify_noblock);
exit3:
	httcsec_io_command_unregister(COMMAND_GET_NOTIFY_INFO_BLOCK,
				      (httcsec_io_command_func) ioctl_tsb_get_notify_block);
exit2:
	httcsec_io_command_unregister(COMMAND_CREATE_NOTIFY_QUEUE,
				      (httcsec_io_command_func) ioctl_tsb_create_notify_queue);
exit1:
	httcsec_io_command_unregister(COMMAND_SEND_NOTIFY_PKG,
				      (httcsec_io_command_func) ioctl_tsb_send_notify);

	tsb_free_notifylist();
out:
	return ret;
}

void tsb_notify_exit(void)
{
	httcsec_io_command_unregister(COMMAND_SEND_NOTIFY_PKG,
				      (httcsec_io_command_func) ioctl_tsb_send_notify);

	httcsec_io_command_unregister(COMMAND_CREATE_NOTIFY_QUEUE,
				      (httcsec_io_command_func) ioctl_tsb_create_notify_queue);

	httcsec_io_command_unregister(COMMAND_GET_NOTIFY_INFO_BLOCK,
				      (httcsec_io_command_func) ioctl_tsb_get_notify_block);
	httcsec_io_command_unregister(COMMAND_GET_NOTIFY_INFO_NOBLOCK,
				      (httcsec_io_command_func) ioctl_tsb_get_notify_noblock);
	httcsec_io_command_unregister(COMMAND_SET_NOTIFY_QUEUE_NUM,
				      (httcsec_io_command_func) ioctl_tsb_set_queue_num );

#ifdef TSB_NOTIFY_DEBUG
	del_timer(&timer);         
#endif
	tsb_free_notifylist();
}

#ifdef TSB_NOTIFY_DEBUG
void timer_handler()
{
	static int count = 0;
	struct notify entry;

	memset(&entry, 0, sizeof (struct notify));
	entry.type = 0;
	entry.length = 32;
	memset(entry.buf, 33 + count, 35);

	if (++count == 94)
		count = 0;

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], added notice buf[%s] length[%d]!\n", __func__,entry.buf, entry.length);
	tsb_put_notify(&entry);

	timer.expires = jiffies + 1*HZ;
	timer.function = (void *)timer_handler;
	add_timer(&timer);      
}

void timer_init()
{
	timer.expires = jiffies + 1*HZ;
	timer.function = (void *)timer_handler;
	add_timer(&timer);
}
#endif
