#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include "log.h"
#include "log_impl.h"
#include "../version.h"
#include "../utils/debug.h"

static int log_buff_stop = 0;

void log_buffer_init(struct log_buffer *buf, struct hlist_head *hastable,int hashsize,int interval,
			flush_object_func flush, free_object_func free)
{
	memset(buf,0,sizeof(struct log_buffer));
	spin_lock_init(&buf->lock);
	INIT_LIST_HEAD(&buf->log_cache);
	INIT_LIST_HEAD(&buf->flushing);
	INIT_LIST_HEAD(&buf->working);
	init_waitqueue_head(&buf->log_event);
	buf->hashsize = hashsize;
	buf->interval = interval;
	buf->func = flush;
	buf->free = free;
	buf->cache_hash = hastable;
}

static int buffer_flush(void *p)
{
	struct log_buffer *buffer = p;
	struct list_head *pos,*n;
	

	pr_dev("Kernel thread buffer_flush start\n");
	set_current_state(TASK_INTERRUPTIBLE);
	while (1)
	{
		 wait_event_interruptible( buffer->log_event, buffer->working_number > 0 );

		spin_lock(&buffer->lock);
		list_splice_init(&buffer->working,&buffer->flushing);
		buffer->working_number = 0;
		spin_unlock(&buffer->lock);

		list_for_each_safe(pos,n,&buffer->flushing)
		{
			list_del(pos);
			buffer->func(pos);
			buffer->free(pos);
		}

		if(log_buff_stop)
		{
			msleep(1 * HZ);
			break;
		}
	}
	pr_dev("Kernel thread buffer_flush stop\n");
	return 0;
}

int log_buffer_empty(struct log_buffer *buffer)
{
	struct list_head *pos,*n;
	struct hlist_node *hpos,*hn;
	int i;
	spin_lock(&buffer->lock);
	list_for_each_safe(pos, n, &buffer->working)
	{
		list_del(pos);
		buffer->free(pos);
	}

	list_for_each_safe(pos, n, &buffer->flushing)
	{
		list_del(pos);
		buffer->free(pos);
	}

	for(i=0; i < WORKING_HASH_SIZE; i++)
	{
		hlist_for_each_safe(hpos,hn,buffer->cache_hash + i)
		{
			hlist_del(hpos);
		}
	}

	list_for_each_safe(pos, n, &buffer->log_cache)
	{
		list_del(pos);
		buffer->free(pos);
	}
	spin_unlock(&buffer->lock);
	return 0;
}

int log_buffer_start(struct log_buffer *buffer,char *task_name)
{
	struct task_struct *flush_task = kthread_run(buffer_flush, buffer,task_name);
	if(IS_ERR(flush_task))
	{
		buffer->flush_task = NULL;
		return PTR_ERR(flush_task);
	}
	buffer->flush_task = flush_task;
	return 0 ;
}

void log_buffer_stop(struct log_buffer *buffer)
{
	if(buffer->flush_task)
	{
		log_buff_stop = 1;
		buffer->working_number = 1;
        	wake_up(&buffer->log_event);
		kthread_stop(buffer->flush_task);
		buffer->flush_task = NULL;
		pr_dev("buffer flush thread_done\n");
	}
}
