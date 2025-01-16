#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "ring_array.h"
#include "../utils/debug.h"

ring_queue *create_queue(unsigned int length)
{
	ring_queue *queue = NULL;
	unsigned int queue_len;
	queue_len = length;

	if( queue_len > MAX_BUF_ITEMS_NUM || queue_len < MIN_BUF_ITEMS_NUM )
	{
		queue_len = DEFAULT_BUF_ITEMS_NUM; 
		DEBUG_MSG(HTTC_TSB_DEBUG, "enter[%s]:queue range should be %d~%d current set to %d \n", 
					__func__,MIN_BUF_ITEMS_NUM,MAX_BUF_ITEMS_NUM,DEFAULT_BUF_ITEMS_NUM);
	}

	queue = (struct ring_queue *)kzalloc( (queue_len + 16) * sizeof(struct httc_notify) , GFP_KERNEL );
	if( queue == NULL )
	{
		DEBUG_MSG(HTTC_TSB_INFO, "enter[%s]: create ring OOM \n",__func__); 
		return NULL;
	}

	queue->head = queue->tail = queue_len - 1;
	queue->queue_length = queue_len;

	return queue;
}

void destory_queue(ring_queue *queue)
{
	if(queue == NULL)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "enter[%s]: queue is null \n",__func__); 
		return;
	}

	kfree(queue);
}

int put_queue(ring_queue *queue,  struct notify *notify_node)
{
	struct httc_notify *notify_item = NULL;

	if(notify_node == NULL)
	{
		DEBUG_MSG(HTTC_TSB_INFO , "enter[%s]: notify item is invalid \n",__func__); 
		return -1;
	}

	if(queue == NULL)
	{
		DEBUG_MSG(HTTC_TSB_INFO , "enter[%s]: queue is null \n",__func__); 
		return -1;
	}

	if(is_full_queue(queue) == 1 )
	{
		DEBUG_MSG(HTTC_TSB_INFO , "enter[%s]: queue is full\n",__func__); 
		return -1;
	}

	queue->tail = (queue->tail+1) % queue->queue_length; 
	
	notify_item = &queue->notify_queue[queue->tail];
	memcpy(&notify_item->notify_item, notify_node, sizeof(struct notify));
	bitmap_copy(notify_item->queue_bitmaps, queue->queue_mask, MAX_CONCURR_PROCESS );

	return 0;
}

int is_full_queue(ring_queue *queue)
{
	if(queue == NULL)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "enter[%s]: queue is null \n",__func__); 
		return -1;
	}

	return ((queue->tail+1)%queue->queue_length == (queue->head%queue->queue_length) ? 1 : 0);
}

int is_empty_queue(ring_queue *queue)
{
	if(queue == NULL)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "enter[%s]: queue is null \n",__func__); 
		return -1;
	}

	return ( queue->head%queue->queue_length == queue->tail%queue->queue_length ? 1 : 0 );    
}

struct httc_notify *retrieve_queue(ring_queue *queue, int ident)
{
	unsigned int h;
	struct httc_notify *notify_item = NULL;

	if(queue == NULL)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "enter[%s]: queue is null \n",__func__); 
		return NULL;
	}

	if(is_empty_queue(queue) == 1)
	{
		return NULL;
	}

	h = queue->head;
	while( h != queue->tail)
	{
		h++;
		h = h%queue->queue_length;

		notify_item = &queue->notify_queue[h];
		if(test_bit(ident,notify_item->queue_bitmaps))
		{
			clear_bit(ident, notify_item->queue_bitmaps);
			if(bitmap_empty(notify_item->queue_bitmaps,MAX_CONCURR_PROCESS))
				get_queue(queue);             /* delete no reference item */
			return notify_item;
		}
	}
	return NULL;
}

void clear_queue_bit(ring_queue *queue, int nr)
{
	unsigned int h;
	if(queue == NULL)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "enter[%s]: queue is null \n",__func__); 
		return;
	}

	if(is_empty_queue(queue) == 1)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "enter[%s]: queue is empty \n",__func__); 
		return ;
	}

	if( nr > MAX_CONCURR_PROCESS || nr < 0 )
	{
		return ;
	}

	h = queue->head;
	while( h != queue->tail)
	{
		struct httc_notify *notify_item;
		h++;
		h = h%queue->queue_length;
		notify_item = &queue->notify_queue[h];
		clear_bit(nr, notify_item->queue_bitmaps);
	}
}

void copy_queue(ring_queue *src, ring_queue *des )
{
	unsigned int h = 0;
	struct httc_notify *notify_item = NULL;
	struct httc_notify *notify_item2 = NULL;

	if(src == NULL || des == NULL )
	{
		DEBUG_MSG(HTTC_TSB_INFO, "enter[%s]: queue is null \n",__func__); 
		return;
	}

	if(is_empty_queue(src) == 1)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "enter[%s]: queue is empty \n",__func__); 
		return;
	}

	h = src->head;
	while( h != src->tail)
	{
		unsigned int t = 0;
		h++;
		h = h%src->queue_length;

		if( is_full_queue(des) )
			get_queue(des);

		notify_item = &src->notify_queue[h];
		put_queue(des, &notify_item->notify_item);
		t = des->tail;
		notify_item2 = &des->notify_queue[t];
		bitmap_copy( notify_item2->queue_bitmaps, notify_item->queue_bitmaps, MAX_CONCURR_PROCESS );
        }
	return;
}

int get_channel_num(ring_queue *queue, int channel )
{
	unsigned int h = 0;
	int count = 0;
	struct httc_notify *notify_item = NULL;

	if(queue == NULL)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "enter[%s]: queue is null \n",__func__); 
		return 0;
	}

	if(is_empty_queue(queue) == 1)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "enter[%s]: queue is empty \n",__func__); 
		return 0;
	}

	h = queue->head;
	while( h != queue->tail)
	{
		h++;
		h = h%queue->queue_length;
		notify_item = &queue->notify_queue[h];
		if(test_bit(channel, notify_item->queue_bitmaps))
			count++;
        }
	return count;
}

int get_queue(ring_queue *queue)
{
	if(queue == NULL)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "enter[%s]: queue is null \n",__func__); 
		return -1;
	}

	if(is_empty_queue(queue) == 1)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "enter[%s]: queue is empty \n",__func__); 
		return -1;
	}
    
	queue->head++;
	queue->head = (queue->head)%queue->queue_length;

	return 1;
}
