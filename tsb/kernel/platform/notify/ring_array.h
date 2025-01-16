#ifndef __RINGQUEUE_H
#define __RINGQUEUE_H
#include "notify.h"

struct httc_notify 
{
	unsigned long  queue_bitmaps[BITS_TO_LONGS(MAX_CONCURR_PROCESS)];
	struct notify notify_item;
};

typedef struct ring_queue
{
	unsigned long queue_mask[BITS_TO_LONGS(MAX_CONCURR_PROCESS)];
	unsigned int  queue_length;
	unsigned int  head;
	unsigned int  tail;
	struct httc_notify notify_queue[0];
} ring_queue;

ring_queue *create_queue(unsigned int length);
int put_queue(ring_queue *queue,  struct notify *notify_node);
int is_full_queue(ring_queue *queue);
int is_empty_queue(ring_queue *queue);
void show_queue(ring_queue *queue);
int get_queue(ring_queue *queue);
void copy_queue(ring_queue *src, ring_queue *des );
void clear_queue_bit(ring_queue *queue, int nr);
void destory_queue(ring_queue *queue);
struct httc_notify * retrieve_queue( ring_queue *queue, int ident );
int get_channel_num(ring_queue *queue, int channel);
#endif
