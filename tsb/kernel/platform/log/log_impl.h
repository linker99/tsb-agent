/*
 * httcsec_log.h
 */

#ifndef HTTCSEC_LOG_IMPL_H_
#define HTTCSEC_LOG_IMPL_H_
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include "log.h"

#define WORKING_HASH_SIZE 1024
#define CACHE_MAX_NUM 200
typedef int (* flush_object_func)(struct list_head *node);
typedef int (* free_object_func)(struct list_head *node);
struct log_buffer
{
	spinlock_t lock;
	wait_queue_head_t log_event;
	struct list_head log_cache;
	struct list_head working;
	struct list_head flushing;
	volatile int working_number;
	volatile int cache_number;
	int hashsize;
	struct hlist_head *cache_hash;
	int interval;
	flush_object_func func;
	free_object_func free;
	struct task_struct *flush_task;
};
static inline void log_lock(struct log_buffer *buffer){
	spin_lock(&buffer->lock);
}
static inline void log_unlock(struct log_buffer *buffer){
	spin_unlock(&buffer->lock);
}
int log_buffer_start(struct log_buffer *buffer,char *task_name);
void log_buffer_stop(struct log_buffer *buffer);
void log_buffer_init(struct log_buffer *buf, struct hlist_head *hastable,int hashsize,int interval,
		flush_object_func flush, free_object_func free);
int log_buffer_empty(struct log_buffer *buffer);
int log_init(void);
void log_exit(void);
#endif /* HTTCSEC_LOG_IMPL_H_ */
