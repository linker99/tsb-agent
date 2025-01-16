#ifndef __AGENT_TIMER_H__
#define __AGENT_TIMER_H__

#include <pthread.h>
#include "rbtree.h"

/*
 * agent :	the master
 * attribute :	TIMER_EXEC_ONCE/TIMER_EXEC_CYCLE/TIMER_EXEC_UNTIL_SUCCESS
 * internal :	the internal how long exec once
 * callback :	the handle!
 * name :	the name of the handle.
 * */
rbnode_t *timer_add_real(void *agent, int attribute, int internal, int (*callback)(void *, void *), const char *name);
rbnode_t *timer_add_real_args(void *agent, int attribute, int internal, int (*callback)(void *, void *), void *args, const char *name);


#define timer_add_once(agent, internal, callback) \
		timer_add_real(agent, TIMER_EXEC_ONCE, internal, callback, #callback)

#define timer_add_cycle(agent, internal, callback) \
		timer_add_real(agent, TIMER_EXEC_CYCLE, internal, callback, #callback)

#define timer_add_try_cycle(agent, internal, callback) \
		timer_add_real(agent, TIMER_EXEC_UNTIL_SUCCESS, internal, callback, #callback)


#define timer_add_once_args(agent, internal, callback, args) \
		timer_add_real_args(agent, TIMER_EXEC_ONCE, internal, callback, args, #callback)

#define timer_add_cycle_args(agent, internal, callback, args) \
		timer_add_real_args(agent, TIMER_EXEC_CYCLE, internal, callback, args, #callback)

#define timer_add_try_cycle_args(agent, internal, callback, args) \
		timer_add_real_args(agent, TIMER_EXEC_UNTIL_SUCCESS, internal, callback, args, #callback)

typedef int (*timer_callback_t)(void *master, void *arg);

struct agent_time_tree {
	pthread_mutex_t lock;
	rbroot_t tree;
};

enum {
	TIMER_EXEC_DIED,
	TIMER_EXEC_ONCE,
	TIMER_EXEC_CYCLE,
	TIMER_EXEC_UNTIL_SUCCESS,
};

void *timer_run(void *args);

int timer_update_internal(void *agent, void *node, int new_internal);
#endif
