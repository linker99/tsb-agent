#ifndef __MEMCMP_ACTION_H
#define __MEMCMP_ACTION_H

#include "dmeasure.h"

struct memcmp_action {
	struct dmeasure_action action;
	char *base;
	int length;
	int status;
	char origin[0];
};

struct memcmp_action *memcmp_action_alloc_init(const char *name, void *base,
					       int data_length, int interval);
void memcmp_action_free(struct memcmp_action *action);
#endif
