#ifndef __DMEASURE_H
#define __DMEASURE_H

#include "dmeasure_types.h"

#define ACTION_STATUS_ENABLED 		0x1
#define ACTION_STATUS_DISABLED 		0x0

#define DEFAULT_DMEASURE_PERIOD  10000  /* ms */

struct dmeasure_action 
{
	char name[MAX_ACTION_NAME_LENGTH];
	int inuse;
	int interval;
	volatile unsigned long status;
	int measure_mode;   /* 0 - soft; 1 - tpcm */
	struct delayed_work dwork;
	int (*check) (void *data);
	void *private_data;
};

int dmeasure_init(void);
void dmeasure_exit(void);

void dmeasure_actions(struct work_struct *httc_work);
int modify_dmeasure_action(int interval, int status, const char *name);
int modify_dmeasure_switch(const char *name, int status);
int dmeasure_trigger_action(unsigned long i_ino, int type);

#endif
