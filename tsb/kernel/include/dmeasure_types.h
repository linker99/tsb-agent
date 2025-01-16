#ifndef __DMEASURE_TYPES_H__
#define __DMEASURE_TYPES_H__

#define MAX_ACTION_NAME_LENGTH		64

#define DM_ACTION_KSECTION_NAME   "kernel_section"
#define DM_ACTION_SYSCALLTABLE_NAME   "syscall_table"
#define DM_ACTION_IDTTABLE_NAME   "idt_table"
#define DM_ACTION_TASKLIST_NAME   "task_list"
#define DM_ACTION_MODULELIST_NAME "module_list"
#define DM_ACTION_FILESYSTEM_NAME "filesystem"
#define DM_ACTION_NETWORK_NAME    "network"

// dmeasure index
enum {
	DMEASURE_SECTION_ACTION = 0,
	DMEASURE_SYSCALL_ACTION,
	DMEASURE_IDT_ACTION,
	//DMEASURE_TASK_ACTION,
	DMEASURE_MODULE_ACTION,
	DMEASURE_FILESYSTEM_ACTION,
	DMEASURE_NET_ACTION,
	DMEASURE_MAX_ACTION,
};

struct dmeasure_node {
	char name[MAX_ACTION_NAME_LENGTH];
	int (*check) (void *data);
};

struct dmeasure_point {
	char name[MAX_ACTION_NAME_LENGTH];
	int type;
};

int dmeasure_register_action(int index, struct dmeasure_node *node);
int dmeasure_unregister_action(int index, struct dmeasure_node *node);

int dmeasure_process_register_action(int index, struct dmeasure_node *node);
int dmeasure_process_unregister_action(int index, struct dmeasure_node *node);

#endif
