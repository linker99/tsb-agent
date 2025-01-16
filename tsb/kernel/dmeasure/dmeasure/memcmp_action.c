/* #include <linux/vmalloc.h> */
/* #include <linux/module.h> */
/* #include "memcmp_action.h" */
/* #include "../hook/syscall.h" */
/* #include "../utils/debug.h" */

/* int memcmp_default_check(void *data) */
/* { */
/*         int ret = 0; */
/*         struct memcmp_action *info = (struct memcmp_action *)data; */

/*         ret = memcmp(info->base, info->origin, info->length); */
/*         if (ret) { */
/*                 if (!strcmp(info->action.name, "TextSection")) { */
/*                         DEBUG_MSG(DEBUG_FOR_LOG, "TextSection Dmeasure Error!\n"); */
/*                         goto out; */
/*                 } */
/*                 if (!strcmp(info->action.name, "SysCallTable")) { */
/*                         DEBUG_MSG(DEBUG_FOR_LOG, "SysCallTable Dmeasure Error!\n"); */
/*                         check_syscall_table(); */
/*                         goto out; */
/*                 } */
/*                 if (!strcmp(info->action.name, "IDT")) { */
/*                         DEBUG_MSG(DEBUG_FOR_LOG, "Idt Dmeasure Error!\n"); */
/*                         goto out; */
/*                 } */
/*         } else { */
/*                 if (!strcmp(info->action.name, "TextSection")) { */
/*                         DEBUG_MSG(DEBUG_FOR_LOG, "TextSection Dmeasure Health!\n"); */
/*                         goto out; */
/*                 } */
/*                 if (!strcmp(info->action.name, "SysCallTable")) { */
/*                         DEBUG_MSG(DEBUG_FOR_LOG, "SysCallTable Dmeasure Health!\n"); */
/*                         goto out; */
/*                 } */
/*                 if (!strcmp(info->action.name, "IDT")) { */
/*                         DEBUG_MSG(DEBUG_FOR_LOG, "Idt Dmeasure Health!\n"); */
/*                         goto out; */
/*                 } */
/*         } */

/* out: */
/*         return ret; */
/* } */

/* struct memcmp_action *memcmp_action_alloc_init(const char *name, void *base, int data_length, int interval) */
/* { */
/*         struct memcmp_action *action = (struct memcmp_action *)vzalloc(sizeof(struct memcmp_action) + data_length); */
/*         if (likely(action)) { */
/*                 strncpy(action->action.name, name, MAX_ACTION_NAME_LENGTH - 1); */
/*                 action->action.interval = interval; */
/*                 action->action.status = ACTION_STATUS_ENABLED; */
/*                 action->action.check = memcmp_default_check; */
/*                 action->action.data = action; */

/*                 action->base = base; */
/*                 action->length = data_length; */
/*                 memcpy(action->origin, base, data_length); */
/*         } */
/*         return action; */
/* } */
/* EXPORT_SYMBOL(memcmp_action_alloc_init); */

/* void memcmp_action_free(struct memcmp_action *action) */
/* { */
/*         if (action) { */
/*                 vfree(action); */
/*                 action = NULL; */
/*         } */
/* } */
/* EXPORT_SYMBOL(memcmp_action_free); */
