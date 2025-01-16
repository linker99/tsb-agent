#include <linux/kernel.h>
#include <linux/module.h>


struct task_struct;

static int (*process_msg_func)(struct task_struct *tsk, const char *fullpath,
			       const char *process_digest, int type);


static int dummy_process_msg(struct task_struct *tsk, const char *fullpath,
			     const char *process_digest, int type)
{
	return 0;
}

void fac_process_msg_set(struct task_struct *tsk, const char *fullpath,
		      const char *process_digest, int type)
{
	process_msg_func(tsk, fullpath, process_digest, type);
}
EXPORT_SYMBOL(fac_process_msg_set);

void process_msg_register(void *func)
{
	if (process_msg_func == (void *)dummy_process_msg)
		process_msg_func = func;
}
EXPORT_SYMBOL(process_msg_register);

void process_msg_unregister(void *func)
{
	if (process_msg_func == func)
		process_msg_func = (void *)dummy_process_msg;
}
EXPORT_SYMBOL(process_msg_unregister);


void fac_process_msg_init(void)
{
	process_msg_func = (void *)dummy_process_msg;
}
