#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/syscalls.h>
#include <linux/profile.h>
#include <linux/notifier.h>
#include "utils/debug.h"
#include "policy/feature_configure.h"
#include "msg/command.h"
#include "process_protect.h"

DEFINE_MUTEX(mutex);
#define NODE_ITEM_USED 0x01
#define NODE_ITEM_FREE 0x00

#define HTTC_PROCESS_PROTECT_ON    0x02
#define HTTC_PROCESS_PROTECT_OFF   0x00
static volatile int g_protect_process_switch = 0;
struct process_node 
{
	pid_t pid;
	int inuse;
	//int flag;
};

static struct process_node protect_list[PROCESS_MAX_NUM];

static int is_exist_list(pid_t pid)
{
	int ret = -1;
	struct process_node *pos = NULL;
	int loop = 0;

	mutex_lock(&mutex);
	for(loop = 0; loop < PROCESS_MAX_NUM; loop++)
	{
		pos = &protect_list[loop];
		if( pos->pid == pid )
		{
			ret = loop;
			break;
		}
		else
			pos = NULL;
	}
	mutex_unlock(&mutex);
	return ret;
}

struct process_node* get_free_item(void)
{
	struct process_node *pos;
	int loop = 0;

	mutex_lock(&mutex);
	for(loop = 0; loop < PROCESS_MAX_NUM; loop++)
	{
		pos = &protect_list[loop];
		if( pos->inuse == NODE_ITEM_FREE )
		{
			break;
		}
		else
			pos = NULL;
	}
	mutex_unlock(&mutex);
	return pos;
}

//int process_protect_on(int status)
//{
//	//int ret = -1;
//	//struct process_node *pos = NULL;
//	//int loop = 0;
//
//	//mutex_lock(&mutex);
//
//	//for(loop = 0; loop < PROCESS_MAX_NUM; loop++)
//	//{
//	//	pos = &protect_list[loop];
//	//	if(pos->inuse == NODE_ITEM_FREE)
//	//	       continue;	
//
//	//	if(( status & HTTC_PROCESS_PROTECT_ON) == HTTC_PROCESS_PROTECT_ON )
//	//	{
//	//		pos->flag = HTTC_PROCESS_PROTECT_ON;
//	//		DEBUG_MSG(HTTC_TSB_INFO, "Enter[%s] process[%d] protected on status[0x%x]\n",__func__,pos->pid,status);
//	//	}
//
//	//	if(( status & HTTC_PROCESS_PROTECT_ON) == HTTC_PROCESS_PROTECT_OFF )
//	//	{
//	//		pos->flag = HTTC_PROCESS_PROTECT_OFF;
//	//		DEBUG_MSG(HTTC_TSB_INFO, "Enter[%s] process[%d] protected off status[0x%x]\n",__func__,pos->pid,status);
//	//	}
//	//}
//
//	if(( status & HTTC_PROCESS_PROTECT_ON) == HTTC_PROCESS_PROTECT_ON )
//	{
//		//pos->flag = HTTC_PROCESS_PROTECT_ON;
//		g_protect_process_switch=1;
//		DEBUG_MSG(HTTC_TSB_INFO, "Enter[%s] protected on status[0x%x]\n",__func__,status);
//	}
//
//	if(( status & HTTC_PROCESS_PROTECT_ON) == HTTC_PROCESS_PROTECT_OFF )
//	{
//		//pos->flag = HTTC_PROCESS_PROTECT_OFF;
//		g_protect_process_switch=0;
//		DEBUG_MSG(HTTC_TSB_INFO, "Enter[%s] protected off status[0x%x]\n",__func__,status);
//	}
//	
//
//	//mutex_unlock(&mutex);
//
//	return 0;
//}

void process_protection_conf_notify_func(int status)
{
	if(( status & HTTC_PROCESS_PROTECT_ON) == HTTC_PROCESS_PROTECT_ON )
	{
		g_protect_process_switch=1;
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter[%s] protected on status[0x%x]\n",__func__,status);
	}

	if(( status & HTTC_PROCESS_PROTECT_ON) == HTTC_PROCESS_PROTECT_OFF )
	{
		g_protect_process_switch=0;
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter[%s] protected off status[0x%x]\n",__func__,status);
	}

	return;
}

static long ioctl_user_protect_request(unsigned long param)
{
	struct process_node *node = NULL;
	int ret = 0;
	pid_t pid;

	pid = current->pid;

	ret = is_exist_list(pid);
	if (ret >= 0) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "process pid[%d] name[%s] already in protect list\n", current->pid,current->comm);
		return -EEXIST;
	}

	node = get_free_item();
	if(node == NULL)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "maximum[%d] number of protected processes exceeded\n", PROCESS_MAX_NUM );
		return -1;
	}

	mutex_lock(&mutex);
	node->pid = pid;
	node->inuse = NODE_ITEM_USED;
	//node->flag = HTTC_PROCESS_PROTECT_ON; 
	mutex_unlock(&mutex);

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter[%s] Add protect process pid[%d] name[%s]\n",__func__, current->pid,current->comm);

	return 0;
}

static long ioctl_user_unprotect_request(unsigned long param)
{
	struct process_node *node = NULL;
	int ret = 0;
	pid_t pid;

	pid = current->pid;

	ret = is_exist_list(pid);
	if (ret < 0) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter[%s] process pid[%d] name[%s] not in protect list\n",__func__, current->pid,current->comm);
		return -EEXIST;
	}

	node = &protect_list[ret];
	mutex_lock(&mutex);
	memset(node,0x00,sizeof(struct process_node));
	mutex_unlock(&mutex);

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter[%s] remove protect process pid[%d] name[%s]\n",__func__, current->pid,current->comm);

	return 0;
}

void unprotect_request(pid_t pid)
{
	int ret;
	struct process_node *pos;

	ret = is_exist_list(pid);
	if ( ret < 0 ) 
	{
		return;
	}

	mutex_lock(&mutex);
	pos = &protect_list[ret];
	memset(pos,0x00,sizeof(struct process_node));
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter[%s] Remove process pid[%d] name[%s]\n",__func__, current->pid, current->comm);
	mutex_unlock(&mutex);

	return;
}

int is_protect_task(struct task_struct *p)
{
	int ret = 0;
	pid_t pid;

	if(g_protect_process_switch==0)
		return 0;

	pid = p->pid; 
	ret = is_exist_list(pid);
	if (ret >= 0) 
	{
		return 1;
		//if( protect_list[ret].flag == HTTC_PROCESS_PROTECT_ON )
		//	return 1;  /* protected */
		//else
		//	return 0;  /* unprotected */
	}

	return 0;          /* unprotected */
}
EXPORT_SYMBOL( is_protect_task );

static int task_exit_handler(struct notifier_block *nb, unsigned long val, void *data)
{
        int ret = 0;
        struct task_struct *tsk = NULL;

        if (data != NULL)
        {
                tsk = (struct task_struct *) data;
		unprotect_request(tsk->pid);
        }

        return ret;
}

static struct notifier_block exit_notifier =
{
        .notifier_call = task_exit_handler,
};

int httc_process_protect_init(void)
{
	int ret;
	ret = profile_event_register(PROFILE_TASK_EXIT, &exit_notifier);
	if (ret)
	{
		ret = -EINVAL;
		return ret;
	}

	if (httcsec_io_command_register(COMMAND_PROCESS_PROTECT_REQ , (httcsec_io_command_func)ioctl_user_protect_request)) 
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n",COMMAND_PROCESS_PROTECT_REQ);
	}

	if (httcsec_io_command_register(COMMAND_PROCESS_UNPROTECT_REQ , (httcsec_io_command_func)ioctl_user_unprotect_request)) 
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n",COMMAND_PROCESS_UNPROTECT_REQ);
	}


	return 0;
}

void httc_process_protect_exit(void)
{
	profile_event_unregister(PROFILE_TASK_EXIT, &exit_notifier);
	httcsec_io_command_unregister(COMMAND_PROCESS_PROTECT_REQ , (httcsec_io_command_func)ioctl_user_protect_request);
	httcsec_io_command_unregister(COMMAND_PROCESS_UNPROTECT_REQ , (httcsec_io_command_func)ioctl_user_unprotect_request);
	return;
}
