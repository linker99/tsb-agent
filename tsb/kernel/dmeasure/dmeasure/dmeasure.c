#include <linux/kthread.h>
#include <linux/workqueue.h>
#include "dmeasure.h"
#include "utils/debug.h"
#include "../policy/policy_dmeasure.h"
#include "tsbapi/tsb_measure_kernel.h"
#include "function_types.h"

struct delayed_work dmeasure_work;  
struct workqueue_struct *httc_wq = NULL;  

static struct dmeasure_feature_conf *dmeasure_feature = NULL;

DEFINE_MUTEX(dmutex);

static struct dmeasure_action dm_action[DMEASURE_MAX_ACTION] = {
	{
	 .name = DM_ACTION_KSECTION_NAME,
	 .status = ACTION_STATUS_DISABLED,
	 .interval = DEFAULT_DMEASURE_PERIOD,
	 .measure_mode = 0,
	 .check = NULL,
	 },
	{
	 .name = DM_ACTION_SYSCALLTABLE_NAME,
	 .status = ACTION_STATUS_DISABLED,
	 .interval = DEFAULT_DMEASURE_PERIOD,
	 .measure_mode = 0,
	 .check = NULL,
	 },
	{
	 .name = DM_ACTION_IDTTABLE_NAME,
	 .status = ACTION_STATUS_DISABLED,
	 .interval = DEFAULT_DMEASURE_PERIOD,
	 .measure_mode = 0,
	 .check = NULL,
	 },
	{
	 .name = DM_ACTION_MODULELIST_NAME,
	 .status = ACTION_STATUS_DISABLED,
	 .interval = DEFAULT_DMEASURE_PERIOD,
	 .measure_mode = 0,
	 .check = NULL,
	 },
	{
	 .name = DM_ACTION_FILESYSTEM_NAME,
	 .status = ACTION_STATUS_DISABLED,
	 .interval = DEFAULT_DMEASURE_PERIOD,
	 .measure_mode = 0,
	 .check = NULL,
	 },
	{
	 .name = DM_ACTION_NETWORK_NAME,
	 .status = ACTION_STATUS_DISABLED,
	 .interval = DEFAULT_DMEASURE_PERIOD,
	 .measure_mode = 0,
	 .check = NULL,
	 },
};

int dmeasure_register_action(int index, struct dmeasure_node *node)
{
	int ret = 0;

	mutex_lock(&dmutex);
	if (strncmp(dm_action[index].name, node->name,
	    strlen(dm_action[index].name)) == 0)
	{
		bool issuc;
		dm_action[index].check = node->check;
		INIT_DELAYED_WORK(&dm_action[index].dwork, dmeasure_actions);
		dm_action[index].inuse = 1;
		issuc = schedule_delayed_work(&dm_action[index].dwork, 3*HZ);
		if ( !issuc )
		{
			DEBUG_MSG(HTTC_TSB_INFO, "[%s]added delay work failed\n",__func__);
			mutex_unlock(&dmutex);
			return -EINVAL;
		}
	}
	else
		ret = -EINVAL;
	mutex_unlock(&dmutex);
	DEBUG_MSG(HTTC_TSB_DEBUG, "debug info [%s] index[%d] name[%s] interval[%d]\n",__func__, index, dm_action[index].name, dm_action[index].interval);
	return ret;
}
EXPORT_SYMBOL(dmeasure_register_action);

int dmeasure_unregister_action(int index, struct dmeasure_node *node)
{
	int ret = 0;
	mutex_lock(&dmutex);

	if (strncmp(dm_action[index].name, node->name,
	    strlen(dm_action[index].name)) == 0)
	{
		if( dm_action[index].inuse == 1)
			cancel_delayed_work(&dm_action[index].dwork);

		dm_action[index].check = NULL;
	}
	else
		ret = -EINVAL;

	mutex_unlock(&dmutex);
	return ret;
}
EXPORT_SYMBOL(dmeasure_unregister_action);

void dmeasure_actions(struct work_struct *httc_work)
{
	int  ret = 0;
	unsigned int period;
	bool issuc;
	struct delayed_work *delay_work; 
	struct dmeasure_action *action;

	delay_work = container_of(httc_work, struct delayed_work, work);
        action = container_of(delay_work, struct dmeasure_action, dwork);

	if (!dmeasure_feature->is_enabled)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "[%s]dmeasure_switch[%d], dmeasure function not have!\n", __func__, dmeasure_feature->is_enabled);
		goto out;
	}

	if ((action->status & ACTION_STATUS_ENABLED) && (!action->measure_mode))
	{
		ret = action->check(action->private_data);
	}
out:
	if (action->interval <= 0)
		period = DEFAULT_DMEASURE_PERIOD;	
	else 
		period = action->interval;	

	issuc = schedule_delayed_work(&action->dwork, msecs_to_jiffies(period));
	if ( !issuc )
	{
		DEBUG_MSG(HTTC_TSB_INFO, "[%s]added delay work failed\n",__func__);
	}
}

int modify_dmeasure_action(int interval, int status, const char *name)
{
	int i, ret = 0;
	struct dmeasure_action *action = NULL;

	mutex_lock(&dmutex);
	for (i = 0; i < DMEASURE_MAX_ACTION; i++) 
	{
		action = &dm_action[i];
		if (!strcmp(action->name, name)) 
		{
			action->interval = interval;
			action->status = status;
			DEBUG_MSG(HTTC_TSB_INFO,
				  "modify:[%s] dmeasure action!\n", name);
			goto out;
		}
	}
	DEBUG_MSG(HTTC_TSB_DEBUG, "dmeasure [%s] action do not regist!\n", name);
out:
	mutex_unlock(&dmutex);
	return ret;
}

int dmeasure_init(void)
{
	int ret = 0;

	dmeasure_feature = get_dmeasure_feature_conf();
	if(dmeasure_feature->measure_mode)
	{
		DEBUG_MSG(HTTC_TSB_DEBUG, "dmeasure_feature->measure_mode[%d], dmeasure kernel_section,syscall_table,idt_table using tpcm, soft dmeasure stop!\n", dmeasure_feature->measure_mode);
		dm_action[0].measure_mode = dmeasure_feature->measure_mode;
		dm_action[1].measure_mode = dmeasure_feature->measure_mode;
		dm_action[2].measure_mode = dmeasure_feature->measure_mode;
	}
	else
		DEBUG_MSG(HTTC_TSB_DEBUG, "dmeasure_feature->measure_mode[%d], dmeasure  kernel_section,syscall_table,idt_table using soft!\n", dmeasure_feature->measure_mode);

	return ret;
}

void dmeasure_exit(void)
{
	return;
}

/* dmeasure interface */
int tsb_measure_kernel_memory(const char *name)
{
	struct dmeasure_action *action = NULL;
	struct dmeasure_point point;
	int i, ret = 0;

	mutex_lock(&dmutex);
	for (i = 0; i < DMEASURE_MAX_ACTION; i++) 
	{
		action = &dm_action[i];

		if (strcmp(action->name, name)!=0) 
		{
			ret = TSB_ERROR_DMEASURE_NAME;
			continue;
		}

		if (!(action->status & ACTION_STATUS_ENABLED)) 
		{
			ret = TSB_ERROR_DMEASURE_POLICY_NOT_FOUND;
			break;
		}

		memset(&point, 0, sizeof(point));
		point.type = DMEASURE_TRIGGER;
		memcpy(point.name, action->name, MAX_ACTION_NAME_LENGTH);

		if (action->check) 
		{
			ret = action->check((void *)&point);
			if(ret)
				ret = TSB_MEASURE_FAILE;
			break;
		}
	}
	mutex_unlock(&dmutex);

	return ret;
}
EXPORT_SYMBOL(tsb_measure_kernel_memory);

int tsb_measure_kernel_memory_all(void)
{
	struct dmeasure_action *action = NULL;
	struct dmeasure_point point;
	int i, ret = 0;
	int retval = 0;

	mutex_lock(&dmutex);
	for (i = 0; i < DMEASURE_MAX_ACTION; i++) 
	{
		action = &dm_action[i];

		// 接口只度量代码段、系统调用表、中断向量表
		if ((strcmp(action->name, DM_ACTION_KSECTION_NAME)!=0) && 
			(strcmp(action->name, DM_ACTION_SYSCALLTABLE_NAME)!=0) && 
			(strcmp(action->name, DM_ACTION_IDTTABLE_NAME)!=0))
			break;

		if (!(action->status & ACTION_STATUS_ENABLED)) 
		{
			continue;
			//mutex_unlock(&dmutex);
			//return TSB_ERROR_DMEASURE_POLICY_NOT_FOUND;
		}

		memset(&point, 0, sizeof(point));
		point.type = DMEASURE_TRIGGER;
		memcpy(point.name, action->name, MAX_ACTION_NAME_LENGTH);

		if (action->check) 
		{
			retval = action->check((void *)&point);
		}
		ret |= retval;
	}
	mutex_unlock(&dmutex);

	if(ret)
		return TSB_MEASURE_FAILE;

	return 0;
}
EXPORT_SYMBOL(tsb_measure_kernel_memory_all);
