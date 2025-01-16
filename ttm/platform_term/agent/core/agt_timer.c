#include "agt_timer.h"
#include "ht_util.h"
#include "agt_log.h"

static unsigned long long per_run_time;

static int timer_task_run(void *agent, void *args)
{
	int ret, attr;
	agent_t *master = (agent_t *)agent;
	rbnode_t *this = (rbnode_t *)args;
	rbroot_t *tree = &master->time_rbtree.tree;

	//如果this->args为空，则回调的第二个参数依旧传this，否则传this->args
	if (this->callback) {
		ret = (this->args == NULL ? this->callback(agent, args) : this->callback(agent, this->args));
	}

	if (this->attribute == TIMER_EXEC_UNTIL_SUCCESS)
		attr = (ret == HTTC_OK ? TIMER_EXEC_DIED : TIMER_EXEC_CYCLE);
	else
		attr = this->attribute;
	
	switch (attr) {
	case TIMER_EXEC_DIED:
		
	case TIMER_EXEC_ONCE:
		agent_free(this);
		break;
	
	case TIMER_EXEC_CYCLE:
		
		pthread_mutex_lock(&master->time_rbtree.lock);
		this->key = ht_getmill_time() + this->internal;
		rbtree_push(tree, this);
		pthread_mutex_unlock(&master->time_rbtree.lock);
		
		break;

	default:
		agent_log(HTTC_ERROR, "timer error attribute");
	}

	return 0;
}

void *timer_run(void *args)
{
	agent_t *master = (agent_t *)args;
	int interval = master->config.common.timer.check_per_millisecond * 1000;
	struct rb_node *node, *tmp;
	rbnode_t *this;
	rbroot_t *tree = &master->time_rbtree.tree;

	agent_log(HTTC_INFO, "agent pthread timer start.");

	while(1) {
		if (master->want_destroy) {
			agent_worker_cleanup(master, 1);
		}

		pthread_mutex_lock(&master->time_rbtree.lock);

		unsigned long long time_now = ht_getmill_time();

		/* 系统时间调到了之前,需重新调整定时任务的触发时间 */
		if(time_now <= per_run_time) {
			agent_log(HTTC_WARN, "the system has change to history time!");

			node = rb_first(&tree->root);
			while (node) {
				this = (rbnode_t *)container_of(node, rbnode_t, rbnode);
				this->key = time_now + this->internal;
				tmp = rb_next(node);
				node = tmp;
			}

			goto next;
		}

		while((node = rb_first(&tree->root)) != NULL) {
			this = (rbnode_t *)container_of(node, rbnode_t, rbnode);

			if(this->key <= time_now) {
				agent_task_t *task = (agent_task_t *)agent_calloc(sizeof(agent_task_t));
				if(!task) {
					agent_log(HTTC_ERROR, "malloc task fail!");
				}
				else {
					task->run = timer_task_run;
					task->ctx = this;
					strncpy(task->name, this->name, sizeof(task->name) - 1);

					rbtree_pop(tree, this);
					pthread_mutex_lock(&master->lock);
					list_add_tail(&task->list, &master->task_list);
					master->wait_task_number++;
					pthread_mutex_unlock(&master->lock);
					pthread_cond_broadcast(&master->cond);
					
				}
			}
			else {
				break;
			}
		}

next:
		per_run_time = time_now;
		pthread_mutex_unlock(&master->time_rbtree.lock);

		usleep(interval);
	}
}

rbnode_t *timer_add_real(void *agent, int attribute, int internal,
							int (*callback)(void *, void *), const char *name)
{
	agent_t *master = (agent_t *)agent;
	rbnode_t *node = (rbnode_t *)agent_calloc(sizeof(rbnode_t));
	if(!node) {
		agent_log(HTTC_INFO, "no memory for new timer node");
		return NULL;
	}

	node->attribute = attribute;
	node->internal = internal;
	node->key = ht_getmill_time() + 500;		//默认500毫秒后执行
	node->callback = callback;
	node->args = NULL;
	strncpy(node->name, name, sizeof(node->name) - 1);

    
	pthread_mutex_lock(&master->time_rbtree.lock);
	rbtree_push(&master->time_rbtree.tree, node);
	pthread_mutex_unlock(&master->time_rbtree.lock);

	return node;
}

/* 支持传参 */
rbnode_t *timer_add_real_args(void *agent, int attribute, int internal,
								int (*callback)(void *, void *), void *args, const char *name)
{
	agent_t *master = (agent_t *)agent;
	rbnode_t *node = (rbnode_t *)agent_calloc(sizeof(rbnode_t));
	if(!node) {
		agent_log(HTTC_INFO, "no memory for new timer node");
		return NULL;
	}

	node->attribute = attribute;
	node->internal = internal;
	node->key = ht_getmill_time() + 500;		//默认500毫秒后执行
	node->callback = callback;
	node->args = args;
	strncpy(node->name, name, sizeof(node->name) - 1);

    
	pthread_mutex_lock(&master->time_rbtree.lock);
	rbtree_push(&master->time_rbtree.tree, node);
	pthread_mutex_unlock(&master->time_rbtree.lock);

	return node;
}
int timer_update_internal(void *agent, void *node, int new_internal)
{
	rbnode_t *rbt_node = (rbnode_t *)node;
	rbt_node->internal = new_internal;

	return 0;
}
