#include "smeasure_wqueue.h"

static smeasure_rbroot_t __smeasure_wqueue_tree;

static DEFINE_SPINLOCK(__smeasure_wqueue_tree_lock_ptr);

static DEFINE_SPINLOCK(__smeasure_wqueue_node_lock_ptr);

//wqueue node 唤醒操作
void smeasure_wqueue_wake_up(smeasure_wqueue_t *queue ,int ret)
{
    //从tree里面移除
    spin_lock(&__smeasure_wqueue_tree_lock_ptr);

    smeasure_rbtree_pop(&__smeasure_wqueue_tree ,(smeasure_rbnode_t *)queue);

    spin_unlock(&__smeasure_wqueue_tree_lock_ptr);

    //调整节点状态
    spin_lock(&__smeasure_wqueue_node_lock_ptr);

    queue->condition = 1;

    queue->refer--;

    queue->result = ret;

	if(!(queue->refer))
	{
		kfree(queue);
		spin_unlock(&__smeasure_wqueue_node_lock_ptr);
	}
	else
	{
		spin_unlock(&__smeasure_wqueue_node_lock_ptr);
		//唤醒节点所在队列
		wake_up(&queue->wait);
	}

}

//等待队列的节点处理
void smeasure_wqueue_node_clean(smeasure_wqueue_t *queue ,int *ret)
{
    spin_lock(&__smeasure_wqueue_node_lock_ptr);

    *ret = queue->result;
    queue->refer--;

    if(!(queue->refer)){kfree(queue);}

    spin_unlock(&__smeasure_wqueue_node_lock_ptr);
}

//创建queue tree新节点
smeasure_wqueue_t *smeasure_wqueue_node_create(char *key)
{
    smeasure_wqueue_t *queue;

    queue = kzalloc(sizeof(smeasure_wqueue_t) ,GFP_KERNEL);
    if(unlikely(!queue)){return NULL;}

    //初始化节点
    queue->refer = 1;

    queue->condition = 0;

    init_waitqueue_head(&queue->wait);

    queue->result = 0;

    snprintf(queue->rbnode.key ,sizeof(queue->rbnode.key) ,"%s" ,key);

    return queue;
}

//查找是否已经推送过相同文件度量请求
smeasure_wqueue_t *smeasure_wqueue_node_search(char *key ,int *flag)
{
    smeasure_wqueue_t *queue;

    spin_lock(&__smeasure_wqueue_tree_lock_ptr);

    queue = (smeasure_wqueue_t *)smeasure_rbtree_search(&__smeasure_wqueue_tree ,key);
    //已经存在新节点
    if(queue){
        *flag = 1;
		queue->refer++;
        goto out;
    }

    queue = smeasure_wqueue_node_create(key);
    //创建新节点失败，内存不足
    if(unlikely(!queue)){
        *flag = 2;
        goto out;
    }

    smeasure_rbtree_push(&__smeasure_wqueue_tree ,(smeasure_rbnode_t *)queue);
    //新节点添加到tree
    *flag = 3;

out:
    spin_unlock(&__smeasure_wqueue_tree_lock_ptr);

    return queue;
}

//wqueue rbtree 比较函数
static int __smeasure_wqueue_tree_compare(unsigned char *k1 ,unsigned char *k2)
{
    return memcmp(k1 ,k2 ,strlen(k1) > strlen(k2) ? strlen(k2) : strlen(k1));
} 

//初始化等待队列
void smeasure_wqueue_init(void)
{
    smeasure_rbtree_init(&__smeasure_wqueue_tree ,&__smeasure_wqueue_tree_lock_ptr ,NULL ,__smeasure_wqueue_tree_compare);
}

//根据路径 相同文件加入到等待队列等待
smeasure_wqueue_t *smeasure_wqueue_handle(char *path ,int *ret ,int *t)
{
    smeasure_wqueue_t *queue;
    int flag = 0;

    //正常情况下queue返回不为空
    //只有在首次发送度量请求且内存不足的情况下才会返回空
    queue = smeasure_wqueue_node_search(path ,&flag);
    if(!queue && (flag == 2)){
        *t = 2;
        return NULL; 
    }

    //首次发送度量请求
    if(queue && (flag == 3)){
        return queue;
    }

    //重复的度量请求
    if(queue && (flag == 1)){
        wait_event(queue->wait ,queue->condition);
        smeasure_wqueue_node_clean(queue ,ret);
        *t = 3;
    }

    return NULL;
}
