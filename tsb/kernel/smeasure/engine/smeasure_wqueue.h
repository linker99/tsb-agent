#ifndef __SMEASURE_WQUEUE_H__
#define __SMEASURE_WQUEUE_H__

#include "smeasure_rbtree.h"
#include "linux/wait.h"
#include <linux/delay.h>

typedef struct smeasure_wqueue_s{
    smeasure_rbnode_t rbnode;
    wait_queue_head_t wait;
    unsigned int refer;
    unsigned int condition;
    unsigned int result;
    unsigned flag;
    spinlock_t *lock;
}smeasure_wqueue_t;

//初始化等待队列
void smeasure_wqueue_init(void);

void smeasure_wqueue_wake_up(smeasure_wqueue_t *queue ,int ret);

smeasure_wqueue_t *smeasure_wqueue_handle(char *path ,int *ret ,int *t);

#endif
