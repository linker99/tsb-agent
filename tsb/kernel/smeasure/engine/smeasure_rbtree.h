#ifndef __SMEASURE_ALGO_H__
#define __SMEASURE_ALGO_H__

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/rbtree.h>
#include <linux/types.h>

/**
 * @brief 红黑树算法 
 */
typedef void (*__rbtree_destroy)(struct rb_node *);

typedef int (*__rbtree_compare)(unsigned char *k1 ,unsigned char *k2);

typedef struct __smeasure_rbnode_s{
	struct rb_node rbnode;
	unsigned int flag;
	unsigned char key[32];
}smeasure_rbnode_t;

typedef struct __smeasure_rbroot_s{
	struct rb_root root;
	void *lock;
	unsigned long int flag;
	__rbtree_compare compare;
	__rbtree_destroy destroy;
}smeasure_rbroot_t;

void smeasure_rbtree_init(smeasure_rbroot_t *tree ,void *lock ,
		__rbtree_destroy destroy ,__rbtree_compare compare);

smeasure_rbnode_t *smeasure_rbtree_search(smeasure_rbroot_t *tree ,unsigned char *);

int smeasure_rbtree_push(smeasure_rbroot_t *tree , smeasure_rbnode_t *data);

void smeasure_rbtree_pop(smeasure_rbroot_t *tree ,smeasure_rbnode_t *data);


#endif
