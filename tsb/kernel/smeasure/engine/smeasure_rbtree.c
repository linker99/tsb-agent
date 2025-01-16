#include "smeasure_rbtree.h"

/**
 * @brief 默认key比较函数
 */
int smeasure_rbtree_compare(unsigned char *k1 ,unsigned char *k2){
    return (int)(*((int *)k1) - *((int *)k2));
}

/**
 * @brief 红黑树初始化函数 
 */
void smeasure_rbtree_init(smeasure_rbroot_t *tree ,void *lock ,__rbtree_destroy destroy ,__rbtree_compare compare)
{
    tree->root = RB_ROOT;
    tree->lock = lock;
    tree->flag = 0;
    tree->destroy = destroy;
    tree->compare = compare ? compare : smeasure_rbtree_compare;
}

/**
 * @brief 红黑树查找
 */
smeasure_rbnode_t *smeasure_rbtree_search(smeasure_rbroot_t *tree ,unsigned char *key)
{
    struct rb_node *node = tree->root.rb_node; 
    smeasure_rbnode_t *data = NULL;

    if(!tree->compare){return NULL;}

    while (node) 
    {
	int result;
        data = (smeasure_rbnode_t *)node;

        result = tree->compare(key ,data->key);
        if(!result){break;}

        if (result < 0){
            node = node->rb_left;
        }else if(result > 0){
            node = node->rb_right;
        }else{
            break;
        }

        data = NULL;
    }

    return data;
}

/**
 * @brief 添加红黑树
 */
int smeasure_rbtree_push(smeasure_rbroot_t *tree ,smeasure_rbnode_t *data)
{
    struct rb_node **new = &(tree->root.rb_node) ,*parent = NULL;
    smeasure_rbnode_t *this = NULL;
    int result = -12334;

    if(!tree->compare){return result;}

    /* Figure out where to put new node */
    while (*new) 
    {
        this = (smeasure_rbnode_t *)container_of(*new ,smeasure_rbnode_t ,rbnode);
        result = tree->compare(data->key ,this->key);
        parent = *new;
        if (result < 0){
            new = &((*new)->rb_left);
        }else{
            new = &((*new)->rb_right);
        }
    }

    /* Add new node and rebalance tree. */
    rb_link_node(&data->rbnode, parent, new);

    rb_insert_color(&data->rbnode, (struct rb_root *)tree);

    return result;
}

/**
 * @brief 删除红黑树 
 */
void smeasure_rbtree_pop(smeasure_rbroot_t *tree ,smeasure_rbnode_t *data){
    rb_erase(&data->rbnode , &tree->root);
}


