/*
 * list.h
 *
 *  Created on: Sep 16, 2014
 *      Author: wangtao
 */

#ifndef LIST_H_
#define LIST_H_
#include "types.h"
#ifdef __cplusplus
extern "C" {
#endif

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *new1,
			      struct list_head *prev, struct list_head *next)
{
	next->prev = new1;
	new1->next = next;
	new1->prev = prev;
	prev->next = new1;
}

static inline void list_add(struct list_head *new1, struct list_head *head)
{
	__list_add(new1, head, head->next);
}

static inline void list_add_tail(struct list_head *new1, struct list_head *head)
{
	__list_add(new1, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = (struct list_head *)0xDEADBEEF;
	entry->prev = (struct list_head *)0xBEEFDEAD;
}

static inline void list_del_init(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	INIT_LIST_HEAD(entry);
}

static inline void list_replace(struct list_head *old,
				struct list_head *new1)
{
	new1->next = old->next;
	new1->next->prev = new1;
	new1->prev = old->prev;
	new1->prev->next = new1;
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}


#define list_entry(ptr, type, member) \
	httc_util_container_of(ptr, type, member)


#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head); 	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))


#define list_for_each_entry_safe(pos, n, head, member)			\
		for (pos = list_entry((head)->next, typeof(*pos), member),	\
			n = list_entry(pos->member.next, typeof(*pos), member); \
			 &pos->member != (head);					\
			 pos = n, n = list_entry(n->member.next, typeof(*n), member))


#ifdef __cplusplus
}
#endif

#endif /* FILE_UTIL_H_ */
