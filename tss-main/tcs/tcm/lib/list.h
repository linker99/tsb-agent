/*
 * list.h
 *
 *  Created on: Apr 2, 2021
 *      Author: root
 */

#ifndef LIB_LIST_H_
#define LIB_LIST_H_

#define container_of(ptr, type, member) \
	((type *)((uintptr_t)(ptr) - (uintptr_t)offsetof(type, member)))

struct list_head {
	struct list_head *prev, *next;
};

/* Get an entry from the list
 *  ptr - the address of this list_head element in "type"
 *  type - the data type that contains "member"
 *  member - the list_head element in "type"
 */
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_next_entry(ptr, type, member) \
	list_entry((ptr)->member.next, type, member)

/* Get each entry from a list
 *  pos - A structure pointer has a "member" element
 *  head - list head
 *  member - the list_head element in "pos"
 *  type - the type of the first parameter
 */
#define list_for_each_entry(pos, head, member, type)			\
	for (pos = list_first_entry(head, type, member);		\
		 &pos->member != (head);				\
		 pos = list_next_entry(pos, type, member))

#define list_for_each_entry_safe(pos, n, head, member, type)		\
	for (pos = list_first_entry(head, type, member),		\
		 n = list_next_entry(pos, type, member);		\
		 &pos->member != (head);				\
		 pos = n, n = list_next_entry(n, type, member))

/* Helper macros to iterate over a list. The structure pointed
 * to by "pos" must have a list_head member named "list".
 */
#define for_each_helper(pos, head, type) \
	list_for_each_entry(pos, head, list, type)

#define for_each_safe_helper(pos, n, head, type) \
	list_for_each_entry_safe(pos, n, head, list, type)

#define list_empty(entry) ((entry)->next == (entry))

static inline void list_init(struct list_head *entry)
{
	entry->prev = entry->next = entry;
}

static inline void list_add(struct list_head *entry, struct list_head *head)
{
	entry->next = head->next;
	entry->prev = head;

	head->next->prev = entry;
	head->next = entry;
}

static inline void list_add_tail(struct list_head *entry,
	struct list_head *head)
{
	entry->next = head;
	entry->prev = head->prev;

	head->prev->next = entry;
	head->prev = entry;
}

static inline void list_del(struct list_head *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
	entry->next = entry->prev = NULL;
}

static inline void list_cut(struct list_head *list, struct list_head *head)
{
	if (list_empty(head)) {
		list_init(list);
		return;
	}

	list->next = head->next;
	list->next->prev = list;
	list->prev = head->prev;
	list->prev->next = list;

	list_init(head);
}

static inline void list_splice_front(struct list_head *list, struct list_head *head)
{
	list->next->prev = head;
	list->prev->next = head->next;
	head->next->prev = list->prev;
	head->next = list->next;
}



#endif /* LIB_LIST_H_ */
