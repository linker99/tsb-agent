#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <httcutils/mem.h>
#include <httcutils/convert.h>
#include <httcutils/debug.h>
#include <httcutils/list.h>
#include <httcutils/array.h>
#include <httcutils/types.h>
#include "tcsapi/tcs_file_integrity.h"
#include "file_integrity.h"
#include "tcfapi/tcf_error.h"
#define CONFIG_HASH_TABLE_SIZE (64 * 1024)
struct file_integrity_node{
	struct file_integrity_node *hash_next;//net poiter in memory
	struct list_head list;
	//struct file_integrity_node *list_next;
	//int offset;//store index
	int hash_index;
	struct  file_integrity_item_info item;
};

static char ZERO_HASH[DEFAULT_HASH_SIZE];
static struct {
	 struct file_integrity_node *hash_table[CONFIG_HASH_TABLE_SIZE];
	 struct list_head list;
	 unsigned int total;
	 unsigned int valid;
	 unsigned int length;
}  file_integrity_data = {
	.list = {&file_integrity_data.list,&file_integrity_data.list}
};
#define hash_value(hash)  *((uint16_t *)(hash))
//#define hash_value(hash)  0x1 & *((uint16_t *)(hash))
struct file_integrity_node *file_integrity_match(
		struct file_integrity_item *item){//return 1 success,0 otherwise
	struct file_integrity_node *node;
	int  index = hash_value(&item->data[0]);
	node = file_integrity_data.hash_table[index];
	//tpcm_debug("index = %d ,pointer=%d,hash_table[%d]=%d\n",index,pointer,index,pointer);
	for(;node;node = node->hash_next){

		if(node->item.path_length == 0){
			if((item->be_path_length == 0) && (!memcmp(item->data,node->item.data.data,DEFAULT_HASH_SIZE)))return node;
			else continue;
		}
		if(ntohs(item->be_path_length) != node->item.path_length )continue;
		if(memcmp(item->data,node->item.data.data,DEFAULT_HASH_SIZE))continue;
		if(memcmp(node->item.data.data + DEFAULT_HASH_SIZE + node->item.data.extend_size,
				item->data + DEFAULT_HASH_SIZE + node->item.data.extend_size,
				node->item.path_length
				))continue;
		return node;
	};
	return 0;
}

static struct file_integrity_node *file_integrity_match_next(
		struct file_integrity_node *node,
		struct file_integrity_item *item){//return 1 success,0 otherwise
	for(node = node->hash_next;node;node = node->hash_next){
		if(node->item.path_length == 0){
			if ((item->be_path_length == 0) && (!memcmp(item->data,node->item.data.data,DEFAULT_HASH_SIZE)))return node;
			else continue;
		}
		if(ntohs(item->be_path_length) != node->item.path_length )continue;
		if(memcmp(item->data,node->item.data.data,DEFAULT_HASH_SIZE))continue;
		if(memcmp(node->item.data.data + DEFAULT_HASH_SIZE + node->item.data.extend_size,
				item->data + DEFAULT_HASH_SIZE + node->item.data.extend_size,
				node->item.path_length
				))continue;
		httc_util_pr_dev("Duplicated item found\n");
		return node;
	};
	return 0;
}
struct file_integrity_node * file_integrity_add_to_hash_table(struct file_integrity_item *item){
	unsigned int path_length;
	unsigned int size;
	struct file_integrity_node *node;
	//if(file_integrity_match(item))return 0;
	path_length = ntohs(item->be_path_length);
	size = DEFAULT_HASH_SIZE + item->extend_size + path_length;
	node = httc_malloc(sizeof(struct file_integrity_node) + size);
	if(!node){
		httc_util_pr_error("No memory");
		return 0;
	}
	memcpy(&node->item.data,item,sizeof(struct file_integrity_item) + size);
	node->item.size = sizeof(struct file_integrity_item) + size;
	node->hash_index = hash_value(&item->data[0]);
	node->item.aligned_size = HTTC_ALIGN_SIZE(node->item.size,4);
	node->item.path_length = ntohs(item->be_path_length);
	node->hash_next = file_integrity_data.hash_table[node->hash_index];
	//node->list_next = 0;
	file_integrity_data.hash_table[node->hash_index] = node;
	//printf("aligned_size=%d\n",node->item.aligned_size);
	return node;
}
void file_integrity_delete_from_hash_table(struct file_integrity_node *node){
		struct file_integrity_node *pos,*pre = 0;
		//first = pos = hash_table[node->hash_index];
		for(pos = file_integrity_data.hash_table[node->hash_index];
				pos;pre = pos,pos = pos->hash_next){
			if(pos == node){
				if(!pre){
					file_integrity_data.hash_table[node->hash_index] = pos->hash_next;
				}
				else{
					pre->hash_next = pos->hash_next;
				}
				break;
			}
		}
}
int file_integrity_add_list_to_hash_table(
		struct file_integrity_item **item,
		unsigned int num,
		struct list_head *pheader,
		unsigned int *pvalid){
	int i, r = 0;
	unsigned int valid  = 0;
	struct file_integrity_node *pos,*n;
	unsigned int file_pos = 0;
	//LIST_HEAD(header) ;
	for(i=0; i<num; i++){
		if(!memcmp(item[i]->data,ZERO_HASH,DEFAULT_HASH_SIZE)){
			httc_util_pr_dev("Zero data found\n");
			file_pos +=  HTTC_ALIGN_SIZE(
					sizeof(struct file_integrity_item) + DEFAULT_HASH_SIZE
					+ item[i]->extend_size + ntohs(item[i]->be_path_length),4);
			continue;
		}
		pos = file_integrity_add_to_hash_table(item[i]);
		if(!pos){
			r = -1;
			break;
		}
		pos->item.offset = file_pos;
		file_pos += pos->item.aligned_size;
		list_add_tail(&pos->list,pheader);
		valid ++;
	}
//	if(valid){
//		i++;
//		for(; i<num; i++){
//			if(!memcmp(item[i]->data,ZERO_HASH,DEFAULT_HASH_SIZE))continue;
//			node = file_integrity_add_to_hash_table(item[i]);
//			if(!node){
//				r = -1;
//				break;
//			}
//			tail->list_next = node;
//			tail = node;
//			valid ++;
//		}
//	}
	if(r){
		list_for_each_entry_safe(pos, n, pheader, list){
			file_integrity_delete_from_hash_table(pos);
			list_del(&pos->list);
			httc_free(pos);
		}
		return r;
	}
	else{
		*pvalid = valid;
	}
	return r;
//	if(r){
//		for(node = head; node; ){
//			file_integrity_delete_from_hash_table(node);
//			next = node->list_next;
//			httc_free(node);
//			node=next;
//		}
//		return 0;
//	}
//	*phead = head;
//	*ptail = tail;

	//return r;

}
int file_integrity_check(struct file_integrity_item *item,unsigned int size){
	int expect_size;
	if(size < sizeof(struct file_integrity_item) + DEFAULT_HASH_SIZE){
		return 0;
	}
	expect_size = sizeof(struct file_integrity_item) + DEFAULT_HASH_SIZE
			+ item->extend_size + ntohs(item->be_path_length);
	//ALIGN
	if(expect_size <= size)return expect_size;
	else return 0;
}
static int buffer_to_item_array(char *data,unsigned int size,
		struct file_integrity_item ***pitems,unsigned int *num){
	int max_items = size/(sizeof(struct file_integrity_item) + DEFAULT_HASH_SIZE) + 1;
	struct file_integrity_item **items;
	int item_size;
	int r = 0;
	int item_size_aligned;
	int item_number = 0;
	struct file_integrity_item * item;
	items = httc_malloc(sizeof(struct file_integrity_item *) * max_items);
	if(!items){
		//httc_util_pr_error("no memeory\n");
		return TCF_ERR_NOMEM;
	}
	item = (struct file_integrity_item *)data;
	while(size > 0){

		item_size = file_integrity_check(item,size);
		if(item_size == 0){
			r = TCF_ERR_BAD_DATA;
			break;
		}
		item_size_aligned = HTTC_ALIGN_SIZE(item_size,4);
		items[item_number] = item;
		item_number ++;
		if(item_size_aligned >= size){
			httc_util_pr_dev("finished\n");
			break;
		}
		item =  (struct file_integrity_item *)
				(((char *)item) + item_size_aligned);
		//pos += item_size_aligned;
		size -= item_size_aligned;
	}
	if(r){
		httc_free(items);
		return r;
	}
	if(item_number == 0)httc_free(items);
	else *pitems = items;
	*num = item_number;
	return 0;
}

int file_integrity_hash_policy_data(
		char *buffer,unsigned int length,
		struct file_integrity_item ***parray,
		unsigned int *ptotal,unsigned int *pvalid){
	struct file_integrity_item **pitems = 0;
	struct file_integrity_node *pos,*n;
	LIST_HEAD(header);
	//struct file_integrity_node *head,*tail;
	unsigned int num;
	unsigned int valid;
	int r;
//	if(length == 0){
//		*ptotal = 0;
//		*pvalid = 0;
//		*parray = 0;
//		return 0;
//	}
	r = buffer_to_item_array(buffer,length,&pitems,&num);
	if(r)return r;
	if(!pitems){
		*ptotal = num;
		*pvalid = 0;
		*parray = 0;
		return 0;
	}
	r = file_integrity_add_list_to_hash_table(pitems,num,&header,&valid);
	if(r){
		httc_free(pitems);
		return r;
	}
	valid = 0;
	list_for_each_entry_safe(pos, n, &header, list){
		list_del(&pos->list);
		pitems[valid++] = &pos->item.data;
	}
	*ptotal = num;
	*pvalid = valid;
	*parray = pitems;
	return 0;
//

//	file_integrity_data.total += num;
//	if(!valid){
//		if(phead)*phead = 0;
//		return 0;
//	}
//
//	file_integrity_data.valid += valid;
//	if(phead)*phead = &list_entry(header.next,struct file_integrity_node,list)->item.data;
//	list_for_each_entry_safe(pos, n, &header, list){
//		list_del(&pos->list);
//		pos->offset = file_integrity_data.length;
//		list_add_tail(&pos->list,&file_integrity_data.list);
//		file_integrity_data.length  += pos->item.aligned_size;
//	}
//	if(file_integrity_data.end){
//		file_integrity_data.end->list_next = head;
//		file_integrity_data.end = head;
//	}
//	else{
//		file_integrity_data.head = head;
//		file_integrity_data.end = tail;
//	}
//	if(phead)*phead = &head->item.data;
//	httc_util_pr_dev("total %d,valid %d length=%d\n",
//			file_integrity_data.total,
//			file_integrity_data.valid,
//			file_integrity_data.length);
//	return r;
}
int file_integrity_delete_policy_data(
		struct file_integrity_item_info **dellist,unsigned int del_num){
	int i;
	//struct file_integrity_item_info *info;
	struct file_integrity_node *node;

	for(i=0;i<del_num;i++){
		//info = CONTAINER_OF(dellist[i],struct file_integrity_item_info,data);
		node = httc_util_container_of(dellist[i],struct file_integrity_node,item);
		file_integrity_delete_from_hash_table(node);
		list_del(&node->list);
		file_integrity_data.valid --;
		file_integrity_data.length -= dellist[i]->aligned_size;
		httc_free(node);
	}
	httc_util_pr_dev("total %d,valid %d length=%d\n",
			file_integrity_data.total,
			file_integrity_data.valid,
			file_integrity_data.length);
	return 0;
}
int file_integrity_delete_policy_data_prepare(char *buffer,unsigned int length,
		struct file_integrity_item_info ***dellist,unsigned int *pdelnum){
	//int del_number = 0;
	struct file_integrity_item **pitems;
	struct file_integrity_item_info *info;
	struct file_integrity_node *node;
	unsigned int num;
	int i;
	struct  httc_util_array delarray;
	int r = buffer_to_item_array(buffer,length,&pitems,&num);
	if(r)return r;
	r = httc_util_array_init(&delarray,sizeof(struct file_integrity_item_info *),
			2,2);
	if(r){
		httc_free(pitems);
		return r;
	}
	for(i=0;i<num;i++){
		//httc_util_dump_hex("try to del ",pitems[i]->data,32);
		node = 	file_integrity_match(pitems[i]);

		for(;node;node=file_integrity_match_next(node,pitems[i])){
			info = &node->item;
			/** 被删除目标查重 */
			if (!httc_util_array_check(&delarray,&info))	continue;
			//httc_util_pr_dev("append del item %p\n",info);
			r = httc_util_array_append(&delarray,&info);
			if(r){
				r = TCF_ERR_NOMEM;
				httc_util_pr_dev("No memory \n");
				goto out;
			}
		}
	}
out:
	httc_free(pitems);
	*pdelnum = delarray.size;
	if(r || delarray.size == 0){
		httc_free(delarray.array);
	}
	else{
		*dellist = delarray.array;
	}
//	*pdelnum = del_number;
//	if(del_number == 0)httc_free(pitems);
//	else *dellist = pitems;
	return r;
//	pitems = httc_malloc();
//	r = file_integrity_add_list_to_hash_table(pitems,num,&head,&tail,&valid);
//	if(r)return r;
//	file_integrity_data.total += num;
//	if(!head){
//		if(phead)*phead = 0;
//		return 0;
//	}
//
//	file_integrity_data.valid += valid;
//	if(file_integrity_data.end){
//		file_integrity_data.end->list_next = head;
//		file_integrity_data.end = head;
//	}
//	else{
//		file_integrity_data.head = head;
//		file_integrity_data.end = tail;
//	}
//	if(phead)*phead = &head->item.data;
//	httc_util_pr_dev("total %d,valid %d\n",file_integrity_data.total,file_integrity_data.valid);
//	return 0;
}
//static struct file_integrity_node * file_integrity_seek(int index){
//	int i;
//	struct file_integrity_node *start;
//	if(index >= file_integrity_data.valid)return 0;
//	start = file_integrity_data.head;
//	//if(!start)return 0;
//	for(i=0;i<index && start;i++){
//		start = start->list_next;
//	}
//	return start;
//}
int file_integrity_iterator(int from,int number,file_integrity_func func,void *context){
	int r;
	struct file_integrity_node *pos,*n;
	int index = 0;
	int end = from + number;
	list_for_each_entry_safe(pos, n, &file_integrity_data.list, list){
		 if(index++ < from)continue;
		 r = func(&pos->item,context);
		 if(r)return r;
		 if(index == end)break;
	}
//	for(node = file_integrity_seek(from);node;node = next){
//		 next =  node->list_next;
//		 r = func(&node->item,context);
//		 if(r)return r;
//	}
	return 0;
}

#define FILE_INTEGRITY_TOTAL_LIMIT	160000

unsigned int file_integrity_valid(void){
	return file_integrity_data.valid;
}
unsigned int file_integrity_total(void){
	return file_integrity_data.total;
}
unsigned int file_integrity_modify_limit(void){
	return FILE_INTEGRITY_TOTAL_LIMIT - file_integrity_data.total;
}
//static int integrity_httc_free(struct file_integrity_item_info *item,void *context){
//	struct file_integrity_node *node =
//			CONTAINER_OF(item,struct file_integrity_node,item);
//	httc_free(node);
//	return 0;
//}


void file_integrity_reset(void){
	struct file_integrity_node *pos,*n;
	//file_integrity_iterator(0,file_integrity_data.valid,integrity_httc_free,0);
	list_for_each_entry_safe(pos, n, &file_integrity_data.list, list){
		list_del(&pos->list);
		httc_free(pos);
	}
	memset(&file_integrity_data,0,sizeof(file_integrity_data));
	INIT_LIST_HEAD(&file_integrity_data.list);
	httc_util_pr_dev("total %d,valid %d length=%d\n",
			file_integrity_data.total,
			file_integrity_data.valid,
			file_integrity_data.length);
	//memset(&file_integrity_data,0,sizeof(file_integrity_data));
	//INIT_LIST_HEAD(&file_integrity_data.list);
	//CONTAINER_OF(struct file_integrity_node);
}

void file_integrity_delete_from_hashtable_array(
		struct file_integrity_item **item,unsigned int num){
	int i;
	struct file_integrity_item_info *info;
	struct file_integrity_node *node;
	for(i=0;i<num;i++){
		info = httc_util_container_of(item[i],struct file_integrity_item_info,data);
		node = httc_util_container_of(info,struct file_integrity_node,item);
		file_integrity_delete_from_hash_table(node);
		httc_free(node);
	}
}
void file_integrity_append_hashed_array(
		struct file_integrity_item **item,unsigned int total,
		unsigned int valid,unsigned data_length){
	int i;
	struct file_integrity_item_info *info;
	struct file_integrity_node *node;
	file_integrity_data.total += total;
	//int length;
	for(i=0;i<valid;i++){
		info = httc_util_container_of(item[i],struct file_integrity_item_info,data);
		node = httc_util_container_of(info,struct file_integrity_node,item);
		info->offset += file_integrity_data.length;
		list_add_tail(&node->list,&file_integrity_data.list);
		file_integrity_data.valid++;
		//httc_util_pr_dev("offset %d,size %d,aligned size %d,path_leng%d\n",
		//		info->offset,info->size,info->aligned_size,info->path_length);
	}
	if(total){
		file_integrity_data.length += HTTC_ALIGN_SIZE(data_length,4);
	}
	httc_util_pr_dev("total %d,valid %d length=%d\n",
			file_integrity_data.total,
			file_integrity_data.valid,
			file_integrity_data.length);
}


//void file_integrity_clear_list(struct file_integrity_item *item){
//	if(!item)return;
//	struct file_integrity_item_info *info =
//				CONTAINER_OF(item,struct file_integrity_item_info,data);
//	struct file_integrity_node *node =
//				CONTAINER_OF(info,struct file_integrity_node,item);
//	struct file_integrity_node *pos,*n;
//	for (pos = node,n = list_entry(pos->list.next, struct file_integrity_node, list);
//		&pos->list != &file_integrity_data.list;
//		pos = n, n = list_entry(n->list.next, struct file_integrity_node, list)){
//		file_integrity_delete_from_hash_table(pos);
//		file_integrity_data.length -= pos->item.aligned_size;
//		list_del(&pos->list);
//		httc_free(pos);
//	}
//
//}
//struct whitelist_node **pointer;
