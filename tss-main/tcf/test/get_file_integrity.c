#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <httcutils/debug.h>
#include <httcutils/mem.h>
#include <tcfapi/tcf_file_integrity.h>
#include <tcfapi/tcf_auth.h>


static void print_item(const char *name,struct file_integrity_item_user *item){
	printf("%s control=%d,enable=%d,full_path=%d\n",name,
		item->is_control,item->is_enable,item->is_full_path);
	if(item->hash)httc_util_dump_hex("ITEM hash",item->hash,item->hash_length);
	if(item->extend_buffer)httc_util_dump_hex("ITEM extend_buffer",item->extend_buffer,item->extend_size);
	if(item->path){
		if(!item->is_full_path)httc_util_dump_hex("ITEM path",item->path,item->path_length);
		else printf("ITEM path %s\n",item->path);
	}
}

int test_get(void){
	struct file_integrity_item_user *getlist = 0;
	unsigned int get_size = 1000000;
	int i;
	int r = tcf_get_file_integrity(&getlist,0,&get_size);
	if(r)return r;
	for(i=0;i<get_size;i++){
		char name[100];
		sprintf(name,"GET %i :",i);
		print_item(name,getlist + i);
	}
	tcf_free_file_integrity(getlist,get_size);
	return r;
}

int main(int argc,const char **args){
	int r=-1;
	r = test_get();
	return r;
}



