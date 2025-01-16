#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "httcutils/debug.h"
#include "tcfapi/tcf_file_integrity.h"

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

int main ()
{
	int i,r;
	int num = 0;
	struct file_integrity_item_user *items = 0;

	if ((r = tcf_get_critical_file_integrity (&items, &num))){
		printf("tcf_get_critical_file_integrity result %d(0x%x)\n", r, r);
		return -1;
	}

	printf ("\n");
	printf ("Critical File Integrity:\n");
	for (i = 0; i < num; i++){
		printf ("  items[%d].hash_length: %d\n", i, items[i].hash_length);
		printf ("  items[%d].path_length: %d\n", i, items[i].path_length);
		printf ("  items[%d].is_control: %d\n", i, items[i].is_control);
		printf ("  items[%d].is_enable: %d\n", i, items[i].is_enable);
		printf ("  items[%d].is_full_path: %d\n", i, items[i].is_full_path);
		printf ("  items[%d].extend_size: %d\n", i, items[i].extend_size);
		printf ("  items[%d].", i); httc_util_dump_hex ("hash", items[i].hash, items[i].hash_length);
		printf ("  items[%d].", i); httc_util_dump_hex ("path", items[i].path, items[i].path_length);
		printf ("  items[%d].", i); httc_util_dump_hex ("extend_buffer", items[i].hash, items[i].extend_size);
	}
	printf ("\n");
	tcf_free_critical_file_integrity (items, num);
	return 0;
}

