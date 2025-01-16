#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "../tsbapi/tsb_admin.h"
#include "../tcsapi/tcs_dmeasure.h"

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		printf("param error!\n");
		return 0;
	}

	int data_length = sizeof(struct dmeasure_policy_item)*6;
	//int update_len = data_length + sizeof(struct dmeasure_policy_update);
	//struct dmeasure_policy_update *p_update = malloc(data_length);
	//p_update->be_item_number = htonl(3);
	//p_update->be_data_length = htonl(data_length);

	//char *p = (char*)p_update;
	//p = p+sizeof(struct dmeasure_policy_update);

	char *p_update = malloc(data_length);
	char *p = (char*)p_update;

	struct dmeasure_policy_item *p_item = (struct dmeasure_policy_item *)p;
	p_item->be_type = htonl(1);
	p_item->be_interval_milli = htonl(10000);
	strcpy(p_item->object, "syscall_table");

	p = p+sizeof(struct dmeasure_policy_item);
	p_item = (struct dmeasure_policy_item *)p;
	p_item->be_type = htonl(1);
	p_item->be_interval_milli = htonl(10000);
	strcpy(p_item->object, "kernel_section");

	p = p+sizeof(struct dmeasure_policy_item);
	p_item = (struct dmeasure_policy_item *)p;
	p_item->be_type = htonl(1);
	p_item->be_interval_milli = htonl(10000);
	strcpy(p_item->object, "idt_table");

	p = p+sizeof(struct dmeasure_policy_item);
	p_item = (struct dmeasure_policy_item *)p;
	p_item->be_type = htonl(1);
	p_item->be_interval_milli = htonl(10000);
	strcpy(p_item->object, "module_list");

	p = p+sizeof(struct dmeasure_policy_item);
	p_item = (struct dmeasure_policy_item *)p;
	p_item->be_type = htonl(1);
	p_item->be_interval_milli = htonl(10000);
	strcpy(p_item->object, "filesystem");

	p = p+sizeof(struct dmeasure_policy_item);
	p_item = (struct dmeasure_policy_item *)p;
	p_item->be_type = htonl(1);
	p_item->be_interval_milli = htonl(10000);
	strcpy(p_item->object, "network");


	if (strcmp(argv[1], "1") == 0)
		tsb_set_dmeasure_policy((const char *)p_update, data_length);
	else if (strcmp(argv[1], "3") == 0)
		tsb_reload_dmeasure_policy();
	else
		printf("param argv error!\n");

	free(p_update);
	
	return 0;
}