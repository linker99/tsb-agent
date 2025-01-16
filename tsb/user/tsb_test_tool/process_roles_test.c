#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "../tsbapi/tsb_admin.h"
#include "../tcsapi/tcs_process_def.h"

#define BYTE4_ALIGNMENT(len) if((len%4) != 0) len += 4-len%4

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		printf("param error!\n");
		return 0;
	}

	char buf[1024] = {0};
	char *p;

	struct process_role *p_role = (struct process_role *)buf;
	p_role->be_name_length = htonl(6);
	p = p_role->members;
	strcpy(p, "hello");
	p += strlen("hello") + 1;



	int role_member_len = sizeof(struct role_member)+4;
	struct role_member *member = malloc(role_member_len);
	member->length = 4;

	strcpy(member->name, "aaa");
	memcpy(p, member, role_member_len);
	p += role_member_len;
	
	strcpy(member->name, "bbb");
	memcpy(p, member, role_member_len);
	p += role_member_len;

	strcpy(member->name, "ccc");
	memcpy(p, member, role_member_len);
	p += role_member_len;
	

	p_role->be_members_number = htonl(3);
	p_role->be_members_length = htonl(role_member_len*3);

	int policy_len = sizeof(struct process_role) + 6 + role_member_len*3;
	printf("111 policy_len:%d\n", policy_len);
	BYTE4_ALIGNMENT(policy_len);
	printf("222 policy_len:%d\n", policy_len);

	if (strcmp(argv[1], "1") == 0)
		tsb_set_process_roles((unsigned char *)p_role, policy_len);
	else if (strcmp(argv[1], "3") == 0)
		tsb_reload_process_roles();
	else
		printf("param argv error!\n");
	
	return 0;
}