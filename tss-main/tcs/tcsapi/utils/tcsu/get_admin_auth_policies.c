#include <stdio.h>
#include <stdlib.h>

#include "mem.h"
#include "convert.h"
#include "tcs_auth.h"
#include "tcs_auth_def.h"

void show_admin_auth_policy(struct admin_auth_policy *policies, int num){	
	int i = 0;
	for(;i < num; i++){
		printf("================admin_auth_policy:%d================\n",i);
		printf ("policies->object_id: 0x%08X\n", ntohl ((policies + i)->be_object_id));
		printf ("policies->admin_auth_type: 0x%08X\n", ntohl ((policies + i)->be_admin_auth_type));
		printf ("policies->policy_flags: 0x%08X\n", ntohl ((policies + i)->be_policy_flags));
		printf ("policies->user_or_group: 0x%08X\n", ntohl ((policies + i)->be_user_or_group));
		printf ("policies->process_or_role: %s\n", (policies + i)->process_or_role);		
	}
	if(policies) httc_free(policies);
}

int main ()
{	
	int ret = 0;
	int num = 0;
	struct admin_auth_policy *list = NULL;
	ret = tcs_get_admin_auth_policies(&list,&num);
		if(ret){
			printf("[Error] tcs_get_admin_auth_policies ret:0x%08X\n",ret);
			return -1;
		}
	show_admin_auth_policy(list,num);
	return 0;
}

