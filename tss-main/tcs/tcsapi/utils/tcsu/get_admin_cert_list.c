#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "tcs_auth.h"
#include "tcs_auth_def.h"

void show_cert(struct admin_cert_item *cert,int num){
	
	int i = 0;
	for(;i < num; i++){
//		httc_util_dump_hex ("Cert", cert + i , sizeof(struct admin_cert_item));
		printf("================Cert:%d================\n",i);
		printf ("cert->be_cert_type: 0x%08X\n", ntohl ((cert + i)->be_cert_type));
		printf ("cert->be_cert_len: 0x%08X\n", ntohl ((cert + i)->be_cert_len));
		printf ("cert->name: %s\n", (cert + i)->name);
		httc_util_dump_hex ("CERT", (cert + i)->data , ntohl ((cert + i)->be_cert_len));
	}
	if(cert) httc_free(cert);
}


int main ()
{
	int ret  = 0;
	int num = 0;
	struct admin_cert_item *list = NULL;
	
	ret = tcs_get_admin_list(&list, &num);
	if(ret){
		printf("[Error] tcs_get_admin_list ret:0x%08X\n",ret);
		return -1;
	}
	show_cert(list,num);
	return ret;

}

