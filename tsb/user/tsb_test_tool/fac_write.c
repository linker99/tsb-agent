#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#include "../tsbapi/tsb_admin.h"
#include "../tcsapi/tcs_file_protect_def.h"
#include "sm3.h"

#define HASH_LEN 32

int main(int argc, char **argv)
{
	int ret = 0;
	int len=0, num=0;
	unsigned char hash[HASH_LEN] = {0};
	char buf[1024] = {0};
	struct file_protect_item* p_mac=NULL;
	struct file_protect_privileged_process* p_dac=NULL;

	ret = sm3_file("/usr/bin/rm", hash);
	//ret = sm3_file("/mnt/hgfs/work/httc/src/user/tsb_test_tool/fac_process_measure", hash);
	if(ret)
	{
		printf("sm3_file error!\n");
		return 0;
	}


	p_mac = (struct file_protect_item*)buf;
	p_mac->measure_flags = 3;
	p_mac->type = FILE_WRITE_PROTECT;
	//p_mac->type = FILE_READ_PROTECT;
	p_mac->be_privileged_process_num = htons(1);
	strcpy(p_mac->path, "^/root/hyq/test(/?|/.*)$");
	//strcpy(p_mac->path, "^/root/hyq/test/a.sh$");

	p_dac = (struct file_protect_privileged_process*)(buf+sizeof(struct file_protect_item));
	p_dac->be_privi_type = htonl(PRIVI_ALL);
	memcpy(p_dac->hash, hash, HASH_LEN);
	strcpy(p_dac->path, "^/usr/bin/rm$");
	//strcpy(p_dac->path, "^/mnt/hgfs/work/httc/src/user/tsb_test_tool/fac_process_measure$");


	FILE* fp_w = fopen("file_protect.data", "wb");
	len = sizeof(struct file_protect_item)+sizeof(struct file_protect_privileged_process);
	num = 1;
	fwrite(&len, 1, sizeof(len), fp_w);
	fwrite(&num, 1, sizeof(num), fp_w);
	fwrite(buf, 1, sizeof(struct file_protect_item)+sizeof(struct file_protect_privileged_process), fp_w);
	fclose(fp_w);
	
	return 0;
}
