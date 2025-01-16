#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "../tsbapi/tsb_admin.h"
#include "../tcsapi/tcs_file_integrity.h"

#define LEN_HASH  32
#define BYTE4_ALIGNMENT(len) if((len%4) != 0) len += 4-len%4

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		printf("param error!\n");
		return 0;
	}

	char path1[512]={0}, path2[512]={0}, path3[512]={0}, path4[512]={0}, path5[512]={0};
	char hash[256]={0};
	int item_len, update_len, data_len;
	uint16_t path1_len, path2_len, path3_len, path4_len, path5_len;

	unsigned int     k = 0;
	unsigned char digest[LEN_HASH];
	int i;


	strcpy(path1, "/mnt/hgfs/work/TSB_main/base_platfrom/base_kernel/test_tool/whitelist_test/shell/test1.sh");
	path1_len = strlen(path1)+1;
	strcpy(path2, "/mnt/hgfs/work/TSB_main/base_platfrom/base_kernel/test_tool/whitelist_test/shell/test2.sh");
	path2_len = strlen(path2)+1;
	strcpy(path3, "/mnt/hgfs/work/TSB_main/base_platfrom/base_kernel/test_tool/whitelist_test/shell/test3.sh");
	path3_len = strlen(path3)+1;
	strcpy(path4, "/mnt/hgfs/work/TSB_main/base_platfrom/base_kernel/test_tool/whitelist_test/shell/test4.sh");
	path4_len = strlen(path4)+1;
	strcpy(path5, "/mnt/hgfs/work/TSB_main/base_platfrom/base_kernel/test_tool/whitelist_test/shell/test5.sh");
	path5_len = strlen(path5)+1;

	data_len = LEN_HASH + path1_len;
	BYTE4_ALIGNMENT(data_len);
	item_len = sizeof(struct file_integrity_item) + data_len;
	item_len = item_len*5;
	//update_len = sizeof(struct file_integrity_update) + item_len;

	//struct file_integrity_update *p_update = malloc(item_len);
	//p_update->be_item_number = htonl(5);
	//p_update->be_data_length = htonl(item_len);
	
	char *p_update = malloc(item_len);
	char *p = (char*)p_update;
	//p = p+sizeof(struct file_integrity_update);



	struct file_integrity_item *p_item = (struct file_integrity_item *)p;
	p_item->extend_size = 0;
	p_item->be_path_length = htons(path1_len);

	p = p+sizeof(struct file_integrity_item);
	strcpy(hash, "7EE801CAB0A06DC887110DAAB5C193B0E29090D1CA2FD7081B976D22475782E8");
	for (i = 0; i < LEN_HASH; i++)
	{
		sscanf(&hash[i * 2], "%2x", &k);
		digest[i] = (unsigned char)k;
	}
	memcpy(p, digest, LEN_HASH);
	memcpy(p+LEN_HASH, path1, path1_len);
	BYTE4_ALIGNMENT(path1_len);
	p = p+LEN_HASH+path1_len;



	p_item = (struct file_integrity_item *)p;
	p_item->extend_size = 0;
	p_item->be_path_length = htons(path2_len);

	p = p+sizeof(struct file_integrity_item);
	strcpy(hash, "0FDBFB5CA302CC913D8E83966AD824C8D58BE9493CA1352D022C0DDD8DB449EF");
	for (i = 0; i < LEN_HASH; i++)
	{
		sscanf(&hash[i * 2], "%2x", &k);
		digest[i] = (unsigned char)k;
	}
	memcpy(p, digest, LEN_HASH);
	memcpy(p+LEN_HASH, path2, path2_len);
	BYTE4_ALIGNMENT(path2_len);
	p = p+LEN_HASH+path2_len;



	p_item = (struct file_integrity_item *)p;
	p_item->extend_size = 0;
	p_item->be_path_length = htons(path3_len);

	p = p+sizeof(struct file_integrity_item);
	strcpy(hash, "ABC56909130DE17711CAFF07919BB79EC8D2F3A0CA1E303A43B4837C9210B316");
	for (i = 0; i < LEN_HASH; i++)
	{
		sscanf(&hash[i * 2], "%2x", &k);
		digest[i] = (unsigned char)k;
	}
	memcpy(p, digest, LEN_HASH);
	memcpy(p+LEN_HASH, path3, path3_len);
	BYTE4_ALIGNMENT(path3_len);
	p = p+LEN_HASH+path3_len;



	p_item = (struct file_integrity_item *)p;
	p_item->extend_size = 0;
	p_item->be_path_length = htons(path4_len);

	p = p+sizeof(struct file_integrity_item);
	strcpy(hash, "6DF451CE358C7BBF7A860E5BC5873DA14B91A1C5E5A0B58A6EA47CDDDBB468EC");
	for (i = 0; i < LEN_HASH; i++)
	{
		sscanf(&hash[i * 2], "%2x", &k);
		digest[i] = (unsigned char)k;
	}
	memcpy(p, digest, LEN_HASH);
	memcpy(p+LEN_HASH, path4, path4_len);
	BYTE4_ALIGNMENT(path4_len);
	p = p+LEN_HASH+path4_len;



	p_item = (struct file_integrity_item *)p;
	p_item->extend_size = 0;
	p_item->be_path_length = htons(path5_len);

	p = p+sizeof(struct file_integrity_item);
	strcpy(hash, "C9C97ADC4DDEE6DEF6E7505DD697FD73FDA6DAAE7795B95E81703498D44E15D1");
	for (i = 0; i < LEN_HASH; i++)
	{
		sscanf(&hash[i * 2], "%2x", &k);
		digest[i] = (unsigned char)k;
	}
	memcpy(p, digest, LEN_HASH);
	memcpy(p+LEN_HASH, path5, path5_len);
	BYTE4_ALIGNMENT(path5_len);
	p = p+LEN_HASH+path5_len;

	if (strcmp(argv[1], "1") == 0)
		tsb_add_file_integrity((const char *)p_update, item_len);
	else if (strcmp(argv[1], "2") == 0)
		tsb_remove_file_integrity((const char *)p_update, item_len);
	else if (strcmp(argv[1], "3") == 0)
		tsb_reload_file_integrity();
	else
		printf("param argv error!\n");

	free(p_update);
	
	return 0;
}