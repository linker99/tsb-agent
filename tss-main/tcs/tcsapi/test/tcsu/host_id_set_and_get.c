#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "tcs_attest.h"
#include "sys.h"

#define HTTC_HOST_ID_FILE		HTTC_TSS_CONFIG_PATH"host.id"

int main(void)
{
	int ret = 0;
	uint8_t get_id[128] = {0};
	uint8_t get_2id[128] = {0};
	uint32_t id_len = sizeof(get_id);
	uint32_t id_2len = sizeof(get_id);
	uint8_t *set_id = "67c6697351ff4aec29cdbaabf2fbe346";
	uint8_t *set_2id = "10b6697351ff4aec29cdbaabf2fbe346";
	int set_len = 32;
	int set_2len = 32;

	/*1 host id no exist set*/
	printf("\n  1 host id no exist set \n");
	httc_util_rm (HTTC_HOST_ID_FILE);
	ret = tcs_set_host_id(set_id, set_len);
	if(ret) {
		printf("[tcs_set_host_id] ret: 0x%08x\n", ret);
		return -1;
	}
	httc_util_dump_hex ("set host id :",  set_id, set_len);	
	ret = tcs_get_host_id(get_id, &id_len);
	if(ret) {
		printf("[tcs_get_host_id] ret: 0x%08x\n", ret);
		return -1;
	}
	httc_util_dump_hex ("get host id :",  get_id, id_len);
	if(memcmp(set_id, get_id, set_len) == 0){
		printf("1 set host id == get host id\n");
	}else{
		printf("1 set host id != get host id\n");
		//return -1;
	}
	
	/*2 host id exist set*/
	printf("\n  2 host id exist set \n");
	ret = tcs_set_host_id(set_2id, set_2len);
	if(ret) {
		printf("[tcs_set_host_id] ret: 0x%08x\n", ret);
		return -1;
	}
	httc_util_dump_hex ("set host id :",  set_2id, set_2len);	
	ret = tcs_get_host_id(get_2id, &id_2len);
	if(ret) {
		printf("[tcs_get_host_id] ret: 0x%08x\n", ret);
		return -1;
	}
	httc_util_dump_hex ("get host id :",  get_id, id_len);
	if(memcmp(get_2id, get_id, id_2len) == 0){
		printf("2 set host id == get host id\n");
	}else{
		printf("2 set host id != get host id\n");
		//return -1;
	}	

	/*3 host id no exist get*/
	printf("\n  3 host id no exist get \n");
	httc_util_rm (HTTC_HOST_ID_FILE);
	ret = tcs_get_host_id(get_id, &id_len);
	if(ret) {
		printf("[tcs_get_host_id] ret: 0x%08x\n", ret);
		return -1;
	}
	httc_util_dump_hex ("get host id",  get_id, id_len);
	ret = tcs_get_host_id(get_2id, &id_2len);
	if(ret) {
		printf("[tcs_get_host_id] ret: 0x%08x\n", ret);
		return -1;
	}
	httc_util_dump_hex ("get host id",  get_2id, id_2len);
	if(memcmp(get_2id, get_id, id_2len) == 0){
		printf("3 set host id == get host id\n");
	}else{
		printf("3 set host id != get host id\n");
		//return -1;
	}
	
	return 0;
}


