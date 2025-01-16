#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "tcs_policy.h"
#include "crypto/sm/sm3.h"
#include "tcs_file_integrity.h"

#define __HASH_DEBUG__

static void usage ()
{
	printf ("\n"
			" Usage: ./read_file_integrity\n"
			"\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	uint32_t num = 0;
	int length = 0;
	int index = 0;
	int ref_ops = 0;
	int item_ops = 0;
	uint16_t path_length = 0;
	uint16_t extend_size = 0;
	uint16_t lib_number = 0;
	uint8_t *reference = NULL;
	struct file_integrity_item *item = NULL;

	if (0 != (ret = tcs_get_file_integrity ((struct file_integrity_item **)&reference, &num, &length))){
		printf ("tpcm_read_file_integrity error: %d(0x%x)\n", ret, ret);
		return ret;
	}
#ifdef __HASH_DEBUG__
	uint8_t wlHash[DEFAULT_HASH_SIZE] = {0};
	sm3 ((const uint8_t *)reference, length, wlHash);
	httc_util_dump_hex ("wlHash", wlHash, DEFAULT_HASH_SIZE);
#endif
	
//	httc_util_dump_hex ("reference", reference, length);
	while (ref_ops < length){
		item = (struct file_integrity_item *)((uint8_t *)reference + ref_ops);
		path_length = ntohs (item->be_path_length);
		
		printf ("\n");
		printf ("file_integrity index: %d(0x%x)\n", index, index);
		printf ("[%d].flags: 0x%x\n", index, item->flags);
		printf ("[%d].extend_size: 0x%x\n", index, item->extend_size);
		printf ("[%d].path_length: 0x%x\n", index, path_length);
		printf ("[%d].", index); httc_util_dump_hex ("hash", item->data, DEFAULT_HASH_SIZE);
		printf ("[%d].", index); httc_util_dump_hex ("extend_data", item->data + DEFAULT_HASH_SIZE, item->extend_size);
		if (path_length){
			if (item->flags & (1 << FILE_INTEGRITY_FLAG_FULL_PATH)){
				printf ("[%d].path: %s\n", index, item->data + DEFAULT_HASH_SIZE + item->extend_size);
			}else{
				printf ("[%d].", index); httc_util_dump_hex ("path", item->data + DEFAULT_HASH_SIZE + item->extend_size, path_length);
			}
		}
		item_ops = sizeof (struct file_integrity_item) +  DEFAULT_HASH_SIZE + item->extend_size + path_length;
		ref_ops += HTTC_ALIGN_SIZE (item_ops, 4);
		index ++;
	}

	printf ("\n");

	if (reference) httc_free (reference);
	return ret;
}

