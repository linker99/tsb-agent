#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "tcs_bmeasure.h"
#include "crypto/sm/sm3.h"

//#define __HASH_DEBUG__

static void usage ()
{
	printf ("\n"
			" Usage: ./get_bmeasure_references\n"
			"\n");
}

int main (int argc, char **argv)
{
	int i = 0;
	int ret = 0;
	int num = 0;
	int ops = 0;
	int size = 0;
	unsigned char *references = NULL;
	struct boot_ref_item *bm_item = NULL;
	ret = tcs_get_boot_measure_references ((struct boot_ref_item **)&references, &num, &size);
	if (ret){
		printf ("[tpcm_get_boot_measure_references_record] ret: %d(0x%x)\n", ret, ret);
		return -1;
	}

	for (i = 0; i < num; i ++){
		bm_item = (struct boot_ref_item*)(references + ops);
		printf ("\n");
		printf ("bm_item index: %d\n", i);
		printf ("[%d].hash_length: %d\n", i, ntohs(bm_item->be_hash_length));
		printf ("[%d].flags: 0x%x\n", i, ntohs(bm_item->be_flags));
		printf ("[%d].name_length: %d\n", i, ntohs (bm_item->be_name_length));
		printf ("[%d].hash_number: %d\n", i, ntohs (bm_item->be_hash_number));
		printf ("[%d].stage: %d\n", i, ntohs (bm_item->be_stage));
		printf ("[%d].extend_size: %d\n", i, ntohs (bm_item->be_extend_size));
		printf ("[%d].", i); httc_util_dump_hex ("item.hash", bm_item->data, DEFAULT_HASH_SIZE);
		printf ("[%d].name: %s\n", i, bm_item->data + DEFAULT_HASH_SIZE);
		if (bm_item->be_extend_size){
			printf ("[%d].", i); 
			httc_util_dump_hex ("item.extend_data",
				bm_item->data + ntohs (bm_item->be_hash_length) * ntohs (bm_item->be_hash_number),
				DEFAULT_HASH_SIZE);
		}
		ops += sizeof (struct boot_ref_item)
				+ ntohs (bm_item->be_hash_length) * ntohs (bm_item->be_hash_number)
				+ ntohs (bm_item->be_extend_size)
				+ ntohs (bm_item->be_name_length);
		ops = HTTC_ALIGN_SIZE (ops, 4);
	}
	printf ("\n");

#ifdef __HASH_DEBUG__
	uint8_t wlHash[DEFAULT_HASH_SIZE] = {0};
	sm3 (references, ops, wlHash);
	httc_util_dump_hex ("references", references, ops);
	httc_util_dump_hex ("wlHash", wlHash, DEFAULT_HASH_SIZE);
#endif

	if (references)	httc_free (references);

	return 0;
}


