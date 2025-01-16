#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "mem.h"
#include "sys.h"
#include "debug.h"
#include "convert.h"
#include "tcs_bmeasure.h"

static void usage ()
{
	printf ("\n"
			" Usage: ./get_bmeasure_records\n"
			"\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	int i = 0;
	int num = 0;
	int ops = 0;
	int size = 0;
	unsigned char *records = NULL;
	struct boot_measure_record *bm_records = NULL;
	ret = tcs_get_boot_measure_records ((struct  boot_measure_record **)&records, &num, &size);
	if (ret){
		printf ("[tcs_get_boot_measure_records] ret: %d(0x%x)\n", ret, ret);
		return -1;
	}

	for (i = 0; i < num; i ++){
		bm_records = (struct boot_measure_record *)(records + ops);
		printf ("\n");
		printf ("bm_records index: %d\n", i);
		printf ("[%d].", i); httc_util_time_print ("measure_time: %s\n", ntohll (bm_records->be_measure_time));
		printf ("[%d].result: %d\n", i, ntohl (bm_records->be_result));
		printf ("[%d].hash_length: %d\n", i, ntohs (bm_records->be_hash_length));
		printf ("[%d].name_length: %d\n", i, ntohs (bm_records->be_name_length));
		printf ("[%d].stage: %d\n", i, ntohs (bm_records->be_stage));
		printf ("[%d].", i); httc_util_dump_hex ("item.hash", bm_records->data, ntohs (bm_records->be_hash_length));
		printf ("[%d].name: %s\n", i, bm_records->data + ntohs (bm_records->be_hash_length));
		ops += sizeof (struct boot_measure_record) + ntohs (bm_records->be_hash_length) + ntohs (bm_records->be_name_length);
		ops = HTTC_ALIGN_SIZE (ops, 4);
	}
	printf ("\n");
	if (records)	httc_free (records);
	
	return 0;
}

