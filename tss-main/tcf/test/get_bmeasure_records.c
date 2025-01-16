#include <stdio.h>
#include <string.h>

#include <httcutils/debug.h>
#include "tcsapi/tcs_error.h"
#include "tcfapi/tcf_bmeasure.h"
#include "httcutils/sys.h"

int main ()
{
	int i;
	int ret = 0;
	int num = 0;
	struct boot_measure_record_user *boot_records = NULL;

	if (0 != (ret = tcf_get_boot_measure_records (&boot_records, &num))){
		httc_util_pr_error ("tcf_get_boot_measure_records error: %d(0x%x)\n", ret, ret);
		return -1;
	}

	for (i = 0; i < num; i++){
		printf ("\n");
		printf ("bm_records index: %d\n", i);
		printf ("[%d].hash_length: %d\n", i, boot_records[i].hash_length);
		printf ("[%d].stage: %u\n", i, boot_records[i].stage);
		printf ("[%d].result: %u\n", i, boot_records[i].result);
		printf ("[%d].", i); httc_util_time_print ("measure_time: %s\n",boot_records[i].measure_time);
		printf ("[%d].", i); httc_util_dump_hex ("hash", boot_records[i].hash, boot_records[i].hash_length);
		printf ("[%d].name: %s\n", i, boot_records[i].name);
	}
	printf ("\n");
	
	printf ("get_bmeasure_record_test success\n");
	
	if (boot_records) tcf_free_boot_measure_records (boot_records, num);
	return ret;
}

