#include <stdio.h>
#include <string.h>

#include <httcutils/debug.h>
#include "tcsapi/tcs_error.h"
#include "tcfapi/tcf_bmeasure.h"

int main ()
{
	int i;
	int ret = 0;
	int num = 0;
	struct boot_ref_item_user *boot_refs = NULL;

	if (0 != (ret = tcf_get_boot_measure_references (&boot_refs, &num))){
		httc_util_pr_error ("tcf_get_boot_measure_references error: %d(0x%x)\n", ret, ret);
		return -1;
	}

	for (i = 0; i < num; i++){
		printf ("\n");
		printf ("bm_references index: %d\n", i);
		printf ("[%d].hash_length: %d\n", i, boot_refs[i].hash_length);
		printf ("[%d].hash_number: %d\n", i, boot_refs[i].hash_number);
		printf ("[%d].stage: %u\n", i, boot_refs[i].stage);
		printf ("[%d].is_control: %u\n", i, boot_refs[i].is_control);
		printf ("[%d].is_enable: %u\n", i, boot_refs[i].is_enable);
		printf ("[%d].", i); httc_util_dump_hex ("hash", boot_refs[i].hash, boot_refs[i].hash_length);
		printf ("[%d].name: %s\n", i, boot_refs[i].name);
		printf ("[%d].extend_size: %u\n", i, boot_refs[i].extend_size);
		printf ("[%d].", i); httc_util_dump_hex ("extend_buffer", boot_refs[i].extend_buffer, boot_refs[i].extend_size);
	}
	printf ("\n");
	printf ("get_bmeasure_reference_test success\n");
	if (boot_refs) tcf_free_boot_measure_references (boot_refs, num);
	return ret;
}

