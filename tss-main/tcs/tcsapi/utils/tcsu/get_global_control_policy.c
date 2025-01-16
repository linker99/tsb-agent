#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#include "convert.h"
#include "tcs_policy.h"
#include "tcs_policy_def.h"


void show_policy(struct global_control_policy *policy){

	printf ("policy->size: 0x%08X\n", ntohl (policy->be_size));
	printf ("policy->boot_measure_on: %s\n", ntohl (policy->be_boot_measure_on) == 0 ? "OFF" : "ON");
	printf ("policy->program_measure_on: %s\n", ntohl (policy->be_program_measure_on) == 0 ? "OFF" : "ON");
	printf ("policy->dynamic_measure_on: %s\n", ntohl (policy->be_dynamic_measure_on) == 0 ? "OFF" : "ON");
	printf ("policy->boot_control: %s\n", ntohl (policy->be_boot_control) == 0 ? "NOT" : "CONTROL");
	printf ("policy->program_control: %s\n", ntohl (policy->be_program_control) == 0 ? "NOT" : "CHECK");
	printf ("policy->be_tsb_flag1: %s\n", ntohl (policy->be_tsb_flag1) == 0 ? "NOT" : "CHECK");
	printf ("policy->be_tsb_flag2: %s\n", ntohl (policy->be_tsb_flag2) == 0 ? "NOT" : "CHECK");
	printf ("policy->be_tsb_flag3: %s\n", ntohl (policy->be_tsb_flag3) == 0 ? "NOT" : "CONTROL");
	printf ("policy->program_measure_mode: %d\n", ntohl (policy->be_program_measure_mode));
	printf ("policy->measure_use_cache: %s\n", ntohl (policy->be_measure_use_cache) == 0 ? "NOT" : "USE_CACHE");
	printf ("policy->dmeasure_max_busy_delay: %d\n", ntohl (policy->be_dmeasure_max_busy_delay));
	printf ("policy->process_dmeasure_ref_mode: %s\n", 
		ntohl (policy->be_process_dmeasure_ref_mode) == 0 ? "Collection at startup" : "File library integrity");
	printf ("policy->process_dmeasure_match_mode: %s\n", 
		ntohl (policy->be_process_dmeasure_match_mode) == 0 ? "Only hash" : "Band path");
	printf ("policy->program_measure_match_mode: %s\n",
		ntohl (policy->be_program_measure_match_mode) == 0 ? "Only hash" : "Band path");
	printf ("policy->process_dmeasure_lib_mode: %s\n", 
		ntohl (policy->be_process_dmeasure_lib_mode) == 1 ? "MEASURE" : "NOT");
	printf ("policy->process_verify_lib_mode: %d\n",ntohl (policy->be_process_verify_lib_mode) );
	printf ("policy->process_dmeasure_sub_process_mode: %s\n", 
		ntohl (policy->be_process_dmeasure_sub_process_mode) == 1 ? "MEASURE" : "NOT");
	printf ("policy->process_dmeasure_old_process_mode: %s\n", 
		ntohl (policy->be_process_dmeasure_old_process_mode) == 1 ? "MEASURE" : "NOT");
	printf ("policy->process_dmeasure_interval: %d\n", ntohl(policy->be_process_dmeasure_interval));	
}

int main ()
{
	int ret = 0;
	struct global_control_policy policy;
	ret = tcs_get_global_control_policy(&policy);
//	httc_util_dump_hex("policy", get_policy, sizeof(struct global_control_policy));
	if(ret){
		printf("[Error] tcs_get_global_control_policy ret:0x%08X\n",ret);
		return -1;
	}
	printf("tcs_get_global_control_policy success!\n");
	show_policy(&policy);
	return 0;
}

