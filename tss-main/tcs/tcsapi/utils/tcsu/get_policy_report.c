#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include "debug.h"
#include "tutils.h"
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

void show_report(struct policy_report *report){

	printf ("report->nonce: 0x%016lX\n", ntohll(report->be_nonce));
	show_policy((struct global_control_policy *)&(report->content.global_control_policy));
	printf ("report->content.file_integrity_valid: 0x%08X\n", ntohl (report->content.be_file_integrity_valid));
	printf ("report->content.file_integrity_total: 0x%08X\n", ntohl (report->content.be_file_integrity_total));
	printf ("report->content.boot_measure_ref_bumber: 0x%08X\n", ntohl (report->content.be_boot_measure_ref_bumber));
	printf ("report->content.dynamic_measure_ref_bumber: 0x%08X\n", ntohl (report->content.be_dynamic_measure_ref_bumber));
	printf ("report->content.admin_cert_number: 0x%08X\n", ntohl (report->content.be_admin_cert_number));
	//printf ("report->content.trusted_cert_number: 0x%08X\n", ntohl (report->content.be_trusted_cert_number));
	httc_util_dump_hex ("report->content.program_reference_hash", report->content.program_reference_hash, DEFAULT_HASH_SIZE);
	httc_util_dump_hex ("report->content.boot_reference_hash", report->content.boot_reference_hash, DEFAULT_HASH_SIZE);
	httc_util_dump_hex ("report->content.dynamic_reference_hash", report->content.dynamic_reference_hash, DEFAULT_HASH_SIZE);
	httc_util_dump_hex ("report->content.admin_cert_hash", report->content.admin_cert_hash, DEFAULT_HASH_SIZE);
	//httc_util_dump_hex ("report->content.trusted_cert_hash", report->content.trusted_cert_hash, DEFAULT_HASH_SIZE);
	httc_util_dump_hex ("report->signiture", report->signiture, DEFAULT_SIGNATURE_SIZE);
}

int main ()
{
	int ret = 0;
	struct policy_report report;
	uint64_t replay_counter;
	
	if(httc_get_replay_counter(&replay_counter)){
		printf("Error httc_get_replay_counter.\n");
		return -1;
	}
	
	ret = tcs_get_policy_report(&report,replay_counter);
	if(ret){
		printf("[Error] tcs_get_global_control_policy ret:0x%08x\n",ret);
		return -1;
	}
	
	printf("tcs_get_global_control_policy success!\n");
	show_report(&report);
	
	return 0;
}

