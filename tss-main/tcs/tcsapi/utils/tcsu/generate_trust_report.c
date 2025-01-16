#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "sys.h"
#include "debug.h"
#include "convert.h"
#include "tcs_attest.h"
#include "tcs_constant.h"
#include "tcs_attest_def.h"
#include "tcs_policy_def.h"
#include "tutils.h"


void show_policy(struct global_control_policy *policy){

	printf ("policy->be_size: 0x%08X\n", ntohl (policy->be_size));
	printf ("policy->be_boot_measure_on: %s\n", ntohl (policy->be_size) == 0 ? "OFF" : "ON");
	printf ("policy->be_dynamic_measure_on: %s\n", ntohl (policy->be_dynamic_measure_on) == 0 ? "OFF" : "ON");
	printf ("policy->be_boot_control: %s\n", ntohl (policy->be_boot_control) == 0 ? "NOT" : "CONTROL");
	printf ("policy->be_program_control: %s\n", ntohl (policy->be_program_control) == 0 ? "NOT" : "CHECK");
	printf ("policy->be_tsb_flag1: %s\n", ntohl (policy->be_tsb_flag1) == 0 ? "NOT" : "CHECK");
	printf ("policy->be_tsb_flag2: %s\n", ntohl (policy->be_tsb_flag2) == 0 ? "NOT" : "CHECK");
	printf ("policy->be_tsb_flag3: %s\n", ntohl (policy->be_tsb_flag3) == 0 ? "NOT" : "CONTROL");
	printf ("policy->be_program_measure_mode: %d\n", ntohl (policy->be_program_measure_mode));
	printf ("policy->be_measure_use_cache: %s\n", ntohl (policy->be_measure_use_cache) == 0 ? "NOT" : "USE_CACHE");
	printf ("policy->be_dmeasure_max_busy_delay: %d\n", ntohl (policy->be_dmeasure_max_busy_delay));
	printf ("policy->be_process_dmeasure_ref_mode: %s\n",
		ntohl (policy->be_process_dmeasure_ref_mode) == 0 ? "Collection at startup" : "File library integrity");
	printf ("policy->be_process_dmeasure_match_mode: %s\n",
		ntohl (policy->be_process_dmeasure_match_mode) == 0 ? "Only hash" : "Band path");
	printf ("policy->be_program_measure_match_mode: %s\n",
		ntohl (policy->be_program_measure_match_mode) == 0 ? "Only hash" : "Band path");
	printf ("policy->be_process_dmeasure_lib_mode: %s\n",
		ntohl (policy->be_process_dmeasure_lib_mode) == 0 ? "NOT" : "MEASURE");
	printf ("policy->be_process_verify_lib_mode: %s\n",
		ntohl (policy->be_process_verify_lib_mode) == 0 ? "File library integrity" : "Identity authentication");

}


int main(void){

	int ret = 0;
	struct trust_report report;
	uint64_t nonce = 0x12345678;
	uint32_t be_addr=0;
	unsigned char host_id[MAX_HOST_ID_SIZE] = {0};
	int len_inout = MAX_HOST_ID_SIZE;

	if(httc_get_replay_counter(&nonce)){
		printf("Error httc_get_replay_counter.\n");
		return -1;
	}

	ret = tcs_get_host_id(host_id,&len_inout);
	if(ret) return ret;


	if ((ret = tcs_generate_trust_report(&report,nonce,host_id,be_addr))){
		printf("tcs_generate_trust_report ret:0x%08x\n",ret);
		return -1;
	}

	if (nonce != ntohll(report.be_nonce)){
		printf("Unmatched nonce: 0x%016lx != 0x%016lx\n", nonce, ntohll(report.be_nonce));
		return -1;
	}

	httc_util_time_print ("report.content.be_host_report_time: %s\n", ntohll (report.content.be_host_report_time));
	httc_util_time_print ("report.content.be_host_startup_time: %s\n", ntohll (report.content.be_host_startup_time));
	httc_util_dump_hex ("report.content.host_id", report.content.host_id, MAX_HOST_ID_SIZE);
	httc_util_dump_hex ("report.content.tpcm_id", report.content.tpcm_id, MAX_TPCM_ID_SIZE);
	show_policy(&(report.content.global_control_policy));
	printf ("report.content.be_eval: 0x%08X\n", ntohl (report.content.be_eval));
	printf ("report.content.be_host_ip: 0x%08X\n", ntohl (report.content.be_host_ip));
	printf ("report.content.be_ilegal_program_load: 0x%08X\n", ntohl (report.content.be_ilegal_program_load));
	printf ("report.content.be_ilegal_lib_load: 0x%08X\n", ntohl (report.content.be_ilegal_lib_load));
	printf ("report.content.be_ilegal_kernel_module_load: 0x%08X\n", ntohl (report.content.be_ilegal_kernel_module_load));
	printf ("report.content.be_ilegal_file_access: 0x%08X\n", ntohl (report.content.be_ilegal_file_access));
	printf ("report.content.be_ilegal_device_access: 0x%08X\n", ntohl (report.content.be_ilegal_device_access));
	printf ("report.content.be_ilegal_network_inreq: 0x%08X\n", ntohl (report.content.be_ilegal_network_inreq));
	printf ("report.content.be_ilegal_network_outreq: 0x%08X\n", ntohl (report.content.be_ilegal_network_outreq));
	printf ("report.content.be_process_code_measure_fail: 0x%08X\n", ntohl (report.content.be_process_code_measure_fail));
	printf ("report.content.be_kernel_code_measure_fail: 0x%08X\n", ntohl (report.content.be_kernel_code_measure_fail));
	printf ("report.content.be_kernel_data_measure_fail: 0x%08X\n", ntohl (report.content.be_kernel_data_measure_fail));
	printf ("report.content.be_notify_fail: 0x%08X\n", ntohl (report.content.be_notify_fail));
	printf ("report.content.be_boot_measure_result: 0x%08X\n", ntohl (report.content.be_boot_measure_result));
	printf ("report.content.be_boot_times: 0x%08X\n", ntohl (report.content.be_boot_times));
	printf ("report.content.be_tpcm_time: 0x%08X\n", ntohl (report.content.be_tpcm_time));
	httc_util_time_print ("report.content.be_tpcm_report_time: %s\n", ntohll (report.content.be_tpcm_report_time));
	printf ("report.content.be_log_number: 0x%08X\n", ntohl (report.content.be_log_number));
	httc_util_dump_hex ("report.content.log_hash", report.content.log_hash, DEFAULT_HASH_SIZE);
	httc_util_dump_hex ("report.content.bios_pcr", report.content.bios_pcr, DEFAULT_PCR_SIZE);
	httc_util_dump_hex ("report.content.boot_loader_pcr", report.content.boot_loader_pcr, DEFAULT_PCR_SIZE);
	httc_util_dump_hex ("report.content.kernel_pcr", report.content.kernel_pcr, DEFAULT_PCR_SIZE);
	httc_util_dump_hex ("report.content.tsb_pcr", report.content.tsb_pcr, DEFAULT_PCR_SIZE);
	httc_util_dump_hex ("report.content.boot_pcr", report.content.boot_pcr, DEFAULT_PCR_SIZE);
	printf ("report.be_nonce: 0x%016lx\n", ntohll (report.be_nonce));
	httc_util_dump_hex ("report.signature", report.signature, DEFAULT_SIGNATURE_SIZE);

	return 0;
}

