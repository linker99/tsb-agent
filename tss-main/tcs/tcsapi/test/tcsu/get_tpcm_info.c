#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "sys.h"
#include "debug.h"
#include "convert.h"
#include "tcs_attest.h"

int main(void)
{
	int ret = 0;
	struct tpcm_info info;

	if(0 != (ret = tcs_get_tpcm_info(&info))) {
		httc_util_pr_error ("ret: %d(0x%08x)\n", ret, ret);
		return -1;
	}

	printf("TPCM info:\n");
	printf("  "); httc_util_time_print ("host_time: %s\n", ntohll(info.be_host_time));
	printf("  global_control_policy.size: %d\n", ntohl(info.global_control_policy.be_size));
	printf("  global_control_policy.boot_measure_on: %d\n", ntohl(info.global_control_policy.be_boot_measure_on));
	printf("  global_control_policy.rogram_measure_on: %d\n", ntohl(info.global_control_policy.be_program_measure_on));
	printf("  global_control_policy.dynamic_measure_on: %d\n", ntohl(info.global_control_policy.be_dynamic_measure_on));
	printf("  global_control_policy.boot_control: %d\n", ntohl(info.global_control_policy.be_boot_control));
	printf("  global_control_policy.program_control: %d\n", ntohl(info.global_control_policy.be_program_control));
	printf("  global_control_policy.be_tsb_flag1: %d\n", ntohl(info.global_control_policy.be_tsb_flag1));
	printf("  global_control_policy.be_tsb_flag2: %d\n", ntohl(info.global_control_policy.be_tsb_flag2));
	printf("  global_control_policy.be_tsb_flag3: %d\n", ntohl(info.global_control_policy.be_tsb_flag3));
	printf("  global_control_policy.program_measure_mode: %d\n", ntohl(info.global_control_policy.be_program_measure_mode));
	printf("  global_control_policy.measure_use_cache: %d\n", ntohl(info.global_control_policy.be_measure_use_cache));
	printf("  global_control_policy.dmeasure_max_busy_delay: %d\n", ntohl(info.global_control_policy.be_dmeasure_max_busy_delay));
	printf("  global_control_policy.process_dmeasure_ref_mode: %d\n", ntohl(info.global_control_policy.be_process_dmeasure_ref_mode));
	printf("  global_control_policy.process_dmeasure_match_mode: %d\n", ntohl(info.global_control_policy.be_process_dmeasure_match_mode));
	printf("  global_control_policy.program_measure_match_mode: %d\n", ntohl(info.global_control_policy.be_program_measure_match_mode));
	printf("  global_control_policy.process_dmeasure_lib_mode: %d\n", ntohl(info.global_control_policy.be_process_dmeasure_lib_mode));
	printf("  global_control_policy.process_verify_lib_mode: %d\n", ntohl(info.global_control_policy.be_process_verify_lib_mode));
	printf("  global_control_policy.process_verify_lib_mode: %d\n", ntohl(info.global_control_policy.be_process_verify_lib_mode));
	printf("  cmd_handled: %d\n", ntohl(info.be_cmd_handled));
	printf("  cmd_pending: %d\n", ntohl(info.be_cmd_pending));
	printf("  cmd_error_param: %d\n", ntohl(info.be_cmd_error_param));
	printf("  cmd_error_refused: %d\n", ntohl(info.be_cmd_error_refused));
	printf("  file_integrity_valid: %d\n", ntohl(info.be_file_integrity_valid));
	printf("  file_integrity_total: %d\n", ntohl(info.be_file_integrity_total));
	printf("  boot_measure_ref_number: %d\n", ntohl(info.be_boot_measure_ref_number));
	printf("  dynamic_measure_ref_number: %d\n", ntohl(info.be_dynamic_measure_ref_number));
	printf("  admin_cert_number: %d\n", ntohl(info.be_admin_cert_number));
	printf("  trusted_cert_number: %d\n", ntohl(info.be_trusted_cert_number));
	printf("  boot_times: %d\n", ntohl(info.be_boot_times));
	printf("  dmeasure_times: %ld\n", ntohll(info.be_dmeasure_times));
	printf("  file_integrity_measure_times: %d\n", ntohl(info.be_file_integrity_measure_times));
	printf("  file_notify_times: %d\n", ntohl(info.be_file_notify_times));
	printf("  tpcm_type: %d\n", ntohl(info.be_tpcm_type));
	printf("  tpcm_total_mem: 0x%08x\n", ntohl(info.be_tpcm_total_mem));
	printf("  tpcm_available_mem: 0x%08x\n", ntohl(info.be_tpcm_available_mem));
	printf("  tpcm_nvsapce_size: 0x%08x\n", ntohl(info.be_tpcm_nvsapce_size));
	printf("  tpcm_nvsapce_availble_size: 0x%08x\n", ntohl(info.be_tpcm_nvsapce_availble_size));
	printf("  boot_trust_state: %d\n", ntohl(info.be_boot_trust_state));
	printf("  trust_os_version: 0x%08x\n", ntohl(info.be_trust_os_version));
	printf("  cpu_firmware_version: 0x%08x\n", ntohl(info.be_cpu_firmware_version));
	printf("  bios_firmware_version: 0x%08x\n", ntohl(info.be_bios_firmware_version));
	printf("  tpcm_firmware_version: 0x%08x\n", ntohl(info.be_tpcm_firmware_version));
	printf("  tpcm_cpu_number: %d\n", ntohl(info.be_tpcm_cpu_number));
	printf("  ek_generated: %d\n", ntohl(info.be_ek_generated));
	printf("  srk_generated: %d\n", ntohl(info.be_srk_generated));
	printf("  pik_generated: %d\n", ntohl(info.be_pik_generated));
	printf("  pesistent_key_number: %d\n", ntohl(info.be_pesistent_key_number));
	printf("  alg_mode: %d\n", ntohl(info.be_alg_mode));
	printf("  "); httc_util_dump_hex ("id", info.tpcm_id, sizeof (info.tpcm_id));
	printf("\n");
	
	return 0;
}


