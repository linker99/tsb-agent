#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "mem.h"
#include "debug.h"
#include "sys.h"
#include "convert.h"

#include "tcs_attest.h"
#include "tcs_attest_def.h"


#define THREAD_NUM_MAX	1024
static pthread_t task_pid[THREAD_NUM_MAX];

void * concurrent_test (void *arg){
	int ret = 0;
	struct tpcm_info info;
	memset(&info,0,sizeof(struct tpcm_info));
	while (1){
		if(0 != (ret = tcs_get_tpcm_info(&info))) {
			httc_util_pr_error ("ret: %d(0x%08x)\n", ret, ret);
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
		usleep (rand()%1000000);
		}
}


void usage (void)
{
		printf ("\n");
		printf (" Usage: ./concurrent_test num \n");
		printf ("    eg. ./concurrent_test 10 (<1-1024>, default: 1)\n");
		printf ("\n");
}

int main (int argc, char **argv)
{
	int i = 0;
	int ret = 0;
	int task_num = atoi (argv[1]);

	if ((task_num > 1024) || (task_num < 1)){
		httc_util_pr_error ("Error: Invalid thread num %d (not in 1-1024)!\n", task_num);
		return -1;
	}

	for (i = 0; i < task_num; i++){
		if ((ret = pthread_create (&task_pid[i], NULL, concurrent_test, NULL)) < 0){
			goto out;		
		}
	}

	for (i = 0; i < task_num; i++){
		pthread_join (task_pid[i], NULL);
	}

	return 0;

out:
	for (i --; i >= 0; i--)
		pthread_cancel (task_pid[i]);
	return 0;
}

