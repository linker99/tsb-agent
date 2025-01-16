#!/bin/sh

run_cmd()
{
	#echo "$*"
	$*
	if [ $? -ne 0 ]; then
		exit 1
	fi
}

run_cmd ./user/utils/tcf/generate_trust_report
run_cmd ./user/utils/tcf/get_global_control_policy 
run_cmd ./user/utils/tcf/get_license_status
run_cmd ./user/utils/tcf/get_tpcm_features 
run_cmd ./user/utils/tcf/get_tpcm_info
run_cmd ./user/utils/tcf/get_trust_status
run_cmd ./user/utils/tcf/get_host_id
run_cmd ./user/utils/tcf/get_log_config
run_cmd ./user/utils/tcf/get_bmeasure_records
run_cmd ./user/utils/tcf/get_policy_version
run_cmd ./user/utils/tcf/get_tpcm_id
#run_cmd ./user/utils/tcf/reset_test_license

