#!/bin/sh

run_cmd()
{
	#echo "$*"
	$*
	if [ $? -ne 0 ]; then
		exit 1
	fi
}

run_cmd ./user/utils/tcs/generate_trust_report
run_cmd ./user/utils/tcs/get_global_control_policy 
run_cmd ./user/utils/tcs/get_license_status
run_cmd ./user/utils/tcs/get_policy_report
run_cmd ./user/utils/tcs/get_tpcm_features 
run_cmd ./user/utils/tcs/get_tpcm_info
run_cmd ./user/utils/tcs/get_trust_status
run_cmd ./user/utils/tcs/get_bmeasure_records
run_cmd ./user/utils/tcs/get_tpcm_id
#run_cmd ./user/utils/tcs/reset_test_license

