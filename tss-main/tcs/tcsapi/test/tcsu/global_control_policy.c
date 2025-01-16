#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>

#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "tcs_attest.h"
#include "tcs_policy.h"
#include "tcs_policy_def.h"
#include "tcs_constant.h"
#include "tcs_auth_def.h"
#include "tutils.h"
#include "crypto/sm/sm2_if.h"

#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128

uint8_t  privkey[32] = {0};
uint8_t  pubkey[64] = {0};
uint32_t default_tag = 0;
uint32_t policy_option = POLICY_ACTION_SET;
uint32_t policy_value = 0;

uint32_t pol[19] = {1, 1, 1, 0, 1, 1, 1, 1,PROCESS_MEASURE_MODE_TCS_MEASURE ,1,300,
					PROCESS_DMEASURE_REF_START, PROCESS_DMEASURE_MATCH_HASH_ONLY, PROCESS_MEASURE_MATCH_HASH_ONLY,
					PROCESS_DMEASURE_MODE_NON_MEASURE, PROCESS_VERIFY_MODE_DEFAULT, PROCESS_DMEASURE_MODE_MEASURE,
					PROCESS_DMEASURE_MODE_MEASURE,60000};

static void usage ()
{
	printf ("\n"
			" Usage: ./global_control_policy -a <auth_type> -k <key> -u <uid> -p <policy> -v <value> -o <operation>\n"
			"        -a <auth_type>	 - The auth_type (default)1:SM2 2:HMAC 3:X501_SM2\n"
			"        -k <key>         - The privkey string + pubkey string\n"
			"        -u <uid>         - The uid\n"
			"        -p <policy>:      - The actual policy\n"
			"        -v <value>       - The policy value\n"
			"        -o <operation>	 - (default)0:tcs_set_global_control_policy\n"
			"                                   1:tcs_get_global_control_policy\n"
			"                                   2:tcs_get_policy_report\n"
			"    eg. ./global_control_policy -a 1 -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A -u 123123 -o 0\n"
			"    eg. ./global_control_policy -a 1 -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A -u 123123 -p 0 -v 1-o 0\n\n");
}

static char* str(int a){
	switch(a){
        case 1: return ("boot_measure_on                         <0:off 1:on>");
        case 2: return ("program_measure_on                      <0:off 1:on>");
		case 3: return ("dynamic_measure_on                      <0:off 1:on>");
		case 4: return ("boot_control                            <0:not 1:contorl>");
		case 5: return ("program_control                         <0:not 1:contorl>");
		case 6: return ("policy_replay_check                     <0:not 1:check>");
		case 7: return ("static_reference_replay_check           <0:not 1:check>");
		case 8: return ("dynamic_reference_replay_check          <0:not 1:check>");
		case 9: return ("program_measure_mode                    <0:tsb measure 1:tsb measure and tcs match 2:tcs measure 3:auto-measure>");
		case 10: return ("measure_use_cache                      <0:not 1:use>");
		case 11: return ("dmeasure_max_busy_delay                <second>");
		case 12: return ("process_dmeasure_ref_mode              <0:Collection at startup 1:File library integrity>");
		case 13: return ("process_dmeasure_match_mode            <0:hash 1:path>");
		case 14: return ("program_measure_match_mode             <0:hash 1:path>");
		case 15: return ("process_dmeasure_lib_mode              <1:measure 2:no>");
		case 16: return ("process_verify_lib_mode                <0:By strategy 1:no measure 2:By global hash lib 3:By specially lib>");
		case 17: return ("process_dmeasure_sub_process_mode      <1:measure 2:no>");
		case 18: return ("process_dmeasure_old_process_mode      <1:measure 2:no>");
		case 19: return ("process_dmeasure_interval              <millisecond>");
        default: return ("Error!");
    }

}
static void policy_view(){
	int i = 1;
	printf("====================[policy - value]==================\n");
	for(; i <= 19;i++){
		printf("%d - %s\n",i,str(i));

	}

}


void build_policy(struct global_control_policy *policy){
	if(!default_tag){	
			policy->be_size = htonl(sizeof(struct global_control_policy));
			policy->be_boot_measure_on = htonl(pol[0]);
			policy->be_program_measure_on = htonl(pol[1]);
			policy->be_dynamic_measure_on = htonl(pol[2]);
			policy->be_boot_control = htonl(pol[3]);
			policy->be_program_control = htonl(pol[4]);
			policy->be_tsb_flag1 = htonl(pol[5]);
			policy->be_tsb_flag2 = htonl(pol[6]);
			policy->be_tsb_flag3 = htonl(pol[7]);
			policy->be_program_measure_mode = htonl(pol[8]);
			policy->be_measure_use_cache = htonl(pol[9]);
			policy->be_dmeasure_max_busy_delay = htonl(pol[10]);
			policy->be_process_dmeasure_ref_mode = htonl(pol[11]);
			policy->be_process_dmeasure_match_mode = htonl(pol[12]);
			policy->be_program_measure_match_mode = htonl(pol[13]);
			policy->be_process_dmeasure_lib_mode = htonl(pol[14]);
			policy->be_process_verify_lib_mode = htonl(pol[15]);
			policy->be_process_dmeasure_sub_process_mode = htonl(pol[16]);
			policy->be_process_dmeasure_old_process_mode = htonl(pol[17]);
			policy->be_process_dmeasure_interval = htonl(pol[18]);
	}else{
		*(uint32_t *)((char *)policy + policy_option * sizeof(uint32_t))
															= htonl(policy_value);
	}
}

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

int httc_sign_verify(const unsigned char *dgst, int dlen,
                unsigned char *privkey, unsigned int privkey_len,
                unsigned char *pubkey, unsigned int pubkey_len,
                unsigned char **sig, unsigned int *siglen){

	int ret = 0;
	ret = os_sm2_sign ((const uint8_t *)dgst, dlen, privkey, privkey_len, pubkey, pubkey_len, sig, siglen);
	if (ret){
		printf ("Sign for reference failed!\n");
		return -1;
	}

	ret = os_sm2_verify ((const uint8_t *)dgst, dlen, pubkey, pubkey_len, *sig, *siglen);
	if (ret){
		printf ("Verify for reference failed!\n");
	}
	return ret;
}

int main(int argc, char **argv){
	
	int ret = 0;
	int ch = 0;
	int opt = 0;
	int len = MAX_TPCM_ID_SIZE;
	char *uid = NULL;
	int auth_type = CERT_TYPE_PUBLIC_KEY_SM2;
	uint8_t *data = NULL;
	uint8_t *KeytStr = NULL;
//	uint8_t *PolicyStr = NULL;
	int keystrlen = 0;
	uint8_t *sign = NULL;
	uint32_t signlen = 0;
	struct global_control_policy_update *policy = NULL;
	struct global_control_policy *get_policy = NULL;
	struct policy_report *report = NULL;
	uint64_t replay_counter;
	uint64_t nonce = 0x12345678;
	
	if(argc < 3 || !(argc%2)){
		usage();
		policy_view();
		return-1;
	}
	
	while ((ch = getopt(argc, argv, "a:k:u:p:v:o:h")) != -1)
	{
		switch (ch) 
		{
			case 'a':
				auth_type = atoi(optarg);
				break;
			case 'k':
				KeytStr = optarg;
				keystrlen = strlen((const char *)KeytStr);
				if(keystrlen != TPCM_PRIVKEY_STR_LEN + TPCM_PUBKEY_STR_LEN){
					usage();
					return -1;
				}
				httc_util_str2array(privkey,KeytStr,TPCM_PRIVKEY_STR_LEN);
				httc_util_str2array(pubkey,KeytStr + TPCM_PRIVKEY_STR_LEN,TPCM_PUBKEY_STR_LEN);
//				httc_util_dump_hex ("privkey", privkey , TPCM_PRIVKEY_STR_LEN/2);
//				httc_util_dump_hex ("pubkey", pubkey , TPCM_PUBKEY_STR_LEN/2);
				break;
			case 'u':
				uid = optarg;
				break;
			
			case 'p':
				policy_option = atoi(optarg);
				default_tag = 1;
				break;
			case 'v':
				policy_value = atoi(optarg);
				break;
			case 'o':
				opt = atoi(optarg);
				break;
			case 'h':
				usage ();
				break;
			default:
				usage ();
				return -EINVAL;
		}
	}

	if(NULL ==(data = httc_malloc(4096))){
		printf("[Error] Malloc error!\n");
		return -1;
	}
	
	
	if( opt == 0){
		if(uid == NULL ){
			usage ();
			return -1;
		}
		policy = (struct global_control_policy_update *)data;
		if(default_tag) ret = tcs_get_global_control_policy(&(policy->policy));
//		httc_util_dump_hex("before policy", &(policy->policy), sizeof(struct global_control_policy));
		if(ret){
			printf("[Error] tcs_get_global_control_policy ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}		
		build_policy(&(policy->policy));
//		httc_util_dump_hex("after policy", &policy->policy, sizeof(struct global_control_policy));
		
	
		if(httc_get_replay_counter(&replay_counter)){
			printf("Error httc_get_replay_counter.\n");
			ret = -1;
			goto out;
		}	
		ret = tcs_get_tpcm_id(policy->tpcm_id, &len);
		if(ret) goto out;
		policy->be_replay_counter = htonll(replay_counter);
		
		ret = httc_sign_verify((const unsigned char *)policy,sizeof(struct global_control_policy_update),privkey,32,pubkey,64,&sign,&signlen);
		if (ret){
			printf ("[Error] httc_sign_verify failed!\n");
			ret = -1;
			goto out;
		}
		
		ret = tcs_set_global_control_policy(policy,(const char *)uid,auth_type,signlen,sign);
		if(ret){
			printf("[Error] tcs_set_global_control_policy ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		printf("tcs_set_global_control_policy success!\n");
		goto out;
	}else if(opt == 1){
		get_policy = (struct global_control_policy *)data;
		ret = tcs_get_global_control_policy(get_policy);
//		httc_util_dump_hex("policy", get_policy, sizeof(struct global_control_policy));
		if(ret){
			printf("[Error] tcs_get_global_control_policy ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		printf("tcs_get_global_control_policy success!\n");
		show_policy(get_policy);
		goto out;
	}else if(opt == 2){
		report = (struct policy_report *)data;
	
		if(httc_get_replay_counter(&replay_counter)){
			printf("Error httc_get_replay_counter.\n");
			ret = -1;
			goto out;
		}
		
		ret = tcs_get_policy_report(report,nonce);
		if(ret){
			printf("[Error] tcs_get_global_control_policy ret:0x%08x\n",ret);
			ret = -1;
			goto out;
		}else if( nonce != ntohll(report->be_nonce)){
			printf("[Error] tcs_get_global_control_policy nonce 0x%016lX:0x%016lX\n",nonce,ntohll(report->be_nonce));
			ret = -1;
			goto out;
		}
		printf("tcs_get_global_control_policy success!\n");
		show_report(report);
		goto out;
	}
out:
	if(sign) SM2_FREE(sign);
	if(data) httc_free(data);
	return ret;
}

