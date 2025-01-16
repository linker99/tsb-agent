#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <httcutils/convert.h>
#include <httcutils/debug.h>
#include <httcutils/mem.h>

#include "tcfapi/tcf_auth.h"
#include "tcsapi/tcs_constant.h"
#include "tcfapi/tcf_attest.h"
#include "tcsapi/tcs_auth_def.h"
#include "crypto/sm/sm2_if.h"
#include "crypto/sm/sm3.h"
#include "../src/tutils.h"

#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128

uint8_t  privkey[32] = {0};
uint8_t  pubkey[64] = {0};

static void usage ()
{
	printf ("\n"
			" Usage: ./tcf_auth -n <name> -c <cert_type> -d <cert_data> -o <operation> -k <key>\n"
			"		 -t <name>      - The name of cert\n"
			"		 -c <cert_type> - The auth_type (default)1:SM2 2:HMAC 3:X501_SM2\n"
			"		 -d <cert_data> - The cert data\n"
			"		 -o <operation> - (default)0:tcf_set_admin_cert\n"
			"                                  1:tcf_grant_admin_role\n"
			"                                  2:tcf_remove_admin_role\n"
			"                                  3:tcf_get_admin_list\n"
			"		 -k <key>       - The privkey string + pubkey string\n"			
			"	 eg. ./tcf_auth -n root -c 1 -d 09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A -o 0\n"
			"	 eg. ./tcf_auth -n root -c 1 -d 09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A -o 1 -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n\n");
}


int cert_type = 0;
unsigned char cert_data[MAX_CERT_SIZE];
int act = POLICY_ACTION_SET;
int certlen = 0;
char *certname = NULL;



void show_cert(struct admin_cert_info *cert,int num){
	
	int i = 0;
	for(;i < num; i++){
//		httc_util_dump_hex ("Cert", cert + i , sizeof(struct admin_cert_info));
		printf("================Cert:%d================\n",i);
		printf ("cert->is_root: 0x%08X\n", (cert + i)->is_root);
		printf ("cert->be_cert_type: 0x%08X\n", (cert + i)->cert_type);
		printf ("cert->be_cert_len: 0x%08X\n", (cert + i)->cert_len);
		printf ("cert->name: %s\n", (cert + i)->name);
		httc_util_dump_hex ("CERT", (cert + i)->data ,(cert + i)->cert_len);
	}
	if(cert) httc_free(cert);
}

void build_cert(struct admin_cert_update *cert){
	
	uint64_t replay_counter;
	
	if(httc_get_replay_counter(&replay_counter)){
		printf("Error httc_get_replay_counter.\n");
		return;
	}
	cert->be_replay_counter = htonll(replay_counter);
	cert->be_size = htonl(sizeof(struct admin_cert_update));
	cert->be_action = htonl(act);
	cert->cert.be_cert_type = htonl(cert_type);
	cert->cert.be_cert_len = htonl(certlen);
	memcpy(cert->cert.name,certname,strlen((const char *)certname));
	cert->cert.name[strlen((const char *)certname)] = '\0';
	memcpy(cert->cert.data,cert_data,certlen);
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


int main(int argc,char **argv){

	int ch = 0;
	int opt = 0;
	int ret = 0;	
	int num = 0;
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	int auth_length = 0;		
	uint8_t *data = NULL;
	uint8_t *CertStr = NULL;
	uint8_t *KeytStr = NULL;
	int keystrlen = 0;
	uint8_t *sign = NULL;
	uint32_t signlen = 0;
	struct admin_cert_update *update = NULL;
	struct admin_cert_info *list = NULL;

	if(argc < 3 || !(argc%2)){
		usage();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "n:c:d:o:k:h")) != -1)
	{
		switch (ch) 
		{
			case 'n':
				certname = optarg;
				break;
			case 'c':
				cert_type = atoi(optarg);
				break;
			case 'd':
				CertStr = optarg;
				certlen = strlen(CertStr);
				httc_util_str2array(cert_data,CertStr,certlen);
				certlen = certlen/2;
				break;
			case 'o':
				opt = atoi(optarg);
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
			case 'h':
				usage ();
				break;
			default:
				usage ();
				return -1;
		}
	}

	if(NULL == (data = httc_malloc(4096))){
		printf("[Error] Malloc error!\n");
		return -1;
	}
	if(opt == 0){
		act = POLICY_ACTION_SET;
		update = (struct admin_cert_update *)data;
		ret = tcf_get_tpcm_id(update->tpcm_id, &tpcm_id_length);
		build_cert(update);
		if(KeytStr){
			ret = httc_sign_verify((const unsigned char *)update,sizeof(struct admin_cert_update),privkey,32,pubkey,64,&sign,&signlen);
			if (ret){
				printf ("[Error] httc_sign_verify failed!\n");
				ret = -1;
				goto out;
			}
		}
		
		ret = tcf_set_admin_cert(update,cert_type, signlen,sign);		
		if(ret){
			printf("[Error] tcs_set_admin_cert ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		goto out;
	}else if(opt == 1){
		act = POLICY_ACTION_ADD;
		update = (struct admin_cert_update *)data;
		ret = tcf_get_tpcm_id(update->tpcm_id, &tpcm_id_length);
		build_cert(update);
		
		ret = httc_sign_verify((const unsigned char *)update,sizeof(struct admin_cert_update),privkey,32,pubkey,64,&sign,&signlen);
		if (ret){
			printf ("[Error] httc_sign_verify failed!\n");
			ret = -1;
			goto out;
		}

		ret = tcf_grant_admin_role(update, cert_type,signlen,sign);
		if(ret){
			printf("[Error] tcs_grant_admin_role ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		goto out;
	}else if(opt == 2){
		act = POLICY_ACTION_DELETE;
		update = (struct admin_cert_update *)data;
		ret = tcf_get_tpcm_id(update->tpcm_id, &tpcm_id_length);
		build_cert(update);
		ret = httc_sign_verify((const unsigned char *)update,sizeof(struct admin_cert_update),privkey,32,pubkey,64,&sign,&signlen);
		if(ret){
			printf("[Error] httc_sign_verify ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		ret = tcf_remove_admin_role(update, cert_type,signlen,sign);
		if(ret){
			printf("[Error] tcs_remove_admin_role ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		goto out;
	}else if(opt == 3){
		
		ret = tcf_get_admin_list(&list, &num);
		if(ret){
			printf("[Error] tcf_get_admin_list ret:0x%08X\n",ret);
			return -1;
		}
		show_cert(list,num);
		goto out;
	}
	

out:
	if(sign) SM2_FREE(sign);
	if(data) httc_free(data);
	return ret;

}

