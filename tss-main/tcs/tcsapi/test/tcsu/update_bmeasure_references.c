#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>

#include "mem.h"
#include "debug.h"
#include "tutils.h"
#include "convert.h"
#include "tcs_auth.h"
#include "tcs_attest.h"
#include "tcs_constant.h"
#include "tcs_bmeasure.h"
#include "crypto/sm/sm2_if.h"

//#define __HASH_DEBUG__

#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128

static int with_extern_data = 0;

static void usage ()
{
	printf ("\n"
			" Usage: ./update_bmeasure_references [options]\n"
			" options:\n"
			"        -k <key>			- The privkey string + pubkey string\n"
			"        -o <operation>		- The operation (0-reset<default>; 1-add; 2-delete; 3-modify)\n"
			"        -u <uid>           - The user ID (for match cert)\n"
			"        -e                 - With extern data"
			"        -F <flag>			- The flag <default: 0>\n"
			"							  0x1 - BOOT_REFERENCE_FLAG_CONTROL\n"
			"		 -m <stage>			- The stage num that you want to modify the reference (default: do not modify anything)"
			"    eg. ./update_bmeasure_references -u dmeasure-uid -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"        ./update_bmeasure_references -m 2000 -u dmeasure-uid -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"	
			"\n");
}

int main (int argc, char **argv)
{
	int ch = 0;	
	int ret = 0;
	int i = 0, j = 0;
	uint32_t tpcmRes = 0;
	uint32_t ref_item_length = 0;
	uint8_t  buf[4096] = {0};
	uint32_t number = 0;
	uint8_t *keyStr = NULL;
  	uint32_t keyStrLen = 0;
	uint8_t  privkey[32] = {0};
  	uint32_t privkeyLen = 0;
	uint8_t  pubkey[64] = {0};
  	uint32_t pubkeyLen = 0;
	uint8_t *sign = NULL;
	uint32_t signlength = 0;
	uint32_t operation = POLICY_ACTION_SET;

	uint32_t m_stage[32] = {0};
	uint32_t m_stage_num = 0;
	struct ref_unit_st *ref = NULL;
	int record_item_size = 0;
	int num = 0;
	int record_ops = 0;
	int size = 0;
	int flag = 0;
	int extend_size = with_extern_data ? 4 : 0;
	uint64_t replay_counter;
	unsigned char *records = NULL;
	struct boot_ref_item *ref_item = NULL;
	struct boot_measure_record *bm_records = NULL;
	const char *uid = NULL;
	int auth_type = CERT_TYPE_PUBLIC_KEY_SM2;
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	struct boot_references_update *references = (struct boot_references_update *)buf;

  	while ((ch = getopt(argc, argv, "k:o:u:m:F:eh")) != -1)
	{
		switch (ch) 
		{
			case 'k':
				keyStr = optarg;
				keyStrLen = strlen (keyStr);
				if ((TPCM_PRIVKEY_STR_LEN + TPCM_PUBKEY_STR_LEN) != keyStrLen){
					printf ("Invalid key string!\n");
					ret = -1;
					break;
				}
				httc_util_str2array (privkey, keyStr, TPCM_PRIVKEY_STR_LEN);
				privkeyLen = TPCM_PRIVKEY_STR_LEN / 2;
				//httc_util_dump_hex ("privkey", privkey, privkeyLen);
				httc_util_str2array (pubkey, keyStr + TPCM_PRIVKEY_STR_LEN, TPCM_PUBKEY_STR_LEN);
				pubkeyLen = TPCM_PUBKEY_STR_LEN / 2;
				//httc_util_dump_hex ("pubkey", pubkey, pubkeyLen);
				ret = -1;
				break;
			case 'o':
				operation = atoi (optarg);
				break;
			case 'u':
				uid = optarg;
				break;
			case 'e':
				with_extern_data = 1;
				break;
			case 'F':
				flag = strtol (optarg, NULL, 16);
				//printf ("***flag: 0x%x\n", flag);
				break;
			case 'm':
				m_stage[m_stage_num] = atoi (optarg);
				m_stage_num ++;
				break;
			case 'h':
			default:
				usage ();
				return -EINVAL;
		}
	}

	ret = tcs_get_boot_measure_records ((struct boot_measure_record **)&records, &num, &size);
	if (ret){
		printf ("[tpcm_get_boot_measure_references_record] ret: %d(0x%x)\n", ret, ret);
		return -1;
	}

	for (i = 0; i < num; i ++){
		bm_records = (struct boot_measure_record *)(records + record_ops);
		ref_item = (struct boot_ref_item *)(references->data + ref_item_length);
		ref_item->be_hash_length = bm_records->be_hash_length;
		ref_item->be_flags = htons (flag & 0xFFFF);
		ref_item->be_name_length = bm_records->be_name_length;
		ref_item->be_hash_number = htons (1);
		ref_item->be_stage = bm_records->be_stage;
		ref_item->be_extend_size = htons (extend_size);
		memcpy (ref_item->data, bm_records->data, ntohs (bm_records->be_hash_length));
		if (extend_size) memset (ref_item->data + ntohs (bm_records->be_hash_length), 'A', extend_size);
		memcpy (ref_item->data + ntohs (bm_records->be_hash_length) + extend_size,
				bm_records->data + ntohs (bm_records->be_hash_length), ntohs (bm_records->be_name_length));
		record_ops += HTTC_ALIGN_SIZE (sizeof (struct boot_measure_record)
				+ ntohs (bm_records->be_hash_length) + ntohs (bm_records->be_name_length), 4);
		ref_item_length += HTTC_ALIGN_SIZE (sizeof (struct boot_ref_item) 
				+ ntohs (ref_item->be_hash_length) * ntohs (ref_item->be_hash_number)
				+ ntohs (ref_item->be_extend_size) + ntohs (ref_item->be_name_length), 4);
	}	
	
	if(httc_get_replay_counter(&replay_counter)){
		printf("Error httc_get_replay_counter.\n");
		ret = -1;
		goto out;
	}
	
	references->be_size = htonl (sizeof (struct boot_references_update));
	references->be_action = htonl (operation);
	references->be_replay_counter = htonll (replay_counter);
	references->be_item_number = htonl (num);
	references->be_data_length = htonl (ref_item_length);

	if (0 != (ret = tcs_get_tpcm_id (references->tpcm_id, &tpcm_id_length))){
		printf ("Get tpcm id error: %d(0x%x)\n", ret, ret);
		ret = -1;
		goto out;
	}

#ifdef __HASH_DEBUG__
	uint8_t wlHash[DEFAULT_HASH_SIZE] = {0};
	sm3 ((const uint8_t *)references->data, ref_item_length, wlHash);
	httc_util_dump_hex ("wlHash", wlHash, DEFAULT_HASH_SIZE);
#endif

	if (keyStr){
		ret = os_sm2_sign ((const uint8_t *)references, sizeof (struct boot_references_update) + ref_item_length, privkey, 32, pubkey, 64, &sign, &signlength);
		if (ret){
			printf ("Sign for reference failed!\n");
			ret = -1;
			goto out;
		}
		ret = os_sm2_verify ((const uint8_t *)references, sizeof (struct boot_references_update) + ref_item_length, pubkey, 64, sign, signlength);
		if (ret){
			printf ("Verify for reference failed!\n");
		}
	}

	if (0 != (ret = tcs_update_boot_measure_references (references, uid, auth_type, signlength, sign))){
		printf ("tpcm_update_boot_measure_references error: %d(0x%x)\n", ret, ret);
	}

out:
	if (records) httc_free (records);
	if (sign) SM2_FREE(sign);
	return ret;
}

