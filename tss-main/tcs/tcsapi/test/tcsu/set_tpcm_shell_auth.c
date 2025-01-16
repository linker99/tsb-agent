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
#include "crypto/sm/sm2_if.h"
#include "tcs_policy.h"
#include "tcs_attest.h"
#include "tcs_auth_def.h"
#include "tcs_maintain.h"

#define TPCM_PRIVKEY_STR_LEN	(SM2_PRIVATE_KEY_SIZE * 2)
#define TPCM_PUBKEY_STR_LEN		(SM2_PUBLIC_KEY_SIZE * 2)

void usage (void)
{
	printf ("\n"
			" Usage: ./set_tpcm_shell_auth -p <password> [options]\n"
			"        -p <password>      - The password string\n"
			" options:\n"
			"        -u <uid>           - The user ID (for match cert)\n"
			"		 -k <key>			- The privkey string + pubkey string\n"
			"    eg. ./set_tpcm_shell_auth -p abcd -u uid -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	int ch = 0;
	uint64_t replay_counter;
	int marklength = MAX_TPCM_ID_SIZE;
	char *pwd = NULL;
	struct shell_passwd *passwd = NULL;
	const char *uid = NULL;
	uint8_t *keyStr = NULL;
  	uint32_t keyStrLen = 0;
	uint8_t  privkey[32] = {0};
  	uint32_t privkeyLen = 0;
	uint8_t  pubkey[64] = {0};
  	uint32_t pubkeyLen = 0;
	uint8_t *sign = NULL;
	uint32_t signlength = 0;
	int auth_type = CERT_TYPE_PUBLIC_KEY_SM2;

	while ((ch = getopt(argc, argv, "t:p:u:k:")) != -1)
	{
		switch (ch) 
		{
			case 'p':
				pwd = optarg;
				//printf ("pwd: %s\n", pwd);
				break;
			case 'u':
				uid = optarg;
				break;				
			case 'k':
				keyStr = optarg;	
				keyStrLen = strlen(keyStr);
				if ((TPCM_PRIVKEY_STR_LEN + TPCM_PUBKEY_STR_LEN) != keyStrLen){
					printf ("Invalid key string!\n");
					return -EINVAL;
				}
				httc_util_str2array (privkey, keyStr, TPCM_PRIVKEY_STR_LEN);
				privkeyLen = TPCM_PRIVKEY_STR_LEN / 2;
				httc_util_dump_hex ("privkey", privkey, privkeyLen);
				httc_util_str2array (pubkey, keyStr + TPCM_PRIVKEY_STR_LEN, TPCM_PUBKEY_STR_LEN);
				pubkeyLen = TPCM_PUBKEY_STR_LEN / 2;
				httc_util_dump_hex ("pubkey", pubkey, pubkeyLen);
				break;
			default:
				usage ();
				return -EINVAL;
		}
	}

	if (!pwd || !keyStr || !uid){
		usage ();
		return -EINVAL;
	}

	if (NULL == (passwd = httc_malloc (1024))){
		perror ("No mem");
		return -1;
	}
	
	if(httc_get_replay_counter(&replay_counter)){
		printf("Error httc_get_replay_counter.\n");
		return -1;
	}
	
	if (0 != (ret = tcs_get_tpcm_id (passwd->tpcm_id, &marklength))){
		printf ("Get tpcm id error: %d(0x%x)\n", ret, ret);
		return -1;
	}
	passwd->be_replay_counter = htonll(replay_counter);
	passwd->be_password_length = htonl(strlen (pwd));
	strcpy (passwd->password, pwd);

	if (keyStr){
		if (0 != (ret = os_sm2_sign((const unsigned char *)passwd, sizeof (struct shell_passwd) + strlen (pwd),
					privkey, SM2_PRIVATE_KEY_SIZE, pubkey, SM2_PUBLIC_KEY_SIZE, &sign, &signlength))){
			printf ("Sign failed!\n");
			return ret;
		}		
		if (0 != (ret = os_sm2_verify ((const unsigned char *)passwd,
					sizeof (struct shell_passwd) + strlen (pwd), pubkey, SM2_PUBLIC_KEY_SIZE, sign, signlength))){
			printf ("Verify failed!\n");
		}
	}

	if (0 != (ret = tcs_set_shell_password (passwd, uid, auth_type, signlength, sign))){
		printf ("[tcs_set_shell_password] ret: %d(0x%x)\n", ret, ret);
		ret = -1;
	}

	if (sign) SM2_FREE (sign);
	return ret;
}

