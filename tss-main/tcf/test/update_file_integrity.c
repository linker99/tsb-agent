#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <httcutils/mem.h>
#include <httcutils/convert.h>
#include <httcutils/debug.h>
#include "tcfapi/tcf_auth.h"
#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_file_integrity.h"
#include "tcsapi/tcs_file_integrity.h"
#include "crypto/sm/sm2_if.h"
#include "crypto/sm/sm3.h"
#include "../src/tutils.h"


//#define __RATE_CHECK__
#define __HASH_DEBUG__

char* file_integrity_ops[4] = {"reset", "add", "delete", "modify"};

static void usage ()
{
	printf ("\n"
			" Usage: ./update_file_integrity [options]\n"
			" options:\n"
			"        -k <key>           - The privkey string + pubkey string\n"
			"        -f <filename>      - The filename as a whitelistreference file\n"
			"        -d <filepath>      - The filepath as the whitelistreference files\n"
			"        -o <operation>     - The operation (0-reset<default>; 1-add; 2-delete; 3-modify)\n"
			"        -u <uid>           - The user ID (for match cert)\n"
			"        -F <flag>          - The flag <default: 0>\n"
			"                             0x1 - FILE_INTEGRITY_FLAG_ENABLE\n"
			"                             0x2 - FILE_INTEGRITY_FLAG_CONTROL\n"
			"                             0x4 - FILE_INTEGRITY_FLAG_FULL_PATH\n"
			"        -p                 - With path"
			"        -e                 - With extern data"
			"        -l <number>		- The limit number of filepath files\n"
			"        -n <number>		- The once number of filepath files\n"
			"        -h 				- Help info\n\n"
			"    eg. ./update_file_integrity -o 1 -F 0x80 -f /usr/bin/gdb -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"    eg. ./update_file_integrity -o 1 -f /usr/bin/gdb -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"    eg. ./update_file_integrity -o 1 -d /usr/bin -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"\n");
}

#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128

static int gui_num_limit = 20000;
static int with_extern_data = 0;
static int with_path = 0;

int generate_file_integrity_item (char *wlFilename, uint8_t flag, struct file_integrity_item_user *item)
{	
	FILE *fp = NULL;
	char *buf = NULL;
  	struct stat fileStat;
  	uint32_t statLen = 0;
	char *wlData = NULL;
	char *path = NULL;
	
	if (NULL == (fp = fopen ((const char*)wlFilename, "rb")))
	{
		perror ("Open message file faliure");
		return -1;
	}
	stat ((const char*)wlFilename, &fileStat);
	statLen = (int)fileStat.st_size;
	if (NULL == (wlData = httc_malloc (statLen))){
		fclose (fp);
		return -1;
	}
	if (statLen != fread (wlData, 1, statLen, fp)){
		perror ("Read data from file failure");
		fclose (fp);
		httc_free (wlData);
		return -1;
	}
	path = wlFilename;

	item->is_control = flag & (1 << FILE_INTEGRITY_FLAG_CONTROL) ? 1 : 0;
	item->is_enable = flag & (1 << FILE_INTEGRITY_FLAG_ENABLE) ? 1 : 0;
	item->is_full_path = flag & (1 << FILE_INTEGRITY_FLAG_FULL_PATH) ? 1 : 0;
	item->hash_length = DEFAULT_HASH_SIZE;
	item->path_length = with_path ? ((flag & (1 << FILE_INTEGRITY_FLAG_FULL_PATH)) ? (strlen (path) + 1) : DEFAULT_HASH_SIZE) : 0;
	item->extend_size = with_extern_data ? 4 : 0;

	if (NULL == (buf = httc_malloc (item->hash_length + item->path_length + item->extend_size))){
		printf ("No mem for item data\n");
		fclose (fp);
		httc_free (wlData);
		return -ENOMEM;
	}

	if (item->hash_length) item->hash = buf;
	if (item->path_length) item->path = buf + item->hash_length;
	if (item->extend_size) item->extend_buffer = buf + item->hash_length + item->path_length;
	sm3 ((uint8_t *)wlData, statLen, (uint8_t *)item->hash);
	if (item->path_length)
		item->is_full_path ? memcpy (item->path, path, item->path_length) : sm3 ((uint8_t *)item->path, item->path_length, (uint8_t *)item->path);
	memset (item->extend_buffer, 'X', item->extend_size);


	fclose (fp);
	httc_free (wlData);
	return 0;
}

void dir_generate_file_integrity_item (char *path, uint32_t *number, uint8_t flag, void *item)
{
	int ret;
	DIR *dir = NULL;
	struct dirent *wlDirent = NULL;
	char subPath[512] = {0};
	char wlFilename[512] = {0};
	
	if (NULL == (dir = opendir (path))) return ;

	while(1)
	{
		if ((int)(*number) >= gui_num_limit) break;
	
		if (NULL == (wlDirent = readdir(dir))) break;
 
		if (strncmp(wlDirent->d_name,".",1)==0) continue;				
		if (wlDirent->d_type == 8) 
		{
			memset (wlFilename, 0, sizeof (wlFilename));
			sprintf(wlFilename,"%s/%s",path,wlDirent->d_name);
			if (access (wlFilename, X_OK) != 0)	continue;
			if (0 != (ret = generate_file_integrity_item (wlFilename, flag, (struct file_integrity_item_user *)item + *number))){
				printf ("generate_file_integrity_item error!\n");
				break;
			}
			(*number) ++;
		}
		else if (wlDirent->d_type == 4){
			sprintf(subPath,"%s/%s",path,wlDirent->d_name);
			dir_generate_file_integrity_item (subPath, number, flag, item);
		}
	}
	closedir (dir);
	return ;
}

int main (int argc, char **argv)
{
	int ret = 0;
	int ch = 0;
	int once = 0;

	uint8_t flag = 0;
	uint64_t replay_counter = 0;
	char *wlFilename = NULL;
	char *path = NULL;
	
	char *keyStr = NULL;
  	int keyStrLen = 0;
	char  privkey[32] = {0};
  	int privkeyLen = 0;
	char  pubkey[64] = {0};
  	int pubkeyLen = 0;

	uint32_t number = 0;
	uint32_t refLength = 0;
	uint8_t *sig = NULL;
	uint32_t sigLen = 0;
	uint32_t action = POLICY_ACTION_SET;

	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	int auth_type = CERT_TYPE_PUBLIC_KEY_SM2;
	const char *uid = NULL;
	struct file_integrity_update *references = NULL;
	struct file_integrity_item_user *item = NULL;
	uint8_t local_data[128] = {1};
	uint32_t local_length = 128;

	int opt = 0;
	int cur_num = 0;

#ifdef __RATE_CHECK__
	struct timeval start;
	struct timeval end;
	uint64_t used_usec = 0;
	float used_sec = 0;
#endif
	
	if (NULL == (item =
			(struct file_integrity_item_user *)httc_calloc (gui_num_limit, sizeof (struct file_integrity_item_user)))){
		perror ("Malloc for reference failure\n");
		return -1;
	}
	httc_util_pr_dev ("httc_calloc item okay!\n");
  	while ((ch = getopt(argc, argv, "k:f:F:o:d:n:l:u:peh")) != -1)
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
				httc_util_str2array ((uint8_t *)privkey, (uint8_t *)keyStr, TPCM_PRIVKEY_STR_LEN);
				privkeyLen = TPCM_PRIVKEY_STR_LEN / 2;
				//httc_util_dump_hex ("privkey", privkey, privkeyLen);
				httc_util_str2array ((uint8_t *)pubkey, (uint8_t *)keyStr + TPCM_PRIVKEY_STR_LEN, TPCM_PUBKEY_STR_LEN);
				pubkeyLen = TPCM_PUBKEY_STR_LEN / 2;
				//httc_util_dump_hex ("pubkey", pubkey, pubkeyLen);
				ret = -1;
				break;
			case 'F':
				flag = strtol (optarg, NULL, 16);
				httc_util_pr_dev ("***flag: 0x%x\n", flag);
				break;
			case 'e':
				with_extern_data = 1;
				break;			
			case 'p':
				with_path = 1;
				break;
			case 'd':
				path = optarg;
				dir_generate_file_integrity_item (path, &number, flag, item);
				httc_util_pr_dev ("dir_generate_file_integrity_item item okay!\n");
				break;
			case 'f':
				wlFilename = optarg;
				if (0 != (ret = generate_file_integrity_item (wlFilename, flag, item))){
					printf ("generate_file_integrity_item error!\n");
					goto out; 
				}
				
				httc_util_pr_dev ("dir_generate_file_integrity_item item okay!\n");
				number++;
				break;
			case 'l':
				gui_num_limit = atoi(optarg);
				httc_util_pr_dev ("gui_num_limit: %d\n", gui_num_limit);
				break;
			case 'n':
				once = atoi(optarg);
				httc_util_pr_dev ("once: %d\n", once);
				break;				
			case 'o':
				action = atoi (optarg);
				break;
			case 'u':
				uid = optarg;
				break;
			case 'h':
			default:
				usage ();
				return -EINVAL;
		}
	}

	if (!once) once = gui_num_limit;
	httc_util_pr_dev ("number: %d, once: %d\n", number, once);

	if (0 != (ret = tcf_get_tpcm_id (tpcm_id, &tpcm_id_length))){
		httc_util_pr_error ("Get tpcm id error: %d(0x%x)\n", ret, ret);
		ret = -1;
		goto out;
	}

	while (opt < number){
		cur_num = once < (number - opt) ? once : (number - opt);
			
		if(httc_get_replay_counter(&replay_counter)){
				httc_util_pr_error("Error httc_get_replay_counter.\n");
				ret = -1;
				goto out;
		}

		replay_counter |= 0x1000000000000000;
		
		httc_util_pr_dev ("tcf_get_tpcm_id item okay!\n");
		if (0 != (ret = tcf_prepare_update_file_integrity (
				item + opt, cur_num, tpcm_id, tpcm_id_length, action, replay_counter, &references, &refLength))){
			httc_util_pr_error ("tcf_prepare_update_file_integrity error: %d(0x%x)\n", ret, ret);
			ret = -1;
			goto out;
		}

		httc_util_pr_dev ("tcf_prepare_update_file_integrity item okay (num = %d)!\n", cur_num);
#ifdef __HASH_DEBUG__
		uint8_t wlHash[DEFAULT_HASH_SIZE] = {0};
		//sm3 (references->data, refLength - sizeof (struct file_integrity_update), wlHash);
		sm3 (references->data, (int)refLength - sizeof (struct file_integrity_update), wlHash);
		httc_util_dump_hex ("wlHash", wlHash, DEFAULT_HASH_SIZE);
#endif

		if (keyStr){
			if (0 != (ret = os_sm2_sign ((const unsigned char *)references, (int)refLength, (unsigned char *)privkey, privkeyLen, (unsigned char *)pubkey, pubkeyLen, &sig, &sigLen))){
				httc_util_pr_error ("Sign for reference failed!\n");
				ret = -1;
				goto out;
			}
			if (0 != (ret = os_sm2_verify ((const unsigned char *)references, (int)refLength, (unsigned char *)pubkey, pubkeyLen, sig, sigLen))){
				printf ("Verify for reference failed!\n");
			}
		}
		memset(local_data,8,128);
		
		//httc_util_pr_dev ("sm2 item okay!\n");
		if (0 != (ret = tcf_update_file_integrity (references, uid, auth_type, sigLen, sig,local_data,local_length))){
			httc_util_pr_error ("tcf_update_file_integrity error: %d(0x%x)\n", ret, ret);
			ret = -1;
			goto out;
		}
		
		httc_util_pr_dev ("tcf_update_file_integrity okay (num = %d)!\n", cur_num);

		httc_free (references); references = NULL;
		SM2_FREE (sig); sig = NULL;
		
		opt += cur_num;
		if (action == POLICY_ACTION_SET)	action = POLICY_ACTION_ADD;
	}

out:
	if (sig) {SM2_FREE (sig); sig = NULL;}
	if (item){
		while (number--) httc_free (item[number].hash);
		httc_free (item);
	}
	
	httc_util_pr_dev ("httc_free item okay!\n");
	if (references) httc_free (references);
	return ret;
}

