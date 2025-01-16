#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>

#include "mem.h"
#include "debug.h"
#include "tutils.h"
#include "convert.h"
#include "tcs_auth.h"
#include "tcs_attest.h"
#include "tcs_constant.h"
#include "tcs_file_integrity.h"
#include "crypto/sm/sm2_if.h"

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
			"        -h 				- Help info\n\n"
			"    eg. ./update_file_integrity -o 0 -F 0x05 -f /usr/bin/gdb -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"    eg. ./update_file_integrity -o 1 -f /usr/bin/gdb -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"    eg. ./update_file_integrity -o 1 -d /usr/bin -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"\n");
}

#define REFERENCE_UPDATE_SIZE  0x1FFF00

#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128

static int gui_num_limit = 20000;
static int with_extern_data = 0;
static int with_path = 0;

int generate_file_integrity_item (uint8_t *wlFilename, uint8_t flag, struct file_integrity_item *item)
{	
	int ret = 0;
	int size = 0;
	FILE *fp = NULL;
  	struct stat fileStat;
  	uint32_t statLen = 0;
	uint8_t *wlData = NULL;
	uint8_t *path = NULL;
	uint16_t path_length = 0;
	
	if (NULL == (fp = fopen (wlFilename, "rb"))){
		perror ("Open message file faliure");
		return 0;
	}
	stat (wlFilename, &fileStat);
	statLen = (int)fileStat.st_size;
	if (NULL == (wlData = httc_malloc (statLen))){
		fclose (fp);
		return 0;
	}
	if (statLen != fread (wlData, 1, statLen, fp)){
		perror ("Read data from file failure");
		fclose (fp);
		httc_free (wlData);
		return 0;
	}
	
	path = wlFilename;
	path_length = with_path ? ((flag & (1 << FILE_INTEGRITY_FLAG_FULL_PATH)) ? (strlen (path) + 1) : DEFAULT_HASH_SIZE) : 0;
	
	item->flags = flag;
	item->extend_size = with_extern_data ? 4 : 0;
	item->be_path_length = htons (path_length);

	sm3 (wlData, statLen, item->data);

	size = sizeof (struct file_integrity_item) + DEFAULT_HASH_SIZE;
	if (item->extend_size){
		memset ((void*)item + size, 'X', item->extend_size);
	}
	size += item->extend_size;

	if (path_length){
		if (flag & (1 << FILE_INTEGRITY_FLAG_FULL_PATH)){
			memcpy ((void*)item + size, path, path_length);	
			size += path_length;
			*((uint8_t*)item + size - 1) = '\0';
		}else{
			sm3 ((const uint8_t *)path, DEFAULT_HASH_SIZE, (void*)item + size);
			size += path_length;
		}	
	}

	size = HTTC_ALIGN_SIZE (size, 4);

	fclose (fp);
	httc_free (wlData);

	return size;
}

void dir_generate_file_integrity_item (uint8_t *path, uint32_t *number, uint8_t flag, void *item, uint32_t *ops, uint32_t maxLen)
{
	uint32_t tpcmRes = 0;
	DIR *dir = NULL;
	int size = 0;
	struct dirent *wlDirent = NULL;
	char subPath[512] = {0};
	FILE *fp = NULL;
  	struct stat fileStat;
  	uint32_t statLen = 0;
	uint8_t wlFilename[512] = {0};
	uint8_t *wlDate = NULL;
	uint8_t wlHash[DEFAULT_HASH_SIZE] = {0};
	
	if (NULL == (dir = opendir (path))) return ;

	while(1)
	{
		if ((int)(*number) >= gui_num_limit) break;
		if (*ops > maxLen)	break;
	
		if (NULL == (wlDirent = readdir(dir))) break;
 
		if (strncmp(wlDirent->d_name,".",1)==0) continue;				
		if (wlDirent->d_type == 8) 
		{
			memset (wlFilename, 0, sizeof (wlFilename));
			sprintf(wlFilename,"%s/%s",path,wlDirent->d_name);
			if (access (wlFilename, X_OK) != 0)	continue;
			if ((size = generate_file_integrity_item (wlFilename, flag, (struct file_integrity_item *)(item + *ops))) <= 0){
				printf ("generate_file_integrity_item error!\n");
				break;
			}
			*ops += size;
			(*number) ++;
		}
		else if (wlDirent->d_type == 4){
			sprintf(subPath,"%s/%s",path,wlDirent->d_name);
			dir_generate_file_integrity_item (subPath, number, flag, item, ops, maxLen);
		}
	}
	closedir (dir);
	return ;
}

int main (int argc, char **argv)
{
	int ret = 0;
	int ch = 0;

	int size = 0;
	uint8_t flag = 0;
	uint64_t replay_counter;
	uint8_t *wlFilename = NULL;
	uint8_t *path = NULL;
	
	uint8_t *keyStr = NULL;
  	uint32_t keyStrLen = 0;
	uint8_t  privkey[32] = {0};
  	uint32_t privkeyLen = 0;
	uint8_t  pubkey[64] = {0};
  	uint32_t pubkeyLen = 0;

	uint32_t number = 0;
	uint32_t refLength = 0;
	uint8_t *sig = NULL;
	uint32_t sigLen = 0;
	uint32_t operation = POLICY_ACTION_SET;
	
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	int auth_type = CERT_TYPE_PUBLIC_KEY_SM2;
	const char *uid = NULL;
	struct file_integrity_update *references = NULL;
	struct file_integrity_item *item = NULL;

#ifdef __RATE_CHECK__
	struct timeval start;
	struct timeval end;
	uint64_t used_usec = 0;
	float used_sec = 0;
#endif
	
	if (NULL == (references = (struct file_integrity_update *)httc_malloc (REFERENCE_UPDATE_SIZE))){
		perror ("Malloc for reference failure\n");
		return -1;
	}
  	while ((ch = getopt(argc, argv, "k:f:F:o:d:l:u:eph")) != -1)
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
			case 'F':
				flag = strtol (optarg, NULL, 16);
				//printf ("***flag: 0x%x\n", flag);
				break;
			case 'e':
				with_extern_data = 1;
				break;	
			case 'p':
				with_path = 1;
				break;	
			case 'd':
				path = optarg;
				dir_generate_file_integrity_item (path, &number, flag, (void*)references->data, &refLength, REFERENCE_UPDATE_SIZE - DEFAULT_SIGNATURE_SIZE);
				//printf ("number: %d, refLength: %d\n", number, refLength);
				break;
			case 'f':
				wlFilename = optarg;
				item = (void*)references->data;
				if ((size = generate_file_integrity_item (wlFilename, flag, item)) <= 0){
					printf ("generate_file_integrity_item error!\n");
					goto out; 
				}
				//httc_util_dump_hex ("item", item, size);
				refLength += size;
				number++;
				break;
			case 'l':
				gui_num_limit = atoi(optarg);
				//printf ("gui_num_limit: %d\n", gui_num_limit);
				break;
			case 'o':
				operation = atoi (optarg);
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

#ifdef __HASH_DEBUG__
	uint8_t wlHash[DEFAULT_HASH_SIZE] = {0};
	//sm3 (references->data, refLength - sizeof (struct file_integrity_update), wlHash);
	
	sm3 (references->data, refLength, wlHash);
	//httc_util_dump_hex ("references->data", references->data, refLength);
	httc_util_dump_hex ("wlHash", wlHash, DEFAULT_HASH_SIZE);
#endif

	
	
	if(httc_get_replay_counter(&replay_counter)){
		printf("Error httc_get_replay_counter.\n");
		ret = -1;
		goto out;
	}
	references->be_size = htonl (sizeof (struct file_integrity_update));
	references->be_action = htonl (operation);
	references->be_replay_counter = htonll (replay_counter);
	references->be_item_number = htonl (number);
	//references->be_data_length = htonl (refLength - sizeof (struct file_integrity_update));
	references->be_data_length = htonl (refLength);

	if (0 != (ret = tcs_get_tpcm_id (references->tpcm_id, &tpcm_id_length))){
		printf ("Get tpcm id error: %d(0x%x)\n", ret, ret);
		goto out;
	}

	if (keyStr){
		ret = os_sm2_sign ((const char *)references, sizeof (struct file_integrity_update) + refLength, privkey, privkeyLen, pubkey, pubkeyLen, &sig, &sigLen);
		if (ret){
			printf ("Sign for reference failed!\n");
			httc_free (references);
			return -1;
		}
		ret = os_sm2_verify ((const char *)references, sizeof (struct file_integrity_update) + refLength, pubkey, pubkeyLen, sig, sigLen);
		if (ret){
			printf ("Verify for reference failed!\n");
		}
	}

//	httc_util_dump_hex ("references", references->data, refLength);


#ifdef __RATE_CHECK__
	gettimeofday (&start, NULL);
	if ((ret = tcs_update_file_integrity (references, uid, auth_type, sigLen, sig))){
		printf ("[tpcm_update_file_integrity] ret: 0x%08x\n", ret);
		ret = -1;
	}
	gettimeofday (&end, NULL);
	used_usec = ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec));
	used_sec = used_usec / (float)1000000;
	printf ("  tpcm_update_file_integrity(%5s:0x%02x)  >>>  |number: %-10d|reflen(KB): %-10.2f|expend: %.02f\n",
											file_integrity_ops[operation], flag, number, (float)refLength/1024, used_sec);
#else
	if ((ret = tcs_update_file_integrity (references, uid, auth_type, sigLen, sig))){
		printf ("[tpcm_update_file_integrity] ret: 0x%08x\n", ret);
		ret = -1;
	}
#endif

out:
	if (sig) SM2_FREE (sig);
	if (references) httc_free (references);
	return ret;
}

