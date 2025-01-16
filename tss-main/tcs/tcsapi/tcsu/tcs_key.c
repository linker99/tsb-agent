#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <ctype.h>

#include "sm3.h"
#include "sm4.h"
#include "tcm.h"
#include "rand.h"
#include "tcmutil.h"
#include "tcmfunc.h"
#include "tcm_error.h"

#include "tcs_key.h"
#include "tcs_store.h"
#include "tcs_error.h"
#include "tcs_attest.h"
#include "tcs_config.h"
#include "tcs.h"

#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "sys.h"
#include "file.h"

#ifndef NO_TSB
#include <tsbapi/tsb_measure_user.h>
#endif

#define NODEAUTH(x) memset(x,0,DEFAULT_HASH_SIZE);\
					sm3(smkpasswd,strlen((const char *)smkpasswd),x);

enum{
	 PCR_TYPE_NO = 0,
	 PCR_TYPE_BIOS, 	   //pcr1
	 PCR_TYPE_BOOTLOADER,  //pcr2
	 PCR_TYPE_KERNAL,	   //pcr3
	 PCR_TYPE_TSB,		   //pcr4
	 PCR_TYPE_BOOT_ALL,    //pcr5
	 PCR_TYPE_DMEASURE,    //pcr6
	 PCR_TYPE_APP_LOAD,    //pcr7
};


#pragma pack(push, 1)

struct save_policy{
	unsigned int policy_flags;
	unsigned int user_or_group;
	uint64_t prlength;
	uint8_t data[0];
};

#pragma pack(pop)

#define USED_PATH 		4
#define SMK_HANDLE		0x40000000
#define KEY_TREE_INDEX 	0x00001000
#define PATH_EXPAND_LENGTH 160  //MAX_KEY_NAME_SIZE + MAX_FILE_NAME_SIZE(32)
#define MAX_USER_OR_GROUP_ID 65535


static uint8_t *smkpasswd= (uint8_t *)"httc@123";
static const char *sharepath=(const char *)HTTC_TSS_CONFIG_PATH"tcmkeytree/";
//static const char *key_version_path=(const char *)HTTC_TSS_CONFIG_PATH"key.version";

//static int attribute = NODE_KEY;
//static int origin = INSIDE_KEY;
//static int migratable = UNMIGRATABLE_KEY;
const static int default_path_key_type = KEY_TYPE_SM4_128;
//static int path_check = 1;

static int tcs_utils_analysis_keypath(unsigned char *key_path,unsigned char **key_name, int *number, unsigned char *cur_key_path){

	
	int n = 0;
	int ret = 0;
	int k,len;
    char str[MAX_KEY_NAME_SIZE];
	int i = USED_PATH;
	int j = USED_PATH;	
	char *home = NULL;
	uint8_t prv_key_path[MAX_KEY_NAME_SIZE];

	if(strncmp((const char *)key_path,"s://",4) != 0 && strncmp((const char *)key_path,"p://",4) != 0){
		httc_util_pr_error(" key_path error %s\n",key_path);
		return TSS_ERR_PARAMETER;
	}
		
	if(*(key_path) == 's'){
		
		/**Check path length**/
		if(strlen((const char *)key_path) > CMD_DEFAULT_ALLOC_SIZE - strlen((const char *)sharepath) - PATH_EXPAND_LENGTH){
			httc_util_pr_error(" key_path too long %s(%ld)\n",key_path, (long int)strlen((const char *)key_path));
			return TSS_ERR_INPUT_EXCEED;
		}
		
		httc_util_system_args("chmod 0755 -R %s 1>/dev/null 2>&1", sharepath);
		
		len = strlen((const char *)sharepath);
		if(cur_key_path) memcpy(cur_key_path, sharepath, len);
		strncpy(str, sharepath, MAX_KEY_NAME_SIZE-1);
		*(cur_key_path + len) = '\0';
		for( k=1; k<len; k++ ){			
			if( str[k]=='/' ){				
				str[k] = '\0';
				if( access(str,0)!=0 )
				{
					ret = mkdir(str, 0755);
					if(ret) {
						perror("mkdir");
						return ret; 
					}
				}
				str[k]='/';
			}
		}
		httc_util_system_args(" chmod -R 755 %s 1>/dev/null 2>&1","/var/httcsec");
	}else if(*(key_path) == 'p'){
		/**Get private path**/
		home = getenv("HOME");
		sprintf((char *)prv_key_path,"%s/%s/tcmkeytree/", home, HTTC_TSS_PRIV_PREFIX);
		len = strlen((const char *)prv_key_path);
		/**Check path length**/
		if(strlen((const char *)key_path) > CMD_DEFAULT_ALLOC_SIZE - len - PATH_EXPAND_LENGTH){
			httc_util_pr_error(" key_path too long %s(%ld)\n",key_path, (long int)strlen((const char *)key_path));
			return TSS_ERR_INPUT_EXCEED;
		}
		if(cur_key_path) memcpy(cur_key_path, prv_key_path, strlen((const char *)prv_key_path));
		strncpy(str, (const char *)prv_key_path, len);
		*(prv_key_path + len) = '\0';
		for( k=1; k<len; k++ ){			
			if( str[k]=='/' ){				
				str[k] = '\0';
				if( access(str,0)!=0 )
				{
					ret = httc_util_create_path((const char *)str);
					if(ret) return ret;
					httc_util_system_args(" chmod -R 700 %s 1>/dev/null 2>&1",prv_key_path);
				}
				str[k]='/';
			}
		}		
	}

	while(*(key_path + i) != '\0'){

		/**Check that the characters are not special symbols and spaces**/
		if((ispunct(*(key_path + i)) && *(key_path + i) != '/') || *(key_path + i) == ' '){
			httc_util_pr_error(" key_path error %s\n",key_path);
			return TSS_ERR_PARAMETER;
		}
		
		if(*(key_path + i) == '/' || *(key_path + i + 1) == '\0'){
			
			/** Get current key name**/			
			if(*(key_path + i + 1) == '\0'){
				
				/**Check name length and '/'**/
				if((i - j + 1) > MAX_KEY_NAME_SIZE || *(key_path + j) =='/'){
					httc_util_pr_error(" key_path error %s\n",key_path);
					*number = n;
					return TSS_ERR_PARAMETER;
				}
				
				if (NULL == (key_name[n] = httc_malloc ((i - j + 2)))){
					httc_util_pr_error (" Req Alloc error!\n");
					*number = n;
					return TSS_ERR_NOMEM;
				}
				memset(key_name[n],0,(i - j + 2));
				strncat((char *)key_name[n], (const char *)key_path + j, (i - j + 1));
			}else{
				
				if(i == j || (i - j) > MAX_KEY_NAME_SIZE){
					httc_util_pr_error(" key_path error %s\n",key_path);
					*number = n;
					return TSS_ERR_PARAMETER;
				}
				
				if (NULL == (key_name[n] = httc_malloc ((i - j) + 1))){
					httc_util_pr_error (" Req Alloc error!\n");
					*number = n;
					return TSS_ERR_NOMEM;
				}
				memset(key_name[n],0,(i - j) + 1);
				strncat((char *)key_name[n], (const char *)key_path + j, (i - j));
			}
			j = i + 1;
			n++;
		}
		i++;
	}
	*number = n;
//	httc_util_pr_error (" number i:%d!\n",n);
	return ret;
}
static int tcs_utils_upate_pcrinfo_tcmlocked(uint32_t policy_flags, unsigned char *seal_pcrinfo, uint32_t *pcrInfoSize){

		
	int i = 0;
	int ret = 0;
	int pcr_number = 0;
	uint32_t status = 0;
		
	TCM_PCR_INFO pcrInfo;
    TCM_PCR_COMPOSITE pcrComp;
    STACK_TCM_BUFFER(serPcrInfo);	

	memset(&pcrInfo, 0x0, sizeof(pcrInfo));
    memset(&pcrComp, 0x0, sizeof(pcrComp));

	TCM_setlog(0);

	httc_util_pr_dev ("policy_flags: 0x%x\n", policy_flags);
		
	/**pcr flag  0x6F80 **/
	if(policy_flags & POLICY_PCR){
		ret = tcs_get_trust_status(&status);
		if(ret){
			httc_util_pr_error ("tcs_get_trust_status error!\n");
			return ret;
		}

		if(status){
			httc_util_pr_error ("Environment untrusted (%d)!\n",status);
			return TSS_ERR_UNTRUSTED;
		}
	}
	if(policy_flags & POLICY_FLAG_TRUST_STATE){
		policy_flags |= (POLICY_FLAG_TRUST_DMEASURE
				  |POLICY_FLAG_TRUST_APP_LOAD
				  |POLICY_FLAG_TRUST_BOOT);
	}
	/*
     * Now builthe pcrInfo
     */
    pcrInfo.tag = TCM_TAG_PCR_INFO;
    pcrInfo.localityAtRelease = TCM_LOC_ZERO;
    pcrInfo.localityAtCreation = TCM_LOC_ZERO;
    pcrInfo.PcrAtRelease.sizeOfSelect = 4;
    pcrInfo.PcrAtCreation.sizeOfSelect = 4;	
	if(policy_flags & POLICY_FLAG_TRUST_BIOS_OR_FIRMWARE){
		pcrInfo.PcrAtRelease.pcrSelect[PCR_TYPE_BIOS >> 3] |= (1 << (PCR_TYPE_BIOS & 0x7));
		pcr_number++;
	}
	if(policy_flags & POLICY_FLAG_TRUST_BOOTLOADER){
		pcrInfo.PcrAtRelease.pcrSelect[PCR_TYPE_BOOTLOADER >> 3] |= (1 << (PCR_TYPE_BOOTLOADER & 0x7));
		pcr_number++;
	}
	if(policy_flags & POLICY_FLAG_TRUST_KERNEL){
		pcrInfo.PcrAtRelease.pcrSelect[PCR_TYPE_KERNAL >> 3] |= (1 << (PCR_TYPE_KERNAL & 0x7));
		pcr_number++;
	}
	if(policy_flags & POLICY_FLAG_TRUST_BOOT){
		pcrInfo.PcrAtRelease.pcrSelect[PCR_TYPE_BOOT_ALL >> 3] |= (1 << (PCR_TYPE_BOOT_ALL & 0x7));
		pcr_number++;
	}
	if(policy_flags & POLICY_FLAG_TRUST_DMEASURE){
		pcrInfo.PcrAtRelease.pcrSelect[PCR_TYPE_DMEASURE >> 3] |= (1 << (PCR_TYPE_DMEASURE & 0x7));
		pcr_number++;
	}
	/*
	if(policy_flags & POLICY_FLAG_TRUST_INIT_ROOT){
		pcrInfo.PcrAtRelease.pcrSelect[PCR_TYPE_INIT_ROOT >> 3] |= (1 << (PCR_TYPE_INIT_ROOT & 0x7));
		pcr_number++;
	}
	if(policy_flags & POLICY_FLAG_TRUST_BOOT_CONFIG){
		pcrInfo.PcrAtRelease.pcrSelect[PCR_TYPE_BOOT_CONFIG >> 3] |= (1 << (PCR_TYPE_BOOT_CONFIG & 0x7));
		pcr_number++;
	}
	*/
	if(policy_flags & POLICY_FLAG_TRUST_APP_LOAD){
		pcrInfo.PcrAtRelease.pcrSelect[PCR_TYPE_APP_LOAD >> 3] |= (1 << (PCR_TYPE_APP_LOAD & 0x7));
		pcr_number++;
	}

    /*
     * Upate the PCR Compoite structure.
     */
    pcrComp.select.sizeOfSelect = 4;
    pcrComp.pcrValue.size = pcr_number * TCM_HASH_SIZE;
	pcrComp.pcrValue.buffer  = httc_malloc(pcrComp.pcrValue.size);
	if(pcrComp.pcrValue.buffer == NULL){
		httc_util_pr_error (" Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	/*
     * Get pcr hash.
     */	
     
     if(pcr_number){
		if(policy_flags & POLICY_FLAG_TRUST_BIOS_OR_FIRMWARE){
			pcrComp.select.pcrSelect[PCR_TYPE_BIOS >> 3] |= (1 << (PCR_TYPE_BIOS & 0x7));
			ret = TCM_PcrRead(PCR_TYPE_BIOS,(unsigned char *)pcrComp.pcrValue.buffer + i*TCM_HASH_SIZE);
			if(ret){
				httc_util_pr_error (" TCM_PcrRead error 0x%08X!\n",ret);
				if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
				return ret;
			}
			i++;
		}
		if(policy_flags & POLICY_FLAG_TRUST_BOOTLOADER){
			pcrComp.select.pcrSelect[PCR_TYPE_BOOTLOADER >> 3] |= (1 << (PCR_TYPE_BOOTLOADER & 0x7));
			ret = TCM_PcrRead(PCR_TYPE_BOOTLOADER,(unsigned char *)pcrComp.pcrValue.buffer + i*TCM_HASH_SIZE);
			if(ret){
				httc_util_pr_error (" TCM_PcrRead error 0x%08X!\n",ret);
				if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
				return ret;
			}
			i++;
		}
		if(policy_flags & POLICY_FLAG_TRUST_KERNEL){
			pcrComp.select.pcrSelect[PCR_TYPE_KERNAL >> 3] |= (1 << (PCR_TYPE_KERNAL & 0x7));
			ret = TCM_PcrRead(PCR_TYPE_KERNAL,(unsigned char *)pcrComp.pcrValue.buffer + i*TCM_HASH_SIZE);
			if(ret){
				httc_util_pr_error (" TCM_PcrRead error 0x%08X!\n",ret);
				if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
				return ret;
			}
			i++;
		}
		if(policy_flags & POLICY_FLAG_TRUST_BOOT){
			pcrComp.select.pcrSelect[PCR_TYPE_BOOT_ALL >> 3] |= (1 << (PCR_TYPE_BOOT_ALL & 0x7));
			ret = TCM_PcrRead(PCR_TYPE_BOOT_ALL,(unsigned char *)pcrComp.pcrValue.buffer + i*TCM_HASH_SIZE);
			if(ret){
				httc_util_pr_error (" TCM_PcrRead error 0x%08X!\n",ret);
				if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
				return ret;
			}
			i++;
		}
		if(policy_flags & POLICY_FLAG_TRUST_DMEASURE){
			pcrComp.select.pcrSelect[PCR_TYPE_DMEASURE >> 3] |= (1 << (PCR_TYPE_DMEASURE & 0x7));
			ret = TCM_PcrRead(PCR_TYPE_DMEASURE,(unsigned char *)pcrComp.pcrValue.buffer + i*TCM_HASH_SIZE);
			if(ret){
				httc_util_pr_error (" TCM_PcrRead error 0x%08X!\n",ret);
				if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
				return ret;
			}
			i++;
		}
		if(policy_flags & POLICY_FLAG_TRUST_APP_LOAD){
			pcrComp.select.pcrSelect[PCR_TYPE_APP_LOAD >> 3] |= (1 << (PCR_TYPE_APP_LOAD & 0x7));
			ret = TCM_PcrRead(PCR_TYPE_APP_LOAD,(unsigned char *)pcrComp.pcrValue.buffer + i*TCM_HASH_SIZE);
			if(ret){
				httc_util_pr_error (" TCM_PcrRead error 0x%08X!\n",ret);
				if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
				return ret;
			}
			i++;
		}
		/*
		if(policy_flags & POLICY_FLAG_TRUST_INIT_ROOT){
			pcrComp.select.pcrSelect[PCR_TYPE_INIT_ROOT >> 3] |= (1 << (PCR_TYPE_INIT_ROOT & 0x7));
			ret = TCM_PcrRead(PCR_TYPE_INIT_ROOT,(unsigned char *)pcrComp.pcrValue.buffer + i*TCM_HASH_SIZE);
			if(ret){
				httc_util_pr_error (" TCM_PcrRead error 0x%08X!\n",ret);
				if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
				return ret;
			}
			i++;
		}
		if(policy_flags & POLICY_FLAG_TRUST_BOOT_CONFIG){
			pcrComp.select.pcrSelect[PCR_TYPE_BOOT_CONFIG >> 3] |= (1 << (PCR_TYPE_BOOT_CONFIG & 0x7));
			ret = TCM_PcrRead(PCR_TYPE_BOOT_CONFIG,(unsigned char *)pcrComp.pcrValue.buffer + i*TCM_HASH_SIZE);
			if(ret){
				httc_util_pr_error (" TCM_PcrRead error 0x%08X!\n",ret);
				if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
				return ret;
			}
			i++;
		}
		*/
		
		TCM_HashPCRComposite(&pcrComp, pcrInfo.digestAtRelease);

		for (i = 0; i < sizeof(pcrInfo.PcrAtRelease.pcrSelect); i++)
			httc_util_pr_dev ("pcrInfo.PcrAtRelease.pcrSelect[%d]: 0x%x\n", i, pcrInfo.PcrAtRelease.pcrSelect[i]);
		for (i = 0; i < sizeof(pcrComp.select.pcrSelect); i++)
			httc_util_pr_dev ("pcrComp.select.pcrSelect[%d]: 0x%x\n", i, pcrComp.select.pcrSelect[i]);
    }	
	
	ret = TCM_WritePCRInfo(&serPcrInfo, &pcrInfo);
    if ((*pcrInfoSize & ERR_MASK) || ret > *pcrInfoSize) {
       httc_util_pr_error("Error while serializing TPM_PCR_INFO_LONG.\n");
	   if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
       return ret;
    }
	if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);

	*pcrInfoSize = ret;
	memcpy(seal_pcrinfo,serPcrInfo.buffer,serPcrInfo.used);
	return TSS_SUCCESS;

}

static uint16_t tcs_utils_get_keyuse(int key_type, uint16_t keyusage){

		if(key_type == KEY_TYPE_SM2_128){
				switch(keyusage)
				{
					case ENCRYPT_KEY:
						return TCM_SM2KEY_BIND;
					case SEAL_KEY:
						return TCM_SM2KEY_STORAGE;
					case STORE_KEY:
						return TCM_SM2KEY_STORAGE;
					case SIGN_KEY:
						return TCM_SM2KEY_SIGNING;
					case MIGRATE_KEY:
						return TCM_SM2KEY_MIGRATION;
					default:
						return -1;
				}
		}else{
				switch (keyusage)
				{
					case ENCRYPT_KEY:
						return TCM_SM4KEY_BIND;
					case SEAL_KEY:
						return TCM_SM4KEY_STORAGE;
					case STORE_KEY:
						return TCM_SM4KEY_STORAGE;
					case MIGRATE_KEY:
						return TCM_SM4KEY_MIGRATION;
					default:
						return -1;
				}

		}
		
		return -1;
}
static int tcs_utils_loadkey_tcmlocked( uint8_t *cur_key_path, uint8_t *cur_key_name, uint16_t keyusage, uint32_t inkeyhandle,
		uint32_t *outkeyhandle, unsigned char *auth,int *pmigratable){

	int ret = 0;	
	uint32_t pkeyhandle = 0;
	uint8_t pkeyauth[DEFAULT_HASH_SIZE] = {0};	
	uint8_t *filename = NULL;
	unsigned char  	keyblob[512] = {0};
    unsigned int   	bloblen = 0;
	struct key_info cur_key_info;
	struct stat keystat;
	
	FILE *key_file;
	FILE *key_info;
	keydata key;
	STACK_TCM_BUFFER( buffer );
	//if(pmigratable)*pmigratable = UNMIGRATABLE_KEY;
	
	TCM_setlog(0);
	
	if(inkeyhandle == 0){
		pkeyhandle = SMK_HANDLE;
		NODEAUTH(pkeyauth);	
	}else{
		pkeyhandle = inkeyhandle;
		memcpy(pkeyauth,auth,DEFAULT_HASH_SIZE);
	}

	if(NULL == (filename = httc_malloc(CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		return TSS_ERR_NOMEM;
	}
	memset(filename,0,CMD_DEFAULT_ALLOC_SIZE);

	/**Check if the key exit**/
	sprintf((char *)filename, "%s%s.info", cur_key_path, cur_key_name);
	key_info = fopen((char *)filename,"r");
	if (key_info == NULL){
		httc_util_pr_error(" The key not exit %s\n", filename);
		httc_free(filename);
		return TSS_ERR_FILE;
	}
	
	/**The key exit**/	
	ret = fread((unsigned char *)&cur_key_info, 1, sizeof(struct key_info), key_info);			
    if (ret != (int)sizeof(struct key_info)) {
       httc_util_pr_error(" I/O Error while reading key info '%s'\n", filename);
		fclose(key_info);
		httc_free(filename);
        return TSS_ERR_READ;
    }
	
	/**Check for migratability**/
	if(cur_key_info.migratable == MIGRATABLE_KEY) *pmigratable = MIGRATABLE_KEY;
	
	/**Check if it is a leaf key**/
	if( tcs_utils_get_keyuse(cur_key_info.key_type,cur_key_info.key_use) != keyusage 
		&& cur_key_info.attribute == LEAF_KEY
		&& cur_key_info.key_use != SEAL_KEY){
		httc_util_pr_error("  The key already exit but not match! key:%s actkey_use:%d except:%d\n", filename,
							tcs_utils_get_keyuse(cur_key_info.key_type,cur_key_info.key_use),keyusage);
		fclose(key_info);
		httc_free(filename);
		return TSS_ERR_PARAMETER;
	}
	
	fclose(key_info);
	
	/** Loakey **/
	memset(filename,0,CMD_DEFAULT_ALLOC_SIZE);	
	sprintf((char *)filename, "%s%s.key", cur_key_path, cur_key_name);
	key_file = fopen((char *)filename,"r");
	if (key_file == NULL){
		httc_util_pr_error("Unable to open key file %s\n", filename);
		httc_free(filename);
		return TSS_ERR_FILE;
	}
	
	stat((char *)filename, &keystat);
    bloblen = (int)keystat.st_size;	
    ret = fread(keyblob, 1, bloblen, key_file);
    if (ret != (int)bloblen){
       httc_util_pr_error("Unable to read key file ret:%d, bloblen:%d\n",ret, bloblen);
		fclose(key_file);
		httc_free(filename);
        return TSS_ERR_READ;		    
     }
	fclose(key_file);
	
	SET_TCM_BUFFER(&buffer, keyblob, bloblen);
    TSS_KeyExtract(&buffer, 0, &key);
	
	if (0 != (ret = TCM_LoadKey(pkeyhandle, pkeyauth, &key, outkeyhandle))){
		httc_util_pr_error("TCM_LoadKey(%s) return error '%s' (%d).\n", filename,TCM_GetErrMsg(ret), ret);
		httc_free(filename);
		return ret;
	}
	httc_free(filename);
	return ret;
} 

static int tcs_utils_createkey_tcmlocked(int key_type, uint16_t keyusage, unsigned char *nkeyauth, uint32_t inkeyhandle,
						uint32_t *outkeyhandle, uint8_t *cur_key_path, uint8_t *cur_key_name, uint32_t policy_flags,
						int attribute,int origin,int *pmigratable){

	
	uint32_t ret = 0;
	keydata ikey;
	keydata okey;
	FILE *key_file;
	FILE *key_info;
	FILE *pub_key;
	uint16_t key_use = 0;
	uint32_t pcrInfoSize = 256;
	uint8_t *filename = NULL;	
	uint32_t pkeyhandle = 0;
	uint8_t pkeyauth[DEFAULT_HASH_SIZE] = {0};
	uint8_t okeyblob[512] = {0};
	uint32_t okeybloblen = sizeof (okeyblob);
	struct key_info cur_key_info;

	TCM_setlog(0);
	
	if(inkeyhandle == 0){
		pkeyhandle = SMK_HANDLE;		
	}else{
		pkeyhandle = inkeyhandle;;
	}
	NODEAUTH(pkeyauth);	
//	printf("migratable:%d,key_type:%d keyusage:%d\n",migratable,key_type,keyusage);
	key_use = tcs_utils_get_keyuse(key_type,keyusage);
	if(key_use == -1){
		httc_util_pr_error("get keyuse fail");
		return TSS_ERR_PARAMETER;
	}

	if(NULL == (filename = httc_malloc(CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		return TSS_ERR_NOMEM;
	}
	memset(filename,0,CMD_DEFAULT_ALLOC_SIZE);
	
	/**Check if the key exit**/
	sprintf((char *)filename, "%s%s.info", cur_key_path, cur_key_name);
	key_info = fopen((char *)filename,"r");
	if (key_info == NULL) goto createkey;
	
	/**The key exit**/
	ret = fread((unsigned char *)&cur_key_info, 1, sizeof(struct key_info), key_info);			
    if (ret != (int)sizeof(struct key_info)) {
       httc_util_pr_error("I/O Error while reaing key info '%s'\n", filename);
		fclose(key_info);
		httc_free(filename);
        return TSS_ERR_READ;
    }

	/**Check whether it is a leaf**/	
	if(tcs_utils_get_keyuse(cur_key_info.key_type,cur_key_info.key_use) == key_use
		&& cur_key_info.attribute == LEAF_KEY)
	{
		httc_util_pr_error("The key already exit! key:%s keyusage:%d\n", filename, cur_key_info.key_use);
		fclose(key_info);
		httc_free(filename);
		return TSS_ERR_RECREATE;
	}		
	fclose(key_info);
	httc_free(filename);

	/**Load exited key**/
	ret = tcs_utils_loadkey_tcmlocked(cur_key_path, cur_key_name, key_use, inkeyhandle, outkeyhandle, nkeyauth,pmigratable);
	return ret;
	

createkey:
	
	memset(&ikey, 0x0, sizeof(ikey));
	memset(&okey, 0x0, sizeof(okey));

	ret = tcs_utils_upate_pcrinfo_tcmlocked(policy_flags, ikey.pub.pcrInfo.buffer, &pcrInfoSize);
	if(ret){
		httc_util_pr_error(" TCM_CreatePCRInfo fail.\n");
		if(filename) httc_free(filename);
		return ret;
	}	
    ikey.pub.pcrInfo.size = pcrInfoSize;
	
	ikey.hdr.key12.tag = TCM_TAG_KEY;
	ikey.hdr.key12.fill = 0;
	ikey.keyUsage = key_use;
	ikey.keyFlags= 0;
	ikey.authDataUsage = TCM_AUTH_ALWAYS;
	ikey.encData.size = 0;
	ikey.pub.pubKey.keyLength = 0;
	if(*pmigratable == MIGRATABLE_KEY) ikey.keyFlags |= TCM_KEY_FLG_MIGRATABLE;
	
	if (ikey.keyUsage == TCM_SM2KEY_SIGNING){
		ikey.pub.algorithmParms.encScheme = TCM_ES_SM2NONE;
		ikey.pub.algorithmParms.sigScheme = TCM_SS_SM2;
		ikey.pub.algorithmParms.algorithmID = TCM_ALG_SM2;
		//ikey.keyFlags &= ~TCM_KEY_FLG_MIGRATABLE;
		ikey.pub.algorithmParms.parmSize = 4;
		ikey.pub.algorithmParms.sm2para.keyLength = 256;
	}
	else if (ikey.keyUsage == TCM_SM2KEY_STORAGE){
		ikey.pub.algorithmParms.encScheme = TCM_ES_SM2;
		ikey.pub.algorithmParms.sigScheme = TCM_SS_SM2NONE;
		ikey.pub.algorithmParms.algorithmID = TCM_ALG_SM2;
		ikey.pub.algorithmParms.parmSize = 4;
		ikey.pub.algorithmParms.sm2para.keyLength = 256;
	}else if (ikey.keyUsage == TCM_SM4KEY_STORAGE) {
		ikey.pub.algorithmParms.encScheme = TCM_ES_SM4_CBC;
		ikey.pub.algorithmParms.sigScheme = TCM_SS_SM2NONE;
		ikey.pub.algorithmParms.algorithmID = TCM_ALG_SM4;
		ikey.pub.algorithmParms.parmSize = 28;
		ikey.pub.algorithmParms.sm4para.keyLength = 128;
		ikey.pub.algorithmParms.sm4para.blockSize = 128;
		ikey.pub.algorithmParms.sm4para.ivSize = 16;
		httc_util_rand_bytes (ikey.pub.algorithmParms.sm4para.IV, ikey.pub.algorithmParms.sm4para.ivSize);

	}else if (ikey.keyUsage == TCM_SM2KEY_BIND){
		ikey.pub.algorithmParms.encScheme = TCM_ES_SM2;
		ikey.pub.algorithmParms.sigScheme = TCM_SS_SM2NONE;
		ikey.pub.algorithmParms.algorithmID = TCM_ALG_SM2;
		ikey.pub.algorithmParms.parmSize = 4;
		ikey.pub.algorithmParms.sm2para.keyLength = 256;
	}
	else if (ikey.keyUsage == TCM_SM4KEY_BIND){
		ikey.pub.algorithmParms.encScheme = TCM_ES_SM4_CBC;
		ikey.pub.algorithmParms.sigScheme = TCM_SS_SM2NONE;
		ikey.pub.algorithmParms.algorithmID = TCM_ALG_SM4;
		ikey.pub.algorithmParms.parmSize = 28;
		ikey.pub.algorithmParms.sm4para.keyLength = 128;
		ikey.pub.algorithmParms.sm4para.blockSize = 128;
		ikey.pub.algorithmParms.sm4para.ivSize = 16;
		httc_util_rand_bytes(ikey.pub.algorithmParms.sm4para.IV, ikey.pub.algorithmParms.sm4para.ivSize);
	}else if (ikey.keyUsage == TCM_SM2KEY_MIGRATION){
		ikey.pub.algorithmParms.encScheme = TCM_ES_SM2;
		ikey.pub.algorithmParms.sigScheme = TCM_SS_SM2NONE;
		ikey.pub.algorithmParms.algorithmID = TCM_ALG_SM2;
//		ikey.keyFlags &= ~TCM_KEY_FLG_MIGRATABLE;		
		ikey.pub.algorithmParms.parmSize = 4;
		ikey.pub.algorithmParms.sm2para.keyLength = 256;		
	}else if (ikey.keyUsage == TCM_SM4KEY_MIGRATION){
		ikey.pub.algorithmParms.encScheme = TCM_ES_SM4_CBC;
		ikey.pub.algorithmParms.sigScheme = TCM_SS_SM2NONE;
		ikey.pub.algorithmParms.algorithmID = TCM_ALG_SM4;
		ikey.keyFlags &= ~TCM_KEY_FLG_MIGRATABLE;
		ikey.pub.algorithmParms.parmSize = 28;
		ikey.pub.algorithmParms.sm4para.keyLength = 128;
		ikey.pub.algorithmParms.sm4para.blockSize = 128;
		ikey.pub.algorithmParms.sm4para.ivSize = 16;
		httc_util_rand_bytes(ikey.pub.algorithmParms.sm4para.IV, ikey.pub.algorithmParms.sm4para.ivSize);	
	}
	
//	httc_util_dump_hex((const char *) "tcskey", &ikey, sizeof(ikey));
	if (0 != (ret = TCM_CreateWrapKey (pkeyhandle, pkeyauth,
					nkeyauth, NULL, &ikey, &okey, okeyblob, &okeybloblen))){
			httc_util_pr_error("TCM_CreateWrapKey return error '%s' (%d) path:%s, key:%s\n", TCM_GetErrMsg(ret), ret,cur_key_path,cur_key_name);
			if(filename) httc_free(filename);
			return ret;
	}

	/** Create key three **/
	if(access((const char *)cur_key_path, 0) != 0){
		if(mkdir((const char *)cur_key_path,0777) == -1){
			perror("mkdir error");
			httc_util_pr_error("Dir %s!\n", cur_key_path);
			if(filename) httc_free(filename);
			return TSS_ERR_FILE;
		}
	}
	
	/** Save pubkey **/
	memset(filename,0,CMD_DEFAULT_ALLOC_SIZE);
	sprintf((char *)filename, "%s%s.pub", cur_key_path, cur_key_name);	
    pub_key = fopen((char *)filename, "w");
    if (pub_key == NULL) {
       httc_util_pr_error("Unable to create key file %s!\n", filename);
	   if(filename) httc_free(filename);
       return TSS_ERR_FILE;
    }
//	tpcm_utils_ump_hex((unsigned char *) filename, okey.pub.pubKey.modulus, okey.pub.pubKey.keyLength);
    ret = fwrite(okey.pub.pubKey.modulus, 1, okey.pub.pubKey.keyLength, pub_key);
    if (ret != okey.pub.pubKey.keyLength) {
       httc_util_pr_error("Error writing pubkey ret:%d,length:%d\n",ret, okey.pub.pubKey.keyLength);
		fclose(pub_key);
		if(filename) httc_free(filename);
       	return TSS_ERR_WRITE;
    }
    fclose(pub_key);

	/**Save keyblob**/
//	httc_util_dump_hex((const char *) "tcskey", okeyblob, okeybloblen);	
	memset(filename,0,CMD_DEFAULT_ALLOC_SIZE);	
	sprintf((char *)filename, "%s%s.key", cur_key_path, cur_key_name);	
    key_file = fopen((char *)filename, "wb");
    if (key_file == NULL) {
       httc_util_pr_error(" Unable to create key file %s!\n", filename);
	   if(filename) httc_free(filename);
       return TSS_ERR_FILE;
    }
    ret = fwrite(okeyblob, 1, okeybloblen, key_file);
    if (ret != okeybloblen) {
       httc_util_pr_error(" I/O Error writing key file ret:%d ,length:%d\n",ret, okeybloblen);
		fclose(key_file);
		if(filename) httc_free(filename);
       	return TSS_ERR_WRITE;
    }
    fclose(key_file);

	/**Save key info**/
	
	cur_key_info.key_type = key_type;
	cur_key_info.key_use = keyusage;
	cur_key_info.origin = origin;
	cur_key_info.key_size = okeybloblen;
	cur_key_info.migratable = *pmigratable;
	cur_key_info.attribute = attribute;
	
	memset(filename,0,CMD_DEFAULT_ALLOC_SIZE);
	sprintf((char *)filename, "%s%s.info", cur_key_path, cur_key_name);	
    key_info = fopen((char *)filename, "w");	
    if (key_info == NULL) {
       httc_util_pr_error(" Unable to create key file %s.\n", filename);
	   if(filename) httc_free(filename);
       return TSS_ERR_FILE;
    }
	
    ret = fwrite((char *)&cur_key_info, 1, sizeof(struct key_info), key_info);
    if (ret != sizeof(struct key_info)) {
       httc_util_pr_error(" I/O Error writing keyinfo file\n");
		fclose(key_info);
		if(filename) httc_free(filename);
       	return TSS_ERR_WRITE;
    }
	fclose(key_info);

	if(filename) httc_free(filename);
	
	/**Get handle**/
	if (0 != (ret = TCM_LoadKey(pkeyhandle, pkeyauth, &okey, outkeyhandle))){
		httc_util_pr_error("TCM_LoadKey return error '%s' (%d).\n", TCM_GetErrMsg(ret), ret);
		return ret;
	}
	return TSS_SUCCESS;
}

static int tcs_utils_tree_key_create_tcmlocked(int key_type, uint16_t keyusage, unsigned char *auth,
						unsigned char **key_name, int number, unsigned char *cur_key_path,uint32_t *handle,
						uint32_t policy_flags,int origin,int migratable){

	int ret = 0;
	int i = 0;
	uint32_t inkeyhandle = 0;
	uint32_t outkeyhandle = 0;
	uint8_t keyauth[DEFAULT_HASH_SIZE] = {0};
	//int migratable = UNMIGRATABLE_KEY;
	NODEAUTH(keyauth);
	
	if(number == 0) return TSS_ERR_PARAMETER;
	
	for(; i < number;i++){
		strncat((char *)cur_key_path,(const char *)key_name[i], strlen((const char *)key_name[i]));
		strncat((char *)cur_key_path, "//", 1);
		if(i != number - 1){
			//attribute = NODE_KEY;
			ret = tcs_utils_createkey_tcmlocked(default_path_key_type, STORE_KEY,
					keyauth, inkeyhandle, &outkeyhandle, cur_key_path,
					(uint8_t *)key_name[i], 0,NODE_KEY,origin,&migratable);
			if(ret) goto out;
			inkeyhandle = outkeyhandle;
		}else if(i == number - 1){
			int attribute = NODE_KEY;
			if(keyusage != STORE_KEY)attribute = LEAF_KEY;
			ret = tcs_utils_createkey_tcmlocked(key_type, keyusage, auth, inkeyhandle, &outkeyhandle,
					cur_key_path, (uint8_t *)key_name[i] ,policy_flags,attribute,origin,&migratable);
			if(ret) goto out;
		}
	}
out:
	if(handle != NULL) *handle = outkeyhandle;
	return ret;
}

static int tcs_utils_tree_key_achieve_tcmlocked(uint16_t keyusage, unsigned char **key_name, int number, unsigned char *cur_key_path,uint32_t *handle){

	int ret = 0;
	int i = 0;
	int pmigratable = 0;
	uint32_t inkeyhandle = 0;
	uint32_t outkeyhandle = 0;
	uint8_t keyauth[DEFAULT_HASH_SIZE] = {0};
	NODEAUTH(keyauth);

	if(number == 0) return TSS_ERR_PARAMETER;
	
	for(; i < number;i++){		
		strncat((char *)cur_key_path,(const char *)key_name[i],strlen((const char *)key_name[i]));
		strncat((char *)cur_key_path,"//",1);
		if(i != number - 1){
			ret = tcs_utils_loadkey_tcmlocked(cur_key_path,(uint8_t *)key_name[i],TCM_SM4KEY_STORAGE,inkeyhandle,&outkeyhandle, keyauth,&pmigratable);
			if(ret) goto out;
			inkeyhandle = outkeyhandle;
		}else if(i == number - 1){
			ret = tcs_utils_loadkey_tcmlocked(cur_key_path,(uint8_t *)key_name[i],keyusage,inkeyhandle,&outkeyhandle, keyauth,&pmigratable);
			if(ret) goto out;
		}
	}	
out:
	if(handle) *handle = outkeyhandle;
	return ret;
}

#ifndef NO_TSB
static int tcs_utils_policy_passwd(struct auth_policy *policy,unsigned char *auth){
	
	int ret = 0;
	sm3_context ctx;

	/**Check whether the policy meets the specification**/
	if((policy->policy_flags & POLICY_FLAG_USER_ID && policy->policy_flags & POLICY_FLAG_GROUP_ID) ||

	  (policy->policy_flags & POLICY_FLAG_PROCESS_IDENTITY && policy->policy_flags & POLICY_FLAG_PROCESS_ROLE) ||
	  ((policy->policy_flags & POLICY_FLAG_USER_ID || policy->policy_flags & POLICY_FLAG_GROUP_ID) && policy->user_or_group > MAX_USER_OR_GROUP_ID) || 
	  ((policy->policy_flags & POLICY_FLAG_PROCESS_IDENTITY || policy->policy_flags& POLICY_FLAG_PROCESS_ROLE) && strlen((const char *)policy->process_or_role) > MAX_NAME_LENGTH)){
		httc_util_pr_error("Error policy.\n");
		return TSS_ERR_PARAMETER;
	  }
	
	sm3_init (&ctx);
	sm3_update (&ctx, (const unsigned char *)&(policy->policy_flags), sizeof(unsigned int));
	if(policy->policy_flags & POLICY_FLAG_USER_ID || policy->policy_flags & POLICY_FLAG_GROUP_ID)
		sm3_update (&ctx, (const unsigned char *)&(policy->user_or_group), sizeof (unsigned int));
	if(policy->policy_flags & POLICY_FLAG_PROCESS_IDENTITY || policy->policy_flags& POLICY_FLAG_PROCESS_ROLE){
		sm3_update (&ctx, (const unsigned char *)policy->process_or_role , strlen((const char *)policy->process_or_role) + 1);
	}
	if(policy->policy_flags & POLICY_FLAG_USED_PASSWD)
		sm3_update (&ctx, (const unsigned char *)policy->password, strlen((const char *)policy->password) + 1);	
	sm3_finish (&ctx, auth);
	
	return ret;	
}

static int tcs_utils_save_policy(unsigned char *keypath,unsigned char *key_name, struct auth_policy *policy){

	int ret = 0;
	int length = 0;
	char *policy_file_name = NULL;
	struct save_policy *save_policy = NULL;	
	
	if(policy->process_or_role) length = strlen((const char *)policy->process_or_role) + 1;	
	if(NULL == (save_policy = (struct save_policy *)httc_malloc(length + sizeof(struct save_policy)))){
		httc_util_pr_error(" Malloc error\n");
		return TSS_ERR_NOMEM;

	}
	memset(save_policy, 0 , length + sizeof(struct save_policy));
	save_policy->policy_flags = policy->policy_flags;
	save_policy->user_or_group = policy->user_or_group;
	save_policy->prlength = length;
	
	if(policy->process_or_role) memcpy(save_policy->data,policy->process_or_role,length - 1);
	length += sizeof(struct save_policy);
	
	if(NULL == (policy_file_name = httc_malloc(CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}
	
	memset(policy_file_name,0,CMD_DEFAULT_ALLOC_SIZE);
	sprintf(policy_file_name,"%s%s.policy",keypath,key_name);
	
	ret = httc_util_file_write((const char *)policy_file_name, (const char *)save_policy, length);	
	if(ret != length){
		httc_util_pr_error(" Policy write error ret:%d length:%d\n",ret,length);
		ret = TSS_ERR_WRITE;
	}
	ret = TSS_SUCCESS;
out:
	if(policy_file_name) httc_free(policy_file_name);
	if(save_policy) httc_free(save_policy);
	return ret;
}
#endif

static int tcs_utils_get_policy_passwd(unsigned char *keypath,unsigned char *key_name,
														unsigned char *passwd,unsigned char *auth){
	
	int ret = 0;
	uint8_t *buf = NULL;
	char *policy_file_name = NULL;

	struct save_policy *policy = NULL;
	uint64_t policy_length = 0;

	uint8_t process_or_role[MAX_PROCESS_NAME_LENGTH] = {0};
	int process_length = MAX_PROCESS_NAME_LENGTH;
	uid_t uid = -1;
	gid_t gid = -1;

	sm3_context ctx;
	sm3_init (&ctx);

	if(NULL == (buf = httc_malloc(CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}
	memset(buf,0,CMD_DEFAULT_ALLOC_SIZE);
	
	policy_file_name = (char *)buf;

	sprintf(policy_file_name,"%s%s.policy",keypath,key_name);

	/** Read policy data**/
	policy = httc_util_file_read_full((const char *)policy_file_name, (unsigned long *)&policy_length);
	if(policy){
		sm3_update (&ctx, (const unsigned char *)&(policy->policy_flags), sizeof(unsigned int));
#ifndef NO_TSB
		if (policy->policy_flags & POLICY_FLAG_ENV){
			if (0 != (ret = tsb_measure_kernel_memory_all ())){
				httc_util_pr_error ("tsb_measure_kernel_memory_all error: %d(0x%x)\n", ret, ret);
				ret =  TSS_ERR_ADMIN_AUTH;
				goto out;
			}
		}

		if(policy->policy_flags & POLICY_FLAG_USER_ID ){
#ifndef TSS_DEBUG
			uid = getuid();
			sm3_update (&ctx, (const unsigned char *)&(uid), sizeof (uid_t));
#else
			sm3_update (&ctx, (const unsigned char *)&(policy->user_or_group), sizeof (unsigned int));
#endif
		}
		else if( policy->policy_flags & POLICY_FLAG_GROUP_ID){
#ifndef TSS_DEBUG
			gid = getgid();
			sm3_update (&ctx, (const unsigned char *)&(gid), sizeof (gid_t));
#else
			sm3_update (&ctx, (const unsigned char *)&(policy->user_or_group), sizeof (unsigned int));
#endif
		}

#ifndef TSS_DEBUG
		if(policy->policy_flags & POLICY_FLAG_PROCESS_IDENTITY){
			ret = tsb_get_process_identity(process_or_role,&process_length);
			if(ret){
				httc_util_pr_error("Error tsb_get_process_identity %d",ret);
				ret =  TSS_ERR_ADMIN_AUTH;
				goto out;
			}			
			sm3_update (&ctx, (const unsigned char *)process_or_role, process_length);
		}
		if(policy->policy_flags & POLICY_FLAG_PROCESS_ROLE){
			
			if( !tsb_is_role_member((const unsigned char *)policy->data)){
				httc_util_pr_error("Error tsb_is_role_member %s",policy->data);
				ret =  TSS_ERR_ADMIN_AUTH;
				goto out;
			}		
			sm3_update (&ctx, (const unsigned char *)policy->data, policy->prlength);
		}
#else		
		if(policy->policy_flags & POLICY_FLAG_PROCESS_IDENTITY || policy->policy_flags & POLICY_FLAG_PROCESS_ROLE){
            sm3_update (&ctx, (const unsigned char *)policy->data , policy->prlength);
		}
#endif
#endif
		if(policy->policy_flags & POLICY_FLAG_USED_PASSWD){
			if(!passwd){
				httc_util_pr_error("Passwd is null.\n");
				ret = TSS_ERR_PARAMETER;
				goto out;
			}
			sm3_update (&ctx, (const unsigned char *)passwd, strlen((const char *)passwd) + 1);	
		}
		sm3_finish (&ctx, auth);
	}else

	{
		if(!passwd){
			httc_util_pr_error("Passwd is null.\n");
			ret = TSS_ERR_PARAMETER;
			goto out;
		}
		sm3(passwd,strlen((const char *)passwd),auth);
	}	
	
out:
	if(policy) httc_free(policy);
	if(buf) httc_free(buf);	
	return ret;	
}

static int tcs_utils_get_encryptkey_tcmlocked(unsigned char *key_path,unsigned char *passwd,	uint8_t *encyrptkey,
												uint32_t *encyrptkeylength, uint32_t *encryptkeyhandle, uint8_t *auth){

	int ret = 0;
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;	
	uint8_t *encyrptkeysealname = NULL;
	uint8_t *encyrptkeydata = NULL;
	uint64_t encyrptkeylen = 0;
	uint32_t Encryptkeyhandle = 0;
	uint8_t *inbuffer = NULL;
	uint32_t inbuflen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *outbuffer = NULL;
	uint32_t outbuflen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t keyauth[DEFAULT_HASH_SIZE] = {0};
	
	/** Get Save encyrptkeyhandle **/
	if(NULL == (buf = httc_malloc(3*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}
	
	cur_key_path = buf; 										//CMD_DEFAULT_ALLOC_SIZE
	encyrptkeysealname = buf + CMD_DEFAULT_ALLOC_SIZE; 			//CMD_DEFAULT_ALLOC_SIZE
	inbuffer = encyrptkeysealname + CMD_DEFAULT_ALLOC_SIZE;
	outbuffer =  inbuffer + CMD_DEFAULT_ALLOC_SIZE/2;

	if(NULL == (key_name = (unsigned char **)httc_malloc(CMD_DEFAULT_ALLOC_SIZE/4))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}
	
	memset(buf,0,3*CMD_DEFAULT_ALLOC_SIZE);
	memset(key_name,0,CMD_DEFAULT_ALLOC_SIZE/4);
	
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))) goto out;
	
	/** Get encyrptkey file **/	
	sprintf((char *)encyrptkeysealname, "%s%s/%s.encrypt", cur_key_path,key_path + USED_PATH, key_name[number - 1]);
	if(access((const char *)encyrptkeysealname,0)!=0){
	/** Get inner encyrptkey **/
   		 if(0 != ( ret = tcs_utils_tree_key_achieve_tcmlocked(TCM_SM4KEY_BIND, key_name, number, (unsigned char *)cur_key_path, encryptkeyhandle))) goto out;
		 if(0 != (ret = tcs_utils_get_policy_passwd(cur_key_path, key_name[number - 1], passwd, keyauth))) goto out;
		 if(auth) memcpy(auth,keyauth,DEFAULT_HASH_SIZE);
   		 goto out;

	}else{
		encyrptkeydata = httc_util_file_read_full((const char *)encyrptkeysealname, (unsigned long *)&encyrptkeylen);
		if(encyrptkeydata == NULL){
			httc_util_pr_error("read encyrptkey file fail %s!\n",encyrptkeysealname);		
			ret =  TSS_ERR_READ;
			goto out;
		}	
		memcpy(inbuffer, encyrptkeydata, encyrptkeylen);	
		inbuflen = encyrptkeylen;
		if(0 != (ret = tcs_utils_tree_key_achieve_tcmlocked(TCM_SM4KEY_BIND, key_name, number,(unsigned char *) cur_key_path,&Encryptkeyhandle))) goto out;
		if(0 != (ret = tcs_utils_get_policy_passwd(cur_key_path, key_name[number - 1], passwd, keyauth))) goto out;

		TCM_setlog(0);
		ret = TSS_SM4Decrypt(Encryptkeyhandle, keyauth, inbuffer, inbuflen, outbuffer, (uint32_t *)&outbuflen);
		if (ret) {
	       httc_util_pr_error(" Error from TSS_SM4Decrypt %s(%d)\n", TCM_GetErrMsg(ret),ret);
			goto out;
	    }
			
		if(encyrptkey != NULL) memcpy(encyrptkey,outbuffer,outbuflen);
		*encyrptkeylength = outbuflen;
	}

out:
	if(encyrptkeydata) httc_free(encyrptkeydata);
	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(key_name) httc_free(key_name);
	if(buf) httc_free(buf);	
	return ret;

}
static int tcs_utils_get_node_number(char *path,int *number){

	int n = 0;
	DIR *dir = NULL;
	struct dirent *Dirent = NULL;
	
	if(NULL == (dir = opendir(path))){
		perror("opendir");
		httc_util_pr_error(" Path wrong %s.\n", path);
		return TSS_ERR_PARAMETER;
	}

	while(1){
		if(NULL == (Dirent = readdir(dir))) break;
		if (strncmp(Dirent->d_name,".",1)==0) continue;
		if(Dirent->d_type == 4) n++;
	}

	*number = n;
	closedir(dir);
	return TSS_SUCCESS;
}

static int tcs_utils_read_dir(char *path,struct key_node *node, unsigned int *level){

	int i = 0;
	int n = 0;
	int ret = TSS_SUCCESS;
	DIR *dir = NULL;
	struct dirent *Dirent = NULL;
	FILE *fp = NULL;
	struct save_policy *spolicy = NULL;
	uint64_t policy_length = 0;
	struct stat fileStat;
	uint8_t *buf = NULL;
	char *dirpath = NULL;
	char *filename = NULL;
	char *encryptfilename = NULL;
	char *encryptfilenamefull = NULL;
	unsigned int actlevel = 0;

	if(strlen((const char *)path) > CMD_DEFAULT_ALLOC_SIZE - PATH_EXPAND_LENGTH){
		httc_util_pr_error(" Path too long %s\n",path);
		return TSS_ERR_INPUT_EXCEED;
	}
	
	if (NULL == (dir = opendir(path))) {
		perror("opendir");
		httc_util_pr_error("wrong path %s.\n", path);
		return TSS_ERR_PARAMETER;
	}	

	if(NULL == (buf = httc_malloc(4*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		closedir(dir);
		return TSS_ERR_NOMEM;
	}

	dirpath = (char *)buf;
	filename = dirpath + CMD_DEFAULT_ALLOC_SIZE;
	encryptfilename = filename + CMD_DEFAULT_ALLOC_SIZE;
	encryptfilenamefull = encryptfilename + CMD_DEFAULT_ALLOC_SIZE;
	
	while(1)
	{			
		if(NULL == (Dirent = readdir(dir))) break;
		if (strncmp(Dirent->d_name,".",1)==0) continue;
		if (Dirent->d_type == 8)		 
		{				
			if (strncmp(Dirent->d_name + (strlen(Dirent->d_name) - 4),"info",4)==0)
			{		
					memset (filename, 0, CMD_DEFAULT_ALLOC_SIZE);
					sprintf(filename,"%s/%s",path,Dirent->d_name);
					memset (encryptfilenamefull, 0, CMD_DEFAULT_ALLOC_SIZE);
					memcpy(encryptfilename,filename,strlen((const char *)filename) - 4);
					sprintf(encryptfilenamefull,"%sencrypt",encryptfilename);					
					if (NULL == (fp = fopen (filename, "rb"))){
						httc_util_pr_error(" Open file faliure %s.\n", filename);
						continue;						
					}
					
					stat (filename, &fileStat);
					if((int)fileStat.st_size != sizeof(struct key_info)){
						httc_util_pr_error(" Wrong file %s.\n", filename);
						fclose (fp);
						continue;
					}

					if (fileStat.st_size != fread(&node->key, 1, fileStat.st_size, fp)){						
						httc_util_pr_error(" Read keyinfo from file failed %s.\n", filename);
						fclose (fp);
						continue;
					}

					if(access((const char *)encryptfilenamefull,0)==0){
						node->key.key_use = ENCRYPT_KEY;
						node->key.key_size = (node->key.key_type == KEY_TYPE_SM2_128 ? SM2_PRIVATE_KEY_SIZE + SM2_PUBLIC_KEY_SIZE : SM4_KEY_SIZE);
					}
									
					fclose(fp);		 		
		 	}

			if (strncmp(Dirent->d_name + (strlen(Dirent->d_name) - 4),"seal",4)==0)				
			{		
//					printf("seal\n");
					memset (filename, 0, CMD_DEFAULT_ALLOC_SIZE);
					sprintf(filename,"%s/%s",path,Dirent->d_name);
//					printf("seal:%s\n",filename);
					stat (filename, &fileStat);
					node->seal_data.size = (int)fileStat.st_size;		 		
		 	}
			
			if (strncmp(Dirent->d_name + (strlen(Dirent->d_name) - 6),"policy",6)==0)				
			{		

					memset (filename, 0, CMD_DEFAULT_ALLOC_SIZE);
					sprintf(filename,"%s/%s",path,Dirent->d_name);
					spolicy = httc_util_file_read_full((const char *)filename, (unsigned long *)&policy_length);
					if(spolicy == NULL){
						httc_util_pr_error(" Read key policy from file failed %s.\n", filename);
						continue;
					}
					
					node->policy.policy_flags = spolicy->policy_flags;
					node->policy.user_or_group = spolicy->user_or_group;
					node->policy.process_or_role = NULL;
					node->policy.password = NULL;
					if(spolicy->prlength){						
						if(NULL == (node->policy.process_or_role = httc_malloc(spolicy->prlength + 1))){
							httc_util_pr_error("Malloc error for policy process %s.\n", filename);
							if(spolicy) httc_free(spolicy);
							continue;
						}
						memset(node->policy.process_or_role, 0, spolicy->prlength + 1);
						memcpy(node->policy.process_or_role,spolicy->data,spolicy->prlength);
					}
					if(spolicy) httc_free(spolicy);
		 	}
		}

		else if (Dirent->d_type == 4)
		{	
			if(!(*level)) continue;
			actlevel = *level;
			memset(dirpath,0,CMD_DEFAULT_ALLOC_SIZE);
			sprintf(dirpath,"%s/%s",path,Dirent->d_name);
			ret = tcs_utils_get_node_number(dirpath,&i);
			if(ret) goto out;
			actlevel -= 1;
			
			if(strlen(Dirent->d_name) > MAX_KEY_NAME_SIZE){
				httc_util_pr_error (" Name too long %ld %s!\n",(long int)strlen(Dirent->d_name), Dirent->d_name);
				closedir(dir);
				if(buf) httc_free(buf);
				return TSS_ERR_OUTPUT_EXCEED;
			}
			
			if (NULL == (node->children[n] = (struct key_node *)httc_malloc (sizeof(struct key_node) + (i+1)*8*(sizeof(char*))))){
				httc_util_pr_error (" Req Alloc error!\n");
				closedir(dir);
				if(buf) httc_free(buf);
				return TSS_ERR_NOMEM;
			}
			
			memset(node->children[n],0,sizeof(struct key_node) + (i+1)*8*(sizeof(char*)));
			memcpy(node->children[n]->name,Dirent->d_name,strlen(Dirent->d_name));
//			httc_util_pr_error("name\n",node->children[n]->name);
			node->children[n]->children_number = i;
			tcs_utils_read_dir(dirpath, node->children[n], &actlevel);
			n++;
		}
	}
out:
	if(buf) httc_free(buf);
	closedir(dir);
	return ret;
}


static int tcs_utils_delete_keytree(const char *keypath){

	int ret = 0;
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	
	if(keypath == NULL) return TSS_ERR_PARAMETER;
	
	if(NULL == (buf = httc_malloc(2*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}
	memset(buf,0,2*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	key_name = (unsigned char **)(buf + CMD_DEFAULT_ALLOC_SIZE);

	if(0 != (ret = tcs_utils_analysis_keypath((unsigned char *)keypath, key_name, &number,(unsigned char *) cur_key_path))) goto out;
	strncat((char *)cur_key_path,(const char *)keypath + USED_PATH,strlen((const char *)keypath) - USED_PATH);
	
	if(number){
		if(httc_util_rm((char *)cur_key_path)) ret = TSS_ERR_SHELL;
	}else{
		if(httc_util_rm((char *)cur_key_path)) ret = TSS_ERR_SHELL;
	}
	
out:
	while (number--) if(key_name[number]) httc_free(key_name[number]);	
	if(buf) httc_free(buf);
	return ret;
}

static int tcs_utils_export_keytree_dirlocked(const char *keypath,unsigned char **pbuffer,int *obuf_len){
	int ret = 0;
	int i = 0;
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	unsigned char *pwd= NULL;
	unsigned char *keytreebuf = NULL;
	uint64_t length = 0;
	uint64_t path_length = 0;
	char path_name[512] = {0};

	if(keypath == NULL || obuf_len == NULL || pbuffer == NULL) return TSS_ERR_PARAMETER;
	
	if(NULL == (buf = httc_malloc(2*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}
	memset(buf,0,2*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	key_name = (unsigned char **)(buf + CMD_DEFAULT_ALLOC_SIZE);
	pwd= buf + CMD_DEFAULT_ALLOC_SIZE + CMD_DEFAULT_ALLOC_SIZE/2;
	
	if(0 != (ret = tcs_utils_analysis_keypath((unsigned char *)keypath, key_name, &number,(unsigned char *) cur_key_path))) goto out;
	if(number > 0){
		for(; i < number - 1;i++){
			strncat((char *)cur_key_path,(const char *)key_name[i],strlen((const char *)key_name[i]));
			strncat((char *)cur_key_path,"//",1);		
		}
	}
	memset(pwd,0,CMD_DEFAULT_ALLOC_SIZE/2);  			
 	if(getcwd((char *)pwd,CMD_DEFAULT_ALLOC_SIZE/2) == NULL){
		ret = TSS_ERR_SHELL;
		goto out;
	}
//	printf("path:%s\n",cur_key_path);
 	ret = chdir((const char *)cur_key_path);
	if(ret){
		httc_util_pr_error("path error %s\n",cur_key_path);
		ret = TSS_ERR_SHELL;
		goto out;
	}
	if(number > 0){
		if(httc_util_system_args("tar -zcf keytree.tar.gz %s",key_name[number - 1])){
			
			httc_util_pr_error("tar error.\n");
			ret = TSS_ERR_SHELL;
			goto out;
		}
	}else{
		if(httc_util_system((const char *)"tar -zcf keytree.tar.gz *")){			
			httc_util_pr_error("tar error.\n");
			ret = TSS_ERR_SHELL;
			goto out;
		}
	}
	
	keytreebuf = httc_util_file_read_full((const char *)"keytree.tar.gz", (unsigned long *)&length);
	if(!keytreebuf){
		httc_util_pr_error("Read keytree error.\n");
		ret = snprintf(path_name, sizeof(path_name), "%s%s", cur_key_path, "keytree.tar.gz");
		if(ret != (strlen((const char *)cur_key_path) + strlen("keytree.tar.gz"))){
			httc_util_pr_error("snprintf %s error.\n", path_name);
			ret = TSS_ERR_BAD_DATA;
			goto out;
		} 

		ret = httc_util_rm(path_name);
		if(ret != 0){
			httc_util_pr_error(" httc_util_rm %s error.\n", path_name);
			ret = TSS_ERR_FILE;
			goto out;
		} 
		ret = TSS_ERR_READ;
		goto out;
	}
	
	if(number > 0) strncat((char *)cur_key_path,(const char *)key_name[number - 1],strlen((const char *)key_name[number - 1]));
	path_length = strlen((const char *)cur_key_path);
	if(NULL == (*pbuffer = httc_malloc(path_length + length + sizeof(uint64_t)))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}

	memset(*pbuffer,0,path_length + length + sizeof(uint64_t));
	memcpy(*pbuffer, &path_length, sizeof(uint64_t));
	memcpy(*pbuffer + sizeof(uint64_t),cur_key_path,path_length);
	memcpy(*pbuffer + sizeof(uint64_t) + path_length, keytreebuf, length);
	
	*obuf_len = path_length + length + sizeof(uint64_t);
	
	ret = snprintf(path_name, sizeof(path_name), "%s%s", cur_key_path, "keytree.tar.gz");
	if(ret != (strlen((const char *)cur_key_path) + strlen("keytree.tar.gz"))){
		httc_util_pr_error("snprintf %s error.\n", path_name);
		ret = TSS_ERR_BAD_DATA;
		goto out;
	} 

	ret = httc_util_rm(path_name);
	if(ret != 0){
		httc_util_pr_error(" httc_util_rm %s error.\n", path_name);
		ret = TSS_ERR_FILE;
		goto out;
	} 
	
	ret = TSS_SUCCESS;
out:
	do{if(chdir((const char *)pwd))break;}while(0);
	while (number--) if(key_name[number]) httc_free(key_name[number]);	
	if(buf) httc_free(buf);
	if(keytreebuf) httc_free(keytreebuf);
	return ret; 
}

static int tcs_utils_import_keytree_dirlocked(const char *keypath,unsigned char *pbuffer,int buf_len,int path_check){

	int op = 0;
	int ret = 0;
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	unsigned char *pwd= NULL;
	unsigned char *key_file = NULL;
	unsigned char *tree_path = NULL;
	uint64_t path_length = 0;
	char path_name[512] = {0};
	
	if(keypath == NULL || pbuffer == NULL) return TSS_ERR_PARAMETER;
	
	if(NULL == (buf = httc_malloc(3*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}
	memset(buf,0,3*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	tree_path = buf + CMD_DEFAULT_ALLOC_SIZE;
	key_name = (unsigned char **)(tree_path + CMD_DEFAULT_ALLOC_SIZE);
	pwd= buf + CMD_DEFAULT_ALLOC_SIZE + CMD_DEFAULT_ALLOC_SIZE/2;
	key_file = pwd + CMD_DEFAULT_ALLOC_SIZE/4;

	if(0 != (ret = tcs_utils_analysis_keypath((unsigned char *)keypath, key_name, &number,(unsigned char *) cur_key_path))) goto out;
	if(number > 0){
		if(number > 1){
			if(0 != (ret = tcs_utils_tree_key_achieve_tcmlocked(STORE_KEY, key_name, number - 1, cur_key_path, NULL))) goto out;
		}
		strncat((char *)cur_key_path,(const char *)key_name[number - 1],strlen((const char *)key_name[number - 1]));
		strncat((char *)cur_key_path,"//",1);
	}
	
	memcpy(&path_length,pbuffer,sizeof(uint64_t));
	op += sizeof(uint64_t);
	if(path_length >= buf_len){
		ret = TSS_ERR_PARAMETER;
		goto out;
	}
	memcpy(tree_path,pbuffer + op,path_length);
	op += path_length;

	if(memcmp(tree_path, cur_key_path, path_length) != 0 && path_check){
		httc_util_pr_error("Path error export:%s import:%s\n",tree_path,cur_key_path);
		ret  = TSS_ERR_PARAMETER;
		goto out;
	}
	
	if(number > 0){
		*(cur_key_path + (strlen((const char *)cur_key_path) - strlen((const char *)key_name[number - 1]) - 1)) = '\0';
	}

	memset(pwd,0,CMD_DEFAULT_ALLOC_SIZE/4);  			
 	if(getcwd((char *)pwd,CMD_DEFAULT_ALLOC_SIZE/4) == NULL){
		ret = TSS_ERR_SHELL;
		goto out;
	}
	
	if(access((const char *)cur_key_path, 0) != 0){
		if(memcmp(keypath,"s://",4) == 0){
			if(mkdir((const char *)cur_key_path,0777) == -1){
				httc_util_pr_error("mkdir error");
				httc_util_pr_error("Dir %s!\n", cur_key_path);
				ret =  TSS_ERR_FILE;
				goto out;
			}
		}else{
			if(mkdir((const char *)cur_key_path,0700) == -1){
				httc_util_pr_error("mkdir error");
				httc_util_pr_error("Dir %s!\n", cur_key_path);
				ret =  TSS_ERR_FILE;
				goto out;
			}
		}
		goto out;
	}

 	ret = chdir((const char *)cur_key_path);
	if(ret){
		httc_util_pr_error("path error %s\n",cur_key_path);
		ret = TSS_ERR_SHELL;
		goto out;
	}

	memset(key_file,0,CMD_DEFAULT_ALLOC_SIZE/4);
	sprintf((char *)key_file,"%s/%s.key",key_name[number - 1],key_name[number - 1]);
	if(access((const char *)key_file, 0) == 0){
		httc_util_pr_error("path error %s\n",cur_key_path);
		ret = TSS_ERR_PARAMETER;
		goto out;
	}
		
	ret = httc_util_file_write((const char *) "keytree.tar.gz", (const char *)pbuffer + op, buf_len - op);
	if(ret != (buf_len - op)){				
		httc_util_pr_error(" Write Keytree file fail %s .\n", "keytree.tar.gz");
		ret = TSS_ERR_WRITE;
		goto out;
	}
	
	if(httc_util_system((const char *)"tar -zxf keytree.tar.gz")){
		httc_util_pr_error(" Tar error.\n");
		ret = snprintf(path_name, sizeof(path_name), "%s%s", cur_key_path, "keytree.tar.gz");
		if(ret != (strlen((const char *)cur_key_path) + strlen("keytree.tar.gz"))){
			httc_util_pr_error("snprintf %s error.\n", path_name);
			ret = TSS_ERR_BAD_DATA;
			goto out;
		} 
		
		ret = httc_util_rm(path_name);
		if(ret != 0){
			httc_util_pr_error(" httc_util_rm %s error.\n", path_name);
			ret = TSS_ERR_FILE;
			goto out;
		} 
		ret = TSS_ERR_SHELL;
		goto out;
	}

	ret = snprintf(path_name, sizeof(path_name), "%s%s", cur_key_path, "keytree.tar.gz");
	if(ret != (strlen((const char *)cur_key_path) + strlen("keytree.tar.gz"))){
		httc_util_pr_error("snprintf %s error.\n", path_name);
		ret = TSS_ERR_BAD_DATA;
		goto out;
	} 
	
	ret = httc_util_rm(path_name);
	if(ret != 0){
		httc_util_pr_error(" httc_util_rm %s error.\n", path_name);
		ret = TSS_ERR_FILE;
		goto out;
	} 
	
	ret = TSS_SUCCESS;
out:
	//path_check = 1;
	do{if(chdir((const char *)pwd))break;}while(0);
	while (number--)if(key_name[number]) httc_free(key_name[number]);	
	if(buf) httc_free(buf);
	return ret; 
}


int tcs_create_sign_key(unsigned char *key_path, int type, unsigned char *passwd){
	
	int ret = 0;
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	uint8_t keyauth[DEFAULT_HASH_SIZE] = {0};

	if(key_path == NULL || passwd == NULL || type != KEY_TYPE_SM2_128) return TSS_ERR_PARAMETER;	

	if(NULL == (buf = httc_malloc(2*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,2*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	key_name = (unsigned char **)(buf + CMD_DEFAULT_ALLOC_SIZE);
	
	sm3(passwd,strlen((const char *)passwd),keyauth);
	if(0 != (ret =tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))){
		goto out_release;
	}
	if(0 != (ret = TCM_Open())) {
		goto out_release;
	}
	ret = tcs_utils_tree_key_create_tcmlocked(type, SIGN_KEY, keyauth, key_name,number, cur_key_path, NULL, 0,INSIDE_KEY,UNMIGRATABLE_KEY);
	TCM_Close();
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);	
	if(buf) httc_free(buf);
	return ret;	
}

#ifdef NO_TSB
int tcs_create_sign_key_on_policy(		unsigned char *key_path, int type,	struct auth_policy *policy){
	key_path = key_path;
	type = type;
	policy = policy;
	return TSS_ERR_NOT_SUPPORT;
}
#else
int tcs_create_sign_key_on_policy(		unsigned char *key_path, int type,	struct auth_policy *policy){

	int ret = 0;
	int err = 0;
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	uint8_t keyauth[DEFAULT_HASH_SIZE] = {0};
	
	if(key_path == NULL || policy == NULL || type != KEY_TYPE_SM2_128) return TSS_ERR_PARAMETER;

	if(NULL == (buf = httc_malloc(2*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,2*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	key_name = (unsigned char **)(buf + CMD_DEFAULT_ALLOC_SIZE);

	if(0 != (ret =tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))){
	//	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
		goto out_release;
	}
	if(0 != (ret = tcs_utils_policy_passwd(policy, keyauth))){
	//	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
		goto out_release;
	}
	if(0 != (ret = TCM_Open())){
		//tcs_util_sem_release (TCS_SEM_INDEX_KEY);
		goto out_release;
	}
	
	if(0 != (ret = tcs_utils_tree_key_create_tcmlocked(type, SIGN_KEY, keyauth, key_name,number, cur_key_path, NULL, policy->policy_flags,INSIDE_KEY,UNMIGRATABLE_KEY))){
		//();
		//tcs_util_sem_release (TCS_SEM_INDEX_KEY);
		goto out_close;
	}
	
	if(0 != (ret = tcs_utils_save_policy(cur_key_path, key_name[number -1], policy))){
		err = tcs_utils_delete_keytree((const char *)key_path);
		if(err){
			httc_util_pr_error("Recovery error 0x%04X",err);
		}
		//TCM_Close();
		//tcs_util_sem_release (TCS_SEM_INDEX_KEY);
		//goto out;
	}
out_close:
	TCM_Close();
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);	
	if(buf) httc_free(buf);
	return ret;
}
#endif

int tcs_sign(unsigned char *key_path,unsigned char *passwd,unsigned char *ibuffer, int ilength,unsigned char *obuffer,int *oleng_inout){

	int ret = 0;
	int number = 0;
	uint32_t signkeyhandle = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	uint8_t signauth[DEFAULT_HASH_SIZE] = {0};

	if(key_path == NULL || ibuffer == NULL ) return TSS_ERR_PARAMETER;

	TCM_setlog(0);
	if(NULL == (buf = httc_malloc(2*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,2*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	key_name = (unsigned char **)(buf + CMD_DEFAULT_ALLOC_SIZE);

	if(0 != (ret =tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))){
		//tcs_util_sem_release (TCS_SEM_INDEX_KEY);
		goto out_release;
	}
	if(0 != (ret = TCM_Open())) {
		//tcs_util_sem_release (TCS_SEM_INDEX_KEY);
		goto out_release;
	}
    if(0 != (ret = tcs_utils_tree_key_achieve_tcmlocked(TCM_SM2KEY_SIGNING, key_name, number, cur_key_path, &signkeyhandle))){
		//TCM_Close();
		//tcs_util_sem_release (TCS_SEM_INDEX_KEY);
		goto out_close;
	}
	if(0 != (ret = tcs_utils_get_policy_passwd(cur_key_path, key_name[number -1], passwd, signauth))){
		//TCM_Close();
		//tcs_util_sem_release (TCS_SEM_INDEX_KEY);
		goto out_close;
	}
	//tcs_util_sem_release (TCS_SEM_INDEX_KEY);
	
	ret = TCM_Sign(signkeyhandle, signauth, ibuffer, ilength, obuffer, (uint32_t *)oleng_inout);
    if (ret != 0) {
       httc_util_pr_error(" Error from TCM_Sign %s\n", TCM_GetErrMsg(ret));
    }
out_close:
	TCM_Close();	
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(buf) httc_free(buf);
	return ret;
}


int tcs_create_encrypt_key(unsigned char *key_path,int type,unsigned char *passwd){

	int ret = 0;
	int err = 0;
	uint8_t *outbuffer = NULL;
	uint32_t outlen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t  *encrypt_key = NULL;
	uint32_t encrypt_key_len = 2048;
	unsigned char *encrypt_key_filename = NULL;
	unsigned char keyauth[DEFAULT_HASH_SIZE] = {0};
	
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	uint32_t encryptkeyhandle = 0;
	
	if(key_path == NULL || passwd == NULL || type != KEY_TYPE_SM4_128) return TSS_ERR_PARAMETER;		
	sm3 (passwd, strlen ((const char *)passwd), keyauth);	

	if(NULL == (buf = httc_malloc(3*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}

	if(NULL == (key_name = (unsigned char **)httc_malloc(CMD_DEFAULT_ALLOC_SIZE/4))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	
	memset(buf,0,3*CMD_DEFAULT_ALLOC_SIZE);
	memset(key_name,0,CMD_DEFAULT_ALLOC_SIZE/4);
	
	cur_key_path = buf; 													// CMD_DEFAULT_ALLOC_SIZE
	encrypt_key_filename = buf + CMD_DEFAULT_ALLOC_SIZE; 					// CMD_DEFAULT_ALLOC_SIZE
	encrypt_key = encrypt_key_filename + CMD_DEFAULT_ALLOC_SIZE/2;			// CMD_DEFAULT_ALLOC_SIZE/2
	outbuffer = encrypt_key + CMD_DEFAULT_ALLOC_SIZE/2;						// CMD_DEFAULT_ALLOC_SIZE/2
	
	TCM_setlog(0);
	if(0 != (ret =tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = TCM_Open())) goto out_relase;
	/**Create ymmestric encryption key number**/		
	memset(encrypt_key,0,encrypt_key_len);
	ret = TCM_GetRandom(SM4_KEY_SIZE*2, encrypt_key, &encrypt_key_len);
	if(ret || encrypt_key_len != SM4_KEY_SIZE*2){
		httc_util_pr_error(" Create encryption key fail\n");
		goto out_close;
	}	


	/**Create encryption key protect key**/	
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))) {
		goto out_close;
	}
	//origin = OUTSIDE_KEY;
	if(0 != (ret = tcs_utils_tree_key_create_tcmlocked(KEY_TYPE_SM4_128, ENCRYPT_KEY, keyauth, key_name,number, cur_key_path, &encryptkeyhandle, 0,OUTSIDE_KEY,UNMIGRATABLE_KEY))){
		goto out_close;
	}
	//origin = INSIDE_KEY;
	sprintf((char *)encrypt_key_filename , "%s%s.encrypt", cur_key_path,key_name[number -1]);
	
	ret = TSS_SM4Encrypt(encryptkeyhandle, keyauth, encrypt_key, encrypt_key_len, outbuffer, (uint32_t *)&outlen);
	if (ret != 0) {
		httc_util_pr_error(" Error from TSS_SM4Encrypt (%s) %d\n", TCM_GetErrMsg(ret),ret);
		err = tcs_utils_delete_keytree((const char *)key_path);  
		if(err){
			httc_util_pr_error("Recovery error 0x%04X",err);
		}
		goto out_close;
    }
    ret = httc_util_file_write((const char *)encrypt_key_filename,(const char *)outbuffer,outlen);
	if (ret != outlen) {
        httc_util_pr_error("Error writing encrypt_key file\n");
       	ret = TSS_ERR_WRITE;
		err = tcs_utils_delete_keytree((const char *)key_path);
		if(err){
			httc_util_pr_error("Recovery error 0x%04X",err);
		}
		goto out_close;
    }	
	ret = TSS_SUCCESS;	
out_close:
	TCM_Close();
out_relase:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	//origin = INSIDE_KEY;
	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(key_name) httc_free(key_name);
	if(buf) httc_free(buf);
	return ret;

}

int tcs_create_inner_encrypt_key(unsigned char *key_path, int type, unsigned char *passwd){
	
	int ret = 0;
	int number = 0;
	uint32_t outkeyhandle = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	unsigned char keyauth[DEFAULT_HASH_SIZE] = {0};	
	
	if(key_path == NULL || passwd == NULL || type != KEY_TYPE_SM4_128) return TSS_ERR_PARAMETER;
	sm3 (passwd, strlen ((const char *)passwd), keyauth);
	TCM_setlog(0);

	if(NULL == (buf = httc_malloc(CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}

	if(NULL == (key_name = (unsigned char **)httc_malloc(CMD_DEFAULT_ALLOC_SIZE/4))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,CMD_DEFAULT_ALLOC_SIZE);
	memset(key_name,0,CMD_DEFAULT_ALLOC_SIZE/4);
	
	cur_key_path = buf; 										// ALLOC_SIZE
	
	/**Create encryption key**/
	if(0 != (ret =tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))){
		goto out_release;
	}
	if(0 != (ret = TCM_Open())) goto out_release;
	ret = tcs_utils_tree_key_create_tcmlocked(type, ENCRYPT_KEY, keyauth, key_name,number, cur_key_path, &outkeyhandle, 0,INSIDE_KEY,UNMIGRATABLE_KEY);
	TCM_Close();
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(key_name) httc_free(key_name);
	if(buf) httc_free(buf);
	return ret;
}

#ifdef NO_TSB
int tcs_create_encrypt_key_on_policy(unsigned char *key_path, int type, struct auth_policy *policy){
	key_path = key_path;
	type = type;
	policy = policy;
	return TSS_ERR_NOT_SUPPORT;
}
#else
int tcs_create_encrypt_key_on_policy(unsigned char *key_path, int type, struct auth_policy *policy){


	int ret = 0;
	int err = 0;
	uint8_t *outbuffer = NULL;
	uint32_t outlen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t  *encrypt_key = NULL;
	uint32_t encrypt_key_len = 2048;
	unsigned char *encrypt_key_filename = NULL;
	uint8_t auth[DEFAULT_HASH_SIZE] = {0};
	
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	uint32_t encryptkeyhandle = 0;

	if(key_path == NULL || policy == NULL || type != KEY_TYPE_SM4_128) return TSS_ERR_PARAMETER;

	ret = tcs_utils_policy_passwd(policy, auth);
	if(ret) return ret;

	if(NULL == (buf = httc_malloc(3*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}

	if(NULL == (key_name = (unsigned char **)httc_malloc(CMD_DEFAULT_ALLOC_SIZE/4))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}

	memset(buf,0,3*CMD_DEFAULT_ALLOC_SIZE);
	memset(key_name,0,CMD_DEFAULT_ALLOC_SIZE/4);
	
	cur_key_path = buf; 													// CMD_DEFAULT_ALLOC_SIZE
	encrypt_key_filename = buf + CMD_DEFAULT_ALLOC_SIZE; 					// CMD_DEFAULT_ALLOC_SIZE
	encrypt_key = encrypt_key_filename + CMD_DEFAULT_ALLOC_SIZE/2;			// CMD_DEFAULT_ALLOC_SIZE/2
	outbuffer = encrypt_key + CMD_DEFAULT_ALLOC_SIZE/2;						// CMD_DEFAULT_ALLOC_SIZE/2
	
	TCM_setlog(0);
	if(0 != (ret =tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	
	if(0 != (ret = TCM_Open())) goto out_release;
	/**Create ymmestric encryption key number**/		
	memset(encrypt_key,0,encrypt_key_len);
	ret = TCM_GetRandom(SM4_KEY_SIZE*2, encrypt_key, &encrypt_key_len);
	if(ret || encrypt_key_len != SM4_KEY_SIZE*2){
		httc_util_pr_error(" Create encryption key fail %s (%d)\n",TCM_GetErrMsg(ret),ret);
		goto out_close;
	}	

	/**Create encryption key protect key**/	

	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))) {
		goto out_close;
	}
	//origin = OUTSIDE_KEY;
	if(0 != (ret = tcs_utils_tree_key_create_tcmlocked(KEY_TYPE_SM4_128, ENCRYPT_KEY, auth, key_name,number, cur_key_path, &encryptkeyhandle, policy->policy_flags,OUTSIDE_KEY,UNMIGRATABLE_KEY))) {
		goto out_close;
	}
	//origin = INSIDE_KEY;
	sprintf((char *)encrypt_key_filename , "%s%s.encrypt", cur_key_path,key_name[number -1]);
	
	ret = TSS_SM4Encrypt(encryptkeyhandle, auth, encrypt_key, encrypt_key_len, outbuffer, (uint32_t *)&outlen);
    if (ret != 0) {
		httc_util_pr_error(" Error from TSS_SM4Encrypt (%s) %d\n", TCM_GetErrMsg(ret),ret);
		err = tcs_utils_delete_keytree((const char *)key_path);  
		if(err){
			httc_util_pr_error("Recovery error 0x%04X",err);
		}
		goto out_close;
    }
	
    ret = httc_util_file_write((const char *)encrypt_key_filename,(const char *)outbuffer,outlen);
	if (ret != outlen) {
        httc_util_pr_error("Error writing encrypt_key file\n");	
       	ret = TSS_ERR_WRITE;
		err = tcs_utils_delete_keytree((const char *)key_path);
		if(err){
			httc_util_pr_error("Recovery error 0x%04X",err);
		}
		goto out_close;
    }

	if(0 != (ret = tcs_utils_save_policy(cur_key_path, key_name[number -1], policy))){
		err = tcs_utils_delete_keytree((const char *)key_path);
		if(err){
			httc_util_pr_error("Recovery error 0x%04X",err);
		}
		//goto out;
	}	
out_close:
	TCM_Close();
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	//origin = INSIDE_KEY;
	//TCM_Close();
	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(key_name) httc_free(key_name);
	if(buf) httc_free(buf);
	return ret;
}
#endif


#ifdef NO_TSB
int tcs_create_inner_encrypt_key_on_policy(		unsigned char *key_path, int type,		struct auth_policy *policy){
	key_path = key_path;
	type = type;
	policy = policy;
	return TSS_ERR_NOT_SUPPORT;
}
#else
int tcs_create_inner_encrypt_key_on_policy(		unsigned char *key_path, int type,		struct auth_policy *policy){

	int ret = 0;
	int err = 0;
	int number = 0;
	uint32_t outkeyhandle = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	unsigned char keyauth[DEFAULT_HASH_SIZE] = {0};
	
	if(key_path == NULL || policy == NULL || type != KEY_TYPE_SM4_128) return TSS_ERR_PARAMETER;
	
	ret = tcs_utils_policy_passwd(policy, keyauth);
	if(ret) return ret;
	
	TCM_setlog(0);

	if(NULL == (buf = httc_malloc(CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}

	if(NULL == (key_name = (unsigned char **)httc_malloc(CMD_DEFAULT_ALLOC_SIZE/4))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	
	memset(buf,0,CMD_DEFAULT_ALLOC_SIZE);
	memset(key_name,0,CMD_DEFAULT_ALLOC_SIZE/4);
	cur_key_path = buf; 										// ALLOC_SIZE
	
	/**Create encryption key**/
	if(0 != (ret =tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))) {
		goto out_release;
	}
	if(0 != (ret = TCM_Open())) goto out_release;
	if(0 != (ret = tcs_utils_tree_key_create_tcmlocked(type, ENCRYPT_KEY, keyauth, key_name,number, cur_key_path, &outkeyhandle, policy->policy_flags,INSIDE_KEY,UNMIGRATABLE_KEY))) {
		goto out_close;
	}
	if(0 != (ret = tcs_utils_save_policy(cur_key_path, key_name[number -1], policy))){
		err = tcs_utils_delete_keytree((const char *)key_path);
		if(err){
			httc_util_pr_error("Recovery error 0x%04X",err);
		}
	}
out_close:
	TCM_Close();
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:

	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(key_name) httc_free(key_name);
	if(buf) httc_free(buf);
	return ret;

}
#endif

int tcs_encrypt(unsigned char *key_path,unsigned char *passwd, int mode,
		unsigned char *ibuffer, int ilength,unsigned char *obuffer,int *olen_inout){

	int ret = 0;
	sm4_context ctx;
	uint8_t encryptkey[128] = {0};
	uint32_t encryptkeylength = 0;
	uint32_t encryptkeyhandle = 0;
	uint8_t keyauth[DEFAULT_HASH_SIZE] = {0};
	pubkeydata k;

	if(key_path == NULL || ibuffer == NULL || obuffer == NULL || *olen_inout < 0) return TSS_ERR_PARAMETER;


	if(0 != (ret =tcs_util_sem_get (TCS_SEM_INDEX_KEY))){
		//TCM_Close();
		return ret;
	}
	if(0 != (ret = TCM_Open())){
		tcs_util_sem_release (TCS_SEM_INDEX_KEY);
		return ret;
	}

	ret = tcs_utils_get_encryptkey_tcmlocked(key_path, passwd, encryptkey, &encryptkeylength, &encryptkeyhandle,keyauth);
	 if (ret) {
       	httc_util_pr_error("get encryptkey fail!\n");
       	TCM_Close();
		tcs_util_sem_release (TCS_SEM_INDEX_KEY);
		return ret;
    }
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);//not closed
	/** Encrypt data **/
	if(encryptkeyhandle){

//		httc_util_dump_hex((const char *)"encrpyt", encryptkey, SM4_KEY_SIZE);	
		ret = TCM_GetPubKey(encryptkeyhandle, keyauth, &k);
		 if (ret != 0) {
			httc_util_pr_error(" Coulnot get public key of encrypt key. %sret=%d\n",  TCM_GetErrMsg(ret),ret);
			TCM_Close();
		 	return ret;
		 }
		 
		 if(k.algorithmParms.algorithmID != TCM_ALG_SM4 ) {	 
			httc_util_pr_error(" bad key handle type.\n");
			TCM_Close();
			ret = TSS_ERR_PARAMETER;
			return ret;
		 }
		
		/** Encrypt data **/
		ret = TSS_SM4Encrypt(encryptkeyhandle, keyauth, ibuffer, ilength, obuffer, (uint32_t *)olen_inout);
	    if(ret){
	      	httc_util_pr_error("from TSS_SM4Encrypt %s\n", TCM_GetErrMsg(ret));
			TCM_Close();
			return ret;
	    }
		TCM_Close();
	}else{
		TCM_Close();
		if(mode != FM_ALGMODE_ECB) return TSS_ERR_PARAMETER;
		sm4_importkey(&ctx,encryptkey,encryptkey + SM4_KEY_SIZE);
		if(*olen_inout < ((ilength/16 +1)*16)) return TSS_ERR_OUTPUT_EXCEED;
		sm4_encrypt(&ctx,mode,ibuffer,ilength,obuffer,olen_inout);
	}

	return ret;
}



int tcs_decrypt(unsigned char *key_path,unsigned char *passwd, int mode,
		unsigned char *ibuffer, int ilength,unsigned char *obuffer,int *olen_inout){
		
	int ret = 0;
	sm4_context ctx;
	uint8_t encryptkey[128] = {0};
	uint32_t encryptkeylen = 0;
	uint32_t encryptkeyhandle = 0;
	uint8_t keyauth[DEFAULT_HASH_SIZE] = {0};
	uint8_t *buf = NULL;
	int buf_length = ilength;
	
	if(key_path == NULL || ibuffer == NULL || obuffer == NULL || *olen_inout < 0) return TSS_ERR_PARAMETER;

	if(0 != (ret =tcs_util_sem_get (TCS_SEM_INDEX_KEY))){
		//TCM_Close();
		return ret;
	}
	if(0 != (ret = TCM_Open())){
		tcs_util_sem_release (TCS_SEM_INDEX_KEY);
		return ret;
	}
	ret = tcs_utils_get_encryptkey_tcmlocked(key_path, passwd, encryptkey,&encryptkeylen,&encryptkeyhandle,keyauth);
	if (ret != 0) {
       	httc_util_pr_error(" TCM_GetEncryptKey Error!\n");
       	TCM_Close();
		tcs_util_sem_release (TCS_SEM_INDEX_KEY);
		return ret;
    }
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);//not closed
	 /** Decrypt data **/
	if(encryptkeyhandle){
		ret = TSS_SM4Decrypt(encryptkeyhandle, keyauth, ibuffer, ilength, obuffer, (uint32_t *)olen_inout);
		if (ret != 0) {
	       	httc_util_pr_error(" Error from TSS_SM4Decrypt %s\n", TCM_GetErrMsg(ret));
			 TCM_Close();
			return ret;
	    }
		TCM_Close();
	}else if(encryptkeylen == SM4_KEY_SIZE*2){
		TCM_Close();
		if(mode != FM_ALGMODE_ECB) return TSS_ERR_PARAMETER;
		sm4_importkey(&ctx,encryptkey,encryptkey + SM4_KEY_SIZE);
		
		if(NULL == (buf = httc_malloc(buf_length))){
			httc_util_pr_error(" Malloc error\n");
			ret = TSS_ERR_NOMEM;
			return ret;
		}
		sm4_decrypt(&ctx,mode,ibuffer,ilength,buf,&buf_length);
		if(buf_length > *olen_inout){
			if(buf) httc_free(buf);
			return TSS_ERR_OUTPUT_EXCEED;
		}
		memcpy(obuffer,buf,buf_length);
		*olen_inout = buf_length;
	}
	if(buf) httc_free(buf);
	return ret;
}

int tcs_set_encrypt_key(	unsigned char *key_path, unsigned char *passwd,	int length, unsigned char *key){

	int ret = 0;
	int number = 0;
	uint32_t encryptkeyhandle = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;	
	uint8_t *encrypt_key_filename = NULL;
	uint8_t keyauth[DEFAULT_HASH_SIZE] = {0};
	uint8_t *outbuffer = NULL;
	uint32_t outbuflen = CMD_DEFAULT_ALLOC_SIZE/4;
	
	if(length != SM4_KEY_SIZE*2 || passwd== NULL || key_path == NULL || key == NULL) return TSS_ERR_PARAMETER;
	
	/** Get seal encyrptkey handle **/
	if(NULL == (buf = httc_malloc(3*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,3*CMD_DEFAULT_ALLOC_SIZE);

	cur_key_path = buf;
	encrypt_key_filename = buf + CMD_DEFAULT_ALLOC_SIZE;
	key_name = (unsigned char **)(encrypt_key_filename + CMD_DEFAULT_ALLOC_SIZE);	
	outbuffer = encrypt_key_filename + CMD_DEFAULT_ALLOC_SIZE + CMD_DEFAULT_ALLOC_SIZE/2;

	if(0 != (ret =tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))) {
			goto out_release;
	}
	if(0 != (ret = TCM_Open())) goto out_release;
	if(0 != (ret = tcs_utils_tree_key_achieve_tcmlocked(TCM_SM4KEY_BIND, key_name, number, cur_key_path, &encryptkeyhandle))){
		goto out_close;
	}
	if(0 != (ret = tcs_utils_get_policy_passwd(cur_key_path, key_name[number - 1], passwd, keyauth))){
		goto out_close;
	}

	/** Recreate encyrptkey file **/	
	sprintf((char *)encrypt_key_filename, "%s%s.encrypt", cur_key_path, key_name[number - 1]);	
	TCM_setlog(0);

	ret = TSS_SM4Encrypt(encryptkeyhandle, keyauth, key, length, outbuffer, (uint32_t *)&outbuflen);
	if (ret != 0) {
		httc_util_pr_error(" Error from TSS_SM4Encrypt (%s) %d\n", TCM_GetErrMsg(ret),ret);
		goto out_close;
    }	
	//TCM_Close();
	
	ret = httc_util_file_write((const char *)encrypt_key_filename,(const char *)outbuffer,outbuflen);	
	if(ret != outbuflen){
		httc_util_pr_error("Write data fail!");
		ret = TSS_ERR_WRITE;
		goto out_close;
	}
	ret = TSS_SUCCESS;
out_close:
	TCM_Close();
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:

	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(buf) httc_free(buf);
	return ret;
}

int tcs_get_encrypt_key(	unsigned char *key_path, unsigned char *passwd, int *length, unsigned char *key){

	int ret = 0;
	uint8_t encryptkey[128] = {0};
	uint32_t encryptkeylen = 0;
	uint32_t handle = 0;
	
	if(passwd== NULL || key_path == NULL || key == NULL) return TSS_ERR_PARAMETER;

	if(0 != (ret =tcs_util_sem_get (TCS_SEM_INDEX_KEY))){
		//TCM_Close();
		return ret;
	}
	if(0 != (ret = TCM_Open())) {
		tcs_util_sem_release (TCS_SEM_INDEX_KEY);
		return ret;
	}
	if(0 != (ret = tcs_utils_get_encryptkey_tcmlocked(key_path, passwd, encryptkey,&encryptkeylen, &handle, NULL))){
		TCM_Close();
		tcs_util_sem_release (TCS_SEM_INDEX_KEY);
		return ret;
	}
	TCM_Close();
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
	

	if(*length < (int)encryptkeylen){
		httc_util_pr_error("Buffer too small.");
		return TSS_ERR_OUTPUT_EXCEED;

	}
	*length = encryptkeylen;
	memcpy(key,encryptkey,*length);		
	return ret;
}
int tcs_create_seal_key(unsigned char *key_path,int type,unsigned char *passwd){

	int ret = 0;
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	uint8_t keyauth[DEFAULT_HASH_SIZE] = {0};
	
	if(key_path == NULL || passwd == NULL || (type != KEY_TYPE_SM2_128 && type != KEY_TYPE_SM4_128)) return TSS_ERR_PARAMETER;
	
	if(NULL == (buf = httc_malloc(2*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,2*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	key_name = (unsigned char **)(buf + CMD_DEFAULT_ALLOC_SIZE);
	
	sm3(passwd,strlen((const char *)passwd),keyauth);
	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))) {
		goto out_release;
	}
	if(0 != (ret = TCM_Open()))goto out_release;
	ret = tcs_utils_tree_key_create_tcmlocked(type, SEAL_KEY, keyauth, key_name, number, cur_key_path, NULL, 0,INSIDE_KEY,UNMIGRATABLE_KEY);
	TCM_Close();
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(buf) httc_free(buf);
	return ret;
}

#ifdef NO_TSB
int tcs_create_seal_key_on_policy(		unsigned char *key_path, int type,	struct auth_policy *policy){
	key_path = key_path;
	type = type;
	policy = policy;
	return TSS_ERR_NOT_SUPPORT;
}
#else
int tcs_create_seal_key_on_policy(		unsigned char *key_path, int type,	struct auth_policy *policy){

	int ret = 0;
	int err = 0;
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	uint8_t keyauth[DEFAULT_HASH_SIZE] = {0};
	
	if(key_path == NULL || policy == NULL|| (type != KEY_TYPE_SM2_128 && type != KEY_TYPE_SM4_128)) return TSS_ERR_PARAMETER;
	
	ret = tcs_utils_policy_passwd(policy, keyauth);
	if(ret) return ret;

	if(NULL == (buf = httc_malloc(2*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,2*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	key_name = (unsigned char **)(buf + CMD_DEFAULT_ALLOC_SIZE);

	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))){
		goto out_release;
	}
	if(0 != (ret = TCM_Open())) goto out_release;
	if(0 != (ret = tcs_utils_tree_key_create_tcmlocked(type, SEAL_KEY, keyauth, key_name, number, cur_key_path, NULL, policy->policy_flags,INSIDE_KEY,UNMIGRATABLE_KEY))){
		TCM_Close();
		goto out_release;
	}
	TCM_Close();
	if(0 != (ret = tcs_utils_save_policy(cur_key_path, key_name[number -1], policy))){
		err = tcs_utils_delete_keytree((const char *)key_path);
		if(err){
			httc_util_pr_error("Recovery error 0x%04X",err);
		}
	}
	
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:

	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(buf) httc_free(buf);
	return ret;
}
#endif

static int tcs_seal_data_dirlocked(unsigned char *key_path,unsigned char *ibuffer, int ilength,
								unsigned char *obuffer,int *olen_inout,unsigned char *passwd){


	int ret = 0;
	int number = 0;
	uint32_t sealhandle = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	struct key_info *seal_key_info = NULL;
	uint8_t *seal_key_info_file = NULL;
	unsigned char **key_name = NULL;
	unsigned char seal_pcrinfo[1024];
	uint32_t pcrInfoSize = 1024;
	uint8_t keyauth[DEFAULT_HASH_SIZE] = {0};
	uint64_t datalen = 0;
	
	if(key_path == NULL || ibuffer == NULL || obuffer == NULL) return TSS_ERR_PARAMETER;

	if(NULL == (buf = httc_malloc(2*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}

	if(NULL == (key_name= (unsigned char **)httc_malloc(CMD_DEFAULT_ALLOC_SIZE/2))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,2*CMD_DEFAULT_ALLOC_SIZE);
	memset(key_name,0,CMD_DEFAULT_ALLOC_SIZE/2);
	
	cur_key_path = buf;
	seal_key_info_file = cur_key_path + CMD_DEFAULT_ALLOC_SIZE;

	//if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))){
		goto out_free;
	}
	
	sprintf((char *)seal_key_info_file,"%s%s/%s.info",cur_key_path,key_path + USED_PATH,key_name[number -1]);	
	seal_key_info = httc_util_file_read_full((const char *) seal_key_info_file, (unsigned long *)&datalen);
	if(seal_key_info == NULL){
		httc_util_pr_error("path error! %s\n",key_path);
		ret = TSS_ERR_FILE;
		goto out_free;
	}
	
	if(seal_key_info->origin == OUTSIDE_KEY){
		httc_util_pr_error("key error! %s\n",key_path);
		ret = TSS_ERR_PARAMETER;
		goto out_free;
	}
		
	if(0 != (ret = TCM_Open())) goto out_free;
	if(0 != (ret = tcs_utils_tree_key_achieve_tcmlocked(SEAL_KEY, key_name, number, cur_key_path, &sealhandle))) {
		goto out_close;
	}
	if(0 != (ret = tcs_utils_get_policy_passwd(cur_key_path, key_name[number -1], passwd, keyauth))) {
		goto out_close;
	}
	if(0 != (ret = tcs_utils_upate_pcrinfo_tcmlocked(0, seal_pcrinfo, &pcrInfoSize))) {
		goto out_close;
	}
	
	TCM_setlog(0);
	ret = TCM_Seal(sealhandle, seal_pcrinfo, pcrInfoSize, keyauth, keyauth, ibuffer, ilength, obuffer, (uint32_t *)olen_inout);	
    if(ret != 0){
		httc_util_pr_error(" Error from TCM_Seal %s\n", TCM_GetErrMsg(ret));
    }	
out_close:
	TCM_Close();
//out_release:
//	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	//TCM_Close();
	if(seal_key_info) httc_free(seal_key_info);
	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(key_name) httc_free(key_name);
	if(buf) httc_free(buf);
	return ret;
}

int tcs_seal_data(unsigned char *key_path,unsigned char *ibuffer, int ilength,
								unsigned char *obuffer,int *olen_inout,unsigned char *passwd){
	int ret;
	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY)))return ret;
	ret = tcs_seal_data_dirlocked(key_path,ibuffer,ilength,obuffer,olen_inout,passwd);
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
	return ret;
}


static int tcs_unseal_data_dirlocked(unsigned char *key_path,unsigned char *ibuffer, int ilength,unsigned char *obuffer,int *olen_inout,unsigned char *passwd){

	int ret = 0;
	int number = 0;
	uint32_t sealhandle = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	struct key_info *seal_key_info = NULL;
	uint8_t *seal_key_info_file = NULL;
	unsigned char **key_name = NULL;
	uint8_t keyauth[DEFAULT_HASH_SIZE] = {0};
	uint64_t datalen = 0;

	if(key_path == NULL || ibuffer == NULL || obuffer == NULL) return TSS_ERR_PARAMETER;
		
	if(NULL == (buf = httc_malloc(2*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}

	if(NULL == (key_name= (unsigned char **)httc_malloc(CMD_DEFAULT_ALLOC_SIZE/2))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,2*CMD_DEFAULT_ALLOC_SIZE);
	memset(key_name,0,CMD_DEFAULT_ALLOC_SIZE/2);
	
	cur_key_path = buf;
	seal_key_info_file = cur_key_path + CMD_DEFAULT_ALLOC_SIZE;
	
	//if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))) {
		goto out_free;
	}
	
	sprintf((char *)seal_key_info_file,"%s%s/%s.info",cur_key_path,key_path + USED_PATH,key_name[number -1]);
	seal_key_info = httc_util_file_read_full((const char *) seal_key_info_file, (unsigned long *)&datalen);
	if(seal_key_info == NULL){
		httc_util_pr_error("path error! %s\n",key_path);
		ret = TSS_ERR_FILE;
		goto out_free;
	}
	
	if(seal_key_info->origin == OUTSIDE_KEY){
		httc_util_pr_error("key error! %s\n",key_path);
		ret = TSS_ERR_PARAMETER;
		goto out_free;
	}
	
	if(0 != (ret = TCM_Open())) goto out_free;
	if(0 != (ret = tcs_utils_tree_key_achieve_tcmlocked(SEAL_KEY, key_name, number, cur_key_path, &sealhandle))){
		goto out_close;
	}
	if(0 != (ret = tcs_utils_get_policy_passwd(cur_key_path, key_name[number -1], passwd, keyauth))){
		goto out_close;
	}
	
	/**Uneal data**/
	TCM_setlog(0);
	ret = TCM_Unseal(sealhandle, keyauth, keyauth, ibuffer, ilength, obuffer, (uint32_t *)olen_inout);
	if(ret){
		httc_util_pr_error(" Error from TCM_Unseal %s (%d)\n", TCM_GetErrMsg(ret),ret);
	}
out_close:
	TCM_Close();
//out_release:
//	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	if(seal_key_info) httc_free(seal_key_info);
	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(key_name) httc_free(key_name);
	if(buf) httc_free(buf);
	return ret;
}
int tcs_unseal_data(unsigned char *key_path,unsigned char *ibuffer, int ilength,unsigned char *obuffer,int *olen_inout,unsigned char *passwd){
	int ret;
	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY)))return ret;
	ret = tcs_unseal_data_dirlocked(key_path,ibuffer,ilength,obuffer,olen_inout,passwd);
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
	return ret;
}
int tcs_seal_data_store(unsigned char *key_path,unsigned char *ibuffer, int ilength,
												unsigned char *file_name,unsigned char *passwd){
	
	int ret = 0;
	int number = 0;
	int olength = CMD_DEFAULT_ALLOC_SIZE;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	unsigned char *obuffer = NULL;	
	unsigned char *sealfilename = NULL;	

	if(key_path == NULL || ibuffer == NULL ) return TSS_ERR_PARAMETER;
	
	if(NULL == (buf = httc_malloc(3*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		return ret;
	}

	if(NULL == (key_name = (unsigned char **)httc_malloc(CMD_DEFAULT_ALLOC_SIZE/4))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}	
	memset(buf,0,3*CMD_DEFAULT_ALLOC_SIZE);
	memset(key_name,0,CMD_DEFAULT_ALLOC_SIZE/4);
	
	cur_key_path = buf;
	sealfilename = buf + CMD_DEFAULT_ALLOC_SIZE;
	obuffer = sealfilename + CMD_DEFAULT_ALLOC_SIZE;
	
	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	/**seal data**/
	ret = tcs_seal_data_dirlocked(key_path, ibuffer, ilength, obuffer, &olength, passwd);
	if(ret) goto out_release;

	/**save seal data**/

	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))) {
		goto out_release;
	}
	
	sprintf((char *)sealfilename, "%s%s/%s.seal", cur_key_path, key_path + USED_PATH,file_name);
	ret = httc_util_file_write((const char *)sealfilename, (const char *)obuffer, olength);
	if(ret != olength) goto out_release;
	ret = TSS_SUCCESS;	
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(key_name) httc_free(key_name);
	if(buf) httc_free(buf);
	return ret;
}

int tcs_unseal_stored_data(unsigned char *key_path,unsigned char *obuffer,int *olen_inout,unsigned char *file_name,unsigned char *passwd){

	int ret = 0;
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	unsigned char *sealfilename = NULL;
	uint8_t *data = NULL;
	unsigned long datalen = 0;

	if(key_path == NULL || olen_inout == NULL || file_name == NULL || obuffer == NULL) return TSS_ERR_PARAMETER;
	
	if(NULL == (buf = httc_malloc(2*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	if(NULL == (key_name = (unsigned char **)httc_malloc(CMD_DEFAULT_ALLOC_SIZE/4))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	
	memset(buf,0,2*CMD_DEFAULT_ALLOC_SIZE);
	memset(key_name,0,CMD_DEFAULT_ALLOC_SIZE/4);
	
	cur_key_path = buf;
	sealfilename = buf + CMD_DEFAULT_ALLOC_SIZE;	

	/** Get unseal data**/
	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))) {
		goto out_release;
	}
	sprintf((char *)sealfilename, "%s%s/%s.seal", cur_key_path, key_path + USED_PATH,file_name);
	
	data = httc_util_file_read_full((const char *)sealfilename, (unsigned long *)&datalen);
	if(data == NULL){
		httc_util_pr_error("read seal file failed.\n");
		ret = TSS_ERR_READ;
		goto out_release;
	}
	//tcs_util_sem_release (TCS_SEM_INDEX_KEY);
	
	/**Unseal stored data**/
	ret = tcs_unseal_data_dirlocked(key_path, data, datalen, obuffer, olen_inout, passwd);
	//goto out_free;

out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(key_name) httc_free(key_name);
	if(data) httc_free(data);
	if(buf) httc_free(buf);
	return ret;
}

int tcs_get_sealed_data(unsigned char *key_path,unsigned char *obuffer,int *olen_inout,unsigned char *file_name){

	int ret = 0;
	int number = 0;	
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	unsigned char *sealfilename = NULL;
	unsigned char *data = NULL;
	unsigned long datalen = 0;

	if(key_path == NULL || olen_inout == NULL || file_name == NULL || obuffer == NULL) return TSS_ERR_PARAMETER;
	if(strlen((const char *)file_name) > MAX_KEY_NAME_SIZE)	return TSS_ERR_INPUT_EXCEED;
	
	if(NULL == (buf = httc_malloc(3*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,3*CMD_DEFAULT_ALLOC_SIZE);

	cur_key_path = buf;
	key_name = (unsigned char **)(buf + CMD_DEFAULT_ALLOC_SIZE);
	sealfilename = buf + 2*CMD_DEFAULT_ALLOC_SIZE;
	
	/** Get seal data**/
	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret =tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))){
		goto out_release;
	}
	sprintf((char *)sealfilename, "%s%s/%s.seal", cur_key_path, key_path + USED_PATH,file_name);
	
	data = httc_util_file_read_full((const char *)sealfilename, (unsigned long *)&datalen);
	if(data == NULL){
		httc_util_pr_error("read sealed data fail.\n");
		ret = TSS_ERR_READ;
		goto out_release;
	}
	
	if(*olen_inout < datalen){
		httc_util_pr_error("read sealed data too long.\n");
		ret = TSS_ERR_OUTPUT_EXCEED;
		goto out_release;
	}
	*olen_inout = datalen;
	memcpy(obuffer,data,*olen_inout);
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(buf) httc_free(buf);
	if(data) httc_free(data);
	return ret;
}

int tcs_save_sealed_data(unsigned char *key_path, void *ibuffer, int ilength,unsigned char *file_name){

	int ret = 0;
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	unsigned char *sealfilename = NULL;

	if(key_path == NULL || file_name == NULL || ibuffer == NULL) return TSS_ERR_PARAMETER;
	if(strlen((const char *)file_name) > MAX_KEY_NAME_SIZE)	return TSS_ERR_INPUT_EXCEED;
	
	if(NULL == (buf = httc_malloc(3 * CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,3*CMD_DEFAULT_ALLOC_SIZE);

	cur_key_path = buf;
	key_name = (unsigned char **)(buf + CMD_DEFAULT_ALLOC_SIZE);
	sealfilename = buf + 2*CMD_DEFAULT_ALLOC_SIZE;

	/** Set seal data**/
	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))) {
		goto out_release;
	}
	
	sprintf((char *)sealfilename, "%s%s/%s.seal", cur_key_path, key_path + USED_PATH,file_name);	
	ret = httc_util_file_write((const char *)sealfilename, (const char *)ibuffer, (unsigned int)ilength);
	if(ret != ilength){
		httc_util_pr_error(" Writing file fail!\n");
		ret = TSS_ERR_WRITE;
		goto out_release;
	}
	ret = TSS_SUCCESS;
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(buf) httc_free(buf);
	return ret;
}

/*
 * 	设置默认存储密钥类型
 * 	密钥树中的非叶子存储密钥，如果不存在将自动创
 * 	本接口设置自动创建非叶子存储密钥的密钥类型
 *
 */
int tcs_set_default_path_key_type(uint32_t type){
	if(type != KEY_TYPE_SM4_128) return TSS_ERR_PARAMETER;
	return TSS_SUCCESS;
}

int tcs_create_migratable_path_key(unsigned char *key_path,uint32_t type){

	int ret = 0;
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	uint8_t keyauth[DEFAULT_HASH_SIZE] = {0};
	
	if(type != KEY_TYPE_SM4_128 || key_path == NULL) return TSS_ERR_PARAMETER;
	if(key_path == NULL) return TSS_ERR_PARAMETER;
	
	if(NULL == (buf = httc_malloc(2*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,2*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	key_name = (unsigned char **)(buf + CMD_DEFAULT_ALLOC_SIZE);	
		
	NODEAUTH(keyauth);
	//migratable = MIGRATABLE_KEY;
	
	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))){
		goto out_release;
	}
	if(0 != (ret = TCM_Open())) goto out_release;
	ret = tcs_utils_tree_key_create_tcmlocked(type, STORE_KEY, keyauth, key_name,number,
			cur_key_path, NULL, 0,INSIDE_KEY,MIGRATABLE_KEY);
	TCM_Close();
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:

	while (number--) if(key_name[number]) httc_free(key_name[number]);	
	if(buf) httc_free(buf);
	return ret;
}


int tcs_create_path_key(unsigned char *key_path,uint32_t type){

	int ret = 0;
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	uint8_t keyauth[DEFAULT_HASH_SIZE] = {0};
	
	if(type != KEY_TYPE_SM4_128 || key_path == NULL) return TSS_ERR_PARAMETER;
	
	if(NULL == (buf = httc_malloc(2*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,2*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	key_name = (unsigned char **)(buf + CMD_DEFAULT_ALLOC_SIZE);	
	
	NODEAUTH(keyauth);
	//migratable = UNMIGRATABLE_KEY;

	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))) {
		goto out_release;
	}
	if(0 != (ret = TCM_Open())) goto out_release;
	ret = tcs_utils_tree_key_create_tcmlocked(type, STORE_KEY, keyauth, key_name,number,
			cur_key_path, NULL, 0,INSIDE_KEY,UNMIGRATABLE_KEY);
	TCM_Close();
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);	
	if(buf) httc_free(buf);
	return ret;
}

int tcs_get_keyinfo(unsigned char *key_path, struct key_info *info){
	
	int ret = 0;		
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *data = NULL;	
	uint8_t *keyinfoname = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	unsigned long datasize = 0;
	unsigned long encryptdatasize = 0;
	uint8_t *encryptkeyinfo = NULL;
	struct key_info *cur = NULL;

	if(key_path == NULL || info == NULL) return TSS_ERR_PARAMETER;
	
	if(NULL == (buf = httc_malloc(4*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,4*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	keyinfoname = buf + CMD_DEFAULT_ALLOC_SIZE;
	encryptkeyinfo = keyinfoname  + CMD_DEFAULT_ALLOC_SIZE ;
	key_name = (unsigned char **)(encryptkeyinfo + CMD_DEFAULT_ALLOC_SIZE);	

	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))) {
		goto out_release;
	}
	
	sprintf((char *)encryptkeyinfo, "%s%s/%s.encrypt", cur_key_path, key_path + USED_PATH,key_name[number - 1]);
	sprintf((char *)keyinfoname, "%s%s/%s.info", cur_key_path, key_path + USED_PATH,key_name[number - 1]);
	
	data = httc_util_file_read_full((const char *)keyinfoname,(unsigned long *)&datasize);	
	if(datasize != sizeof(struct key_info) || data == NULL){
		httc_util_pr_error("read keyinfo file error %s.\n", keyinfoname);
		ret = TSS_ERR_READ;
		goto out_release;
	}
	
	if(access((const char *)encryptkeyinfo,0)==0){
		ret = httc_util_file_size((const char *)encryptkeyinfo,&encryptdatasize);
		cur = (struct key_info *)data;
		cur->key_type = (encryptdatasize == 48 ? KEY_TYPE_SM4_128 : KEY_TYPE_SM2_128);
		cur->key_size = (cur->key_type == KEY_TYPE_SM2_128 ? (SM2_PRIVATE_KEY_SIZE + SM2_PUBLIC_KEY_SIZE) : SM4_KEY_SIZE);
	}	
	memcpy((char *)info,data,sizeof(struct key_info));	
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(data) httc_free(data);
	if(buf) httc_free(buf);
	return ret;

	
}

int tcs_get_keyinfo_path(unsigned char *key_path, struct key_info **info,int *onumber_inout){
	int ret;
	int i = 0;
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *data = NULL;
	uint64_t length = 0;
	uint8_t *keyinfoname = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	unsigned long encryptdatasize = 0;
	uint8_t *encryptkeyinfo = NULL;
	struct key_info *cur = NULL;

	if(key_path == NULL || info == NULL || onumber_inout == NULL) return TSS_ERR_PARAMETER;
	
	if(NULL == (buf = httc_malloc(4*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,4*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	keyinfoname = buf + CMD_DEFAULT_ALLOC_SIZE;
	encryptkeyinfo = keyinfoname  + CMD_DEFAULT_ALLOC_SIZE ;
	key_name = (unsigned char **)(encryptkeyinfo + CMD_DEFAULT_ALLOC_SIZE);

	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if( 0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))){
		goto out_release;
	}
	*onumber_inout = number;
	
	if(NULL == (*info = httc_malloc (number * sizeof(struct key_info) ))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_release;
	}	
	for(; i < number;i++){
		strncat((char *)cur_key_path,(const char *)key_name[i],strlen((const char *)key_name[i]));
		strncat((char *)cur_key_path,"//",1);
		sprintf((char *)encryptkeyinfo, "%s%s.encrypt", cur_key_path, key_name[i]);
		sprintf((char *)keyinfoname, "%s%s.info", cur_key_path, key_name[i]);		
		data = httc_util_file_read_full((const char *)keyinfoname, (unsigned long *)&length);
		if(length != sizeof(struct key_info)){
			httc_util_pr_error(" keyinfo file read error %s.\n", keyinfoname);
			ret = TSS_ERR_READ;
			if(*info) httc_free(*info);
			*info = NULL;
			goto out_release;
		}
		
		if(access((const char *)encryptkeyinfo,0)==0){
			ret = httc_util_file_size((const char *)encryptkeyinfo,&encryptdatasize);
			cur = (struct key_info *)data;
			cur->key_type = (encryptdatasize == 80 ? KEY_TYPE_SM4_128 : KEY_TYPE_SM2_128);
			cur->key_size = (cur->key_type == KEY_TYPE_SM2_128 ? (SM2_PRIVATE_KEY_SIZE + SM2_PUBLIC_KEY_SIZE) : SM4_KEY_SIZE);
		}

		memcpy(*info + i, data, length);
		if(data) httc_free(data);

	}	
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(buf) httc_free(buf);
	return ret;
}

int tcs_get_public_key(unsigned char *key_path,unsigned char *pbuffer,int *obuf_len){

	int ret = 0;
	int number = 0;
	int length = 0;
	uint8_t *buf = NULL;
	uint8_t *pubkeyname = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	struct stat pubketstat;
	FILE *fp;
	if(key_path == NULL || obuf_len == NULL || pbuffer == NULL) return TSS_ERR_PARAMETER;
	
	if(NULL == (buf = httc_malloc(3*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,3*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	pubkeyname = buf + CMD_DEFAULT_ALLOC_SIZE;
	key_name = (unsigned char **)(pubkeyname + CMD_DEFAULT_ALLOC_SIZE);	

	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))) {
		goto out_release;
	}
	
	memset(pubkeyname,0,CMD_DEFAULT_ALLOC_SIZE);
	sprintf((char *)pubkeyname, "%s%s/%s.pub", cur_key_path, key_path + USED_PATH,key_name[number - 1]);
	fp = fopen((char *)pubkeyname,"r");
	if(fp == NULL){
		httc_util_pr_error(" Open file fail %s!\n",pubkeyname);
		ret = TSS_ERR_FILE;
		goto out_release;
	}
	stat((char *)pubkeyname,&pubketstat);
	length = (int)pubketstat.st_size;
	if(length > *obuf_len){
		httc_util_pr_error(" The space is too small for pubkey!\n");
		fclose(fp);
		ret = TSS_ERR_OUTPUT_EXCEED;
		goto out_release;
	}
	*obuf_len = length;
	ret = fread(pbuffer,1,*obuf_len,fp);
	if(ret != length){
		httc_util_pr_error(" Readpubkey fail!\n");
		fclose(fp);
		ret = TSS_ERR_READ;
		goto out_release;
	}	
	fclose(fp);
	ret = TSS_SUCCESS;
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(buf) httc_free(buf);
 	return ret;
}


int tcs_change_leaf_auth(unsigned char *key_path,unsigned char *oldpasswd,unsigned char *passwd){

	int i = 0;
	int ret = 0;
	int err = 0;
	int number = 0;
	uint32_t inkeyhandle = 0;
	uint32_t outkeyhandle = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	uint8_t *keyfilename = NULL;
	uint8_t *policyfilename = NULL;
	unsigned char **key_name = NULL;
	unsigned char  	*keyblob = NULL;
	unsigned int   	keybloblen = 0;    
	uint64_t datalen = 0;
	uint8_t oldauth[DEFAULT_HASH_SIZE] = {0};
	uint8_t newauth[DEFAULT_HASH_SIZE] = {0};
	uint8_t parauth[DEFAULT_HASH_SIZE] = {0};
	struct save_policy *policy = NULL;
	unsigned int   	bakflag = 0;
	uint32_t policylen = 0;
	int migratable = 0;

	STACK_TCM_BUFFER(buffer)
	STACK_TCM_BUFFER(outblob)
	unsigned int   	bloblen = 0;
	keydata key;
	pubkeydata k;

	uint8_t *encyrptkey_name = NULL;
	uint8_t *encyrptkeydata = NULL;
	uint32_t encyrptkeydataflen = 0;	
	uint8_t *encyrptdata = NULL;
	uint32_t encyrptdatalen = CMD_DEFAULT_ALLOC_SIZE/4;	
	uint8_t *outbuffer = NULL;
	uint32_t outbuflen = CMD_DEFAULT_ALLOC_SIZE/4;

	if(key_path == NULL) return TSS_ERR_PARAMETER;
	
	if(NULL == (buf = httc_malloc(5*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,5*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;											//CMD_DEFAULT_ALLOC_SIZE
	policyfilename = cur_key_path + CMD_DEFAULT_ALLOC_SIZE;		//CMD_DEFAULT_ALLOC_SIZE
	keyfilename = policyfilename + CMD_DEFAULT_ALLOC_SIZE;		//CMD_DEFAULT_ALLOC_SIZE
	encyrptkey_name = keyfilename + CMD_DEFAULT_ALLOC_SIZE;		//CMD_DEFAULT_ALLOC_SIZE
	key_name = (unsigned char **)(encyrptkey_name + CMD_DEFAULT_ALLOC_SIZE);	//CMD_DEFAULT_ALLOC_SIZE/2
	outbuffer = encyrptkey_name + CMD_DEFAULT_ALLOC_SIZE + CMD_DEFAULT_ALLOC_SIZE/2;	//CMD_DEFAULT_ALLOC_SIZE/4
	encyrptdata = outbuffer + CMD_DEFAULT_ALLOC_SIZE/4; //CMD_DEFAULT_ALLOC_SIZE/4

	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath(key_path, key_name, &number,(unsigned char *) cur_key_path))) {
		goto out_release;
	}
	sprintf((char *)encyrptkey_name, "%s%s/%s.encrypt", cur_key_path,key_path + USED_PATH, key_name[number - 1]);
	NODEAUTH(parauth)
	TCM_setlog(0);	
	if(0 != (ret = TCM_Open())) goto out_release;
	for(; i < number;i++){		
		strncat((char *)cur_key_path,(const char *)key_name[i],strlen((const char *)key_name[i]));
		strncat((char *)cur_key_path,"//",1);
		if(i != number - 1){
			ret = tcs_utils_loadkey_tcmlocked(cur_key_path,(uint8_t *)key_name[i],TCM_SM4KEY_STORAGE,inkeyhandle,&outkeyhandle, parauth, &migratable);
			if(ret) goto out_close;
			inkeyhandle = outkeyhandle;
		}else if(i == number - 1){
		
			memset(keyfilename,0,CMD_DEFAULT_ALLOC_SIZE);	
			sprintf((char *)keyfilename, "%s%s.key", cur_key_path, key_name[i]);
			keyblob = httc_util_file_read_full((const char *)keyfilename, (unsigned long *)&datalen);
			if(keyblob == NULL){
				httc_util_pr_error("read key file fail %s!\n",keyfilename);		
				ret =  TSS_ERR_READ;
				goto out_close;
			}
			keybloblen = datalen;
			
			memset(&key, 0x0, sizeof(key));
			SET_TCM_BUFFER(&buffer, keyblob, keybloblen);
		    TSS_KeyExtract(&buffer, 0, &key);
			
			if(!inkeyhandle) inkeyhandle = SMK_HANDLE;
			if (0 != (ret = TCM_LoadKey(inkeyhandle, parauth, &key, &outkeyhandle))){
					httc_util_pr_error(" TCM_LoadKey return error '%s' (%d).\n", TCM_GetErrMsg(ret), ret);
					goto out_close;
			}
			if(0 != (ret = tcs_utils_get_policy_passwd(cur_key_path, key_name[number -1], oldpasswd, oldauth))){
				goto out_close;
			}
			
			/**change policy**/
			memset(policyfilename,0,CMD_DEFAULT_ALLOC_SIZE);	
			sprintf((char *)policyfilename, "%s%s.policy", cur_key_path, key_name[i]);
			policy = httc_util_file_read_full((const char *)policyfilename, (unsigned long *)&datalen);
			if(policy){
				bakflag = policy->policy_flags;
				if(passwd) {
					policy->policy_flags |= POLICY_FLAG_USED_PASSWD;
				}else{
					policy->policy_flags &= (~POLICY_FLAG_USED_PASSWD);
				}
				policylen = datalen;
				ret = httc_util_file_write((const char *)policyfilename,(const char *)policy,policylen);
				if (ret != policylen){
			        httc_util_pr_error("Error change policy.\n");
			       	ret = TSS_ERR_WRITE;
					goto out_close;
				}				
			}else if(policy == NULL && passwd == NULL){
				httc_util_pr_error("Error parameter!\n");		
				ret =  TSS_ERR_PARAMETER;
				goto out_close;
			}
			
			if(0 != (ret = tcs_utils_get_policy_passwd(cur_key_path, key_name[number -1], passwd, newauth))) goto recovery;
			
			/** check if encrypt key**/				
			if(access((const char *)encyrptkey_name,0)==0){
				encyrptkeydata = httc_util_file_read_full((const char *)encyrptkey_name, (unsigned long *)&datalen);
				if(encyrptkey_name == NULL){
					httc_util_pr_error("read encyrptkey file fail %s!\n",encyrptkey_name);		
					ret =  TSS_ERR_READ;
					goto recovery;
				}
				encyrptkeydataflen = datalen;

				ret = TSS_SM4Decrypt(outkeyhandle, oldauth, encyrptkeydata, encyrptkeydataflen, outbuffer, (uint32_t *)&outbuflen);
				if (ret) {
			       	httc_util_pr_error(" Error from TSS_SM4Decrypt %s(%d)\n", TCM_GetErrMsg(ret),ret);
					goto recovery;
			    }
			}			
			
			/**change leafkey auth**/								
	        if(0 != ( ret = TCM_ChangeAuth( inkeyhandle, parauth, oldauth, newauth, TCM_ET_KEY, key.encData.buffer, key.encData.size))){
        		httc_util_pr_error("Error from TCM_ChangeAuth %s\n", TCM_GetErrMsg(ret));
				goto recovery;	
			}
			
			/**Save new keyblob**/
			bloblen = TCM_WriteKey(&outblob, &key);
			if ((bloblen & ERR_MASK) != 0){
				httc_util_pr_error("TCM_WriteKey error%s(%d).\n",TCM_GetErrMsg(ret),ret);
				ret = bloblen;
				goto recovery;
			}
			ret = httc_util_file_write((const char *)keyfilename,(const char *)outblob.buffer,bloblen);
			if (ret != bloblen){
		        httc_util_pr_error("Error writing encrypt_key file.\n");
		       	ret = TSS_ERR_WRITE;
				goto recovery;
			}
			
			/**If encrypt key save new encrypt key file**/
			if(access((const char *)encyrptkey_name,0)==0){

				/** Encrypt data **/
				memset(&key, 0x0, sizeof(key));
				SET_TCM_BUFFER(&buffer, outblob.buffer, bloblen);
		   		TSS_KeyExtract(&buffer, 0, &key);
				
				if (0 != (ret = TCM_LoadKey(inkeyhandle, parauth, &key, &outkeyhandle))){
					httc_util_pr_error(" TCM_LoadKey return error '%s' (%d).\n", TCM_GetErrMsg(ret), ret);
					goto recovery;
				}
	
				ret = TCM_GetPubKey(outkeyhandle, newauth, &k);
				 if (ret != 0) {
					httc_util_pr_error(" Coulnot get public key of encrypt key. %sret=%d\n",  TCM_GetErrMsg(ret),ret);
					goto recovery;
				 }
				 
				 if(k.algorithmParms.algorithmID != TCM_ALG_SM4 ) {	 
					httc_util_pr_error(" bad key handle type.\n");
					ret = TSS_ERR_PARAMETER;
					goto  recovery;
				 }
				 				 
				
				ret = TSS_SM4Encrypt(outkeyhandle, newauth, outbuffer, outbuflen, encyrptdata, (uint32_t *)&encyrptdatalen);
			    if(ret){
			      	httc_util_pr_error("from TSS_SM4Encrypt %s\n", TCM_GetErrMsg(ret));
					goto  recovery;
			    }
				
				 /** Save encrypt data **/				
				ret = httc_util_file_write((const char *)encyrptkey_name,(const char *)encyrptdata,encyrptdatalen);
				if (ret != encyrptdatalen) {
			        httc_util_pr_error("Error writing encrypt_key file\n");
			       	ret = TSS_ERR_WRITE;
					goto recovery;
			    }
			}
		}
	}
	ret = TSS_SUCCESS;
	goto out_close;

recovery:
	err = httc_util_file_write((const char *)keyfilename,(const char *)keyblob,keybloblen);
	if (err != keybloblen){
        httc_util_pr_error("Recovery error writing key file 0x%04X.\n",err);
		goto out_close;
	}
	
	if(policy){
		policy->policy_flags = bakflag;
		err = httc_util_file_write((const char *)policyfilename,(const char *)policy,policylen);
		if (err != policylen){
	        httc_util_pr_error("Recovery error writing policy file 0x%04X.\n",err);
			goto out_close;
		}
	}
out_close:
	TCM_Close();
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);
	if(encyrptkeydata) httc_free(encyrptkeydata);
	if(policy) httc_free(policy);
	if(keyblob) httc_free(keyblob);
	if(buf) httc_free(buf);
	return ret;
}


int tcs_create_shared_keytree_storespace(unsigned char *ownerpass, int size,	unsigned char *nvpasswd){

	uint32_t ret = 0;
	uint32_t index = KEY_TREE_INDEX;

	if(ownerpass == NULL || nvpasswd == NULL) return TSS_ERR_PARAMETER;
	ret = tcs_nv_define_space(index, size, ownerpass, nvpasswd);
	if (ret) return ret;
	
	return TSS_SUCCESS;	
}

int tcs_remove_shared_keytree_storespace(unsigned char *ownerpass){

	uint32_t ret = 0;
	uint32_t index = KEY_TREE_INDEX;
	if(ownerpass == NULL) return TSS_ERR_PARAMETER;
	ret = tcs_nv_delete_space(index,ownerpass);
	if (0 != ret) {
		httc_util_pr_error("tcs_nv_delete_space error.\n");
		return ret;
	}
	return TSS_SUCCESS;
}

int tcs_save_shared_keytree(unsigned char *nvpasswd){

	int ret = 0;
	uint8_t *data = NULL;
	uint32_t datalen = 0;
	uint8_t nvauth[DEFAULT_HASH_SIZE] = {0};

	if(nvpasswd == NULL) return TSS_ERR_PARAMETER;

	sm3 (nvpasswd, strlen ((const char *)nvpasswd), nvauth);
	
	ret = tcs_export_keytree((const char *)"s://", &data, (int *)&datalen);
	if(ret) goto out_free;
	
//	printf("datalen:%ld\n",datalen);
	TCM_setlog(0);
	if(0 != (ret = TCM_Open())) goto out_free;
	ret = TCM_NV_WriteValueAuth(KEY_TREE_INDEX, 0, (unsigned char *)&datalen, sizeof(uint32_t), nvauth);
	if(ret != 0){
		httc_util_pr_error(" Error from NV_WriteValueAuth 1 %s(%08X)\n", TCM_GetErrMsg(ret),ret);
		goto out_close;
	}
	sm3 (nvpasswd, strlen ((const char *)nvpasswd), nvauth);	
	ret = TCM_NV_WriteValueAuth(KEY_TREE_INDEX, sizeof(uint32_t), data, datalen, nvauth);
	if(ret){ 
		httc_util_pr_error(" Error from NV_WriteValueAuth 2 %s(%08X)\n", TCM_GetErrMsg(ret),ret);
	}
out_close:
	TCM_Close();
out_free:

	if(data) httc_free(data);	
	return ret;
	
}

int tcs_load_shared_keytree(unsigned char *nvpasswd){

	uint32_t ret = 0;
	uint8_t *data = NULL;
	uint32_t datalen = 0;
	uint8_t nvauth[DEFAULT_HASH_SIZE] = {0};
	uint32_t cap = TCM_CAP_NV_INDEX;
	STACK_TCM_BUFFER(rep);
	STACK_TCM_BUFFER( ubcap );
	TCM_NV_DATA_PUBLIC np;
    STACK_TCM_BUFFER(tb);

	if(nvpasswd == NULL) return TSS_ERR_PARAMETER;
	
	sm3 (nvpasswd, strlen ((const char *)nvpasswd), nvauth);
	STORE32(ubcap.buffer, 0, KEY_TREE_INDEX);
    ubcap.used= 4;
	
	TCM_setlog(0);


	if(0 != (ret = TCM_Open())) goto out_free;
	/** Get Datalength **/
    ret = TCM_GetCapability(cap, &ubcap, &rep);
    if (0 != ret) {
	   httc_util_pr_error(" TCM_GetCapability returne %s.\n", TCM_GetErrMsg(ret));
		goto out_close;
	}
	
    TSS_SetTCMBuffer(&tb, rep.buffer, rep.used);
    ret = TCM_ReadNVDataPublic(&tb, 0, &np);
    if ( ( ret & ERR_MASK) != 0) {
       httc_util_pr_error(" Coulnot eerialize the TCM_NV_DATA_PUBLIC structure.\n");
		goto out_close;
    }
	
	datalen = (uint32_t)np.dataSize;
	if(NULL == (data = httc_malloc (datalen))){
		httc_util_pr_error (" Req Alloc error!\n");
		ret = TSS_ERR_NOMEM;
		goto out_close;
	}
//	printf("datalen:%d\n",datalen);
	/** Read Data **/
	ret = TCM_NV_ReadValueAuth(KEY_TREE_INDEX, 0, datalen, data, &datalen, nvauth);
	if(ret != 0){
		httc_util_pr_error(" Error from TCM_NV_ReadValueAuth %s(%08X)\n", TCM_GetErrMsg(ret),ret);
		goto out_close;
	}
	TCM_Close();
	memcpy(&datalen, data, sizeof(uint32_t));
	
	/** Load shared keytree**/
	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	ret = tcs_utils_import_keytree_dirlocked((const char *)"s://",(unsigned char *)data + sizeof(uint32_t),datalen,1);
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
	goto out_free;
out_close:
	TCM_Close();
out_free:
	if(data) httc_free(data);
	return ret;

}

int tcs_set_private_keytree_storespace_index(uint32_t nvindex){


	int ret = 0;
	uint8_t filename[128];
	char *home = NULL;
	char *loginname = NULL;	

	home = getenv("HOME");
	loginname = getlogin();
	sprintf((char *)filename,"%s/%s/%s.nvinfo",home,HTTC_TSS_PRIV_PREFIX,loginname);

	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) return ret;
	ret = httc_util_file_write((const char *)filename, (const char *)&nvindex, sizeof(uint32_t));
    if (ret != sizeof(uint32_t)) {
       httc_util_pr_error(" Error writing nvinfo file\n");
	   tcs_util_sem_release (TCS_SEM_INDEX_KEY);
       	return TSS_ERR_WRITE;
    }
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
	return TSS_SUCCESS;	
}


int tcs_save_private_keytree(unsigned char *nvpasswd){

	int ret = 0;
	uint32_t *nvindex = NULL;
	uint8_t *buf = NULL;
	uint8_t *data = NULL;
	uint64_t datalen = 0;
	uint64_t indexlen = 0;
	uint8_t nvauth[DEFAULT_HASH_SIZE] = {0};
	uint8_t *comman = NULL;
	uint8_t *prifilename = NULL;
	uint8_t *nvinfofilename = NULL;
	char *pwd = NULL;
	char *loginname = NULL;
	char *home = NULL;

	if(nvpasswd == NULL) return TSS_ERR_PARAMETER;
	
	sm3 (nvpasswd, strlen ((const char *)nvpasswd), nvauth);
	TCM_setlog(0);

	if(NULL == (buf = httc_malloc(CMD_DEFAULT_ALLOC_SIZE)))
	{
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,CMD_DEFAULT_ALLOC_SIZE);
	
	comman = buf;
	prifilename = comman + 512;
	nvinfofilename = prifilename + 512;
	pwd = (char *)nvinfofilename + 512;
	
	memset(pwd,0, 512);  			
 	if(getcwd((char *)pwd,512) == NULL){
		ret = TSS_ERR_SHELL;
		goto out_free;
	}	
	
	home = getenv("HOME");
	loginname = getlogin();
	
	sprintf((char *)nvinfofilename,"%s/%s/%s.nvinfo",home,HTTC_TSS_PRIV_PREFIX,loginname);	

	
	/**Get nvindex**/
	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	nvindex = httc_util_file_read_full((const char *)nvinfofilename, (unsigned long *)&indexlen);
	if(indexlen != sizeof(uint32_t) || nvindex == NULL){
		httc_util_pr_error(" Reading nvinfo file len:%ld add:%p\n",(long int)indexlen,nvindex);
		//tcs_util_sem_release (TCS_SEM_INDEX_KEY);
        ret = TSS_ERR_READ;
		goto out_release;
	}
	//tcs_util_sem_release (TCS_SEM_INDEX_KEY);
	
	/**Get private_keytree data**/
	ret = tcs_utils_export_keytree_dirlocked((const char *)"p://", &data, (int *)&datalen);
	if(ret) goto out_release;
	
	if(0 != (ret = TCM_Open())) goto out_release;
	ret = TCM_NV_WriteValueAuth(*nvindex, 0, (unsigned char *)&datalen, sizeof(uint64_t), nvauth);
	if(ret != 0){
		httc_util_pr_error(" Error from NV_WriteValueAuth %s(%08X)\n", TCM_GetErrMsg(ret),ret);
		goto out_close;
	}
	
	ret = TCM_NV_WriteValueAuth(*nvindex, sizeof(uint64_t), data, (uint32_t)datalen, nvauth);
	if(ret != 0){
		httc_util_pr_error(" Error from NV_WriteValueAuth %s(%08X)\n", TCM_GetErrMsg(ret),ret);
		//goto out_close;
	}
out_close:
	TCM_Close();
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	if(buf) httc_free(buf);
	if(data) httc_free(data);
	if(nvindex) httc_free(nvindex);
	return ret;
}

int tcs_load_private_keytree(unsigned char *nvpasswd){
	uint32_t ret = 0;
	uint32_t *nvindex = NULL;
	uint64_t indexlen = 0;
	uint8_t *data = NULL;
	uint32_t nvlen = 0;
	uint64_t datalen = 0;
	uint8_t nvauth[DEFAULT_HASH_SIZE] = {0};
	uint32_t cap = TCM_CAP_NV_INDEX;
	uint8_t nvinfofilename[128];
	char *home = NULL;
	char *loginname = NULL;
	
	STACK_TCM_BUFFER(rep);
	STACK_TCM_BUFFER( ubcap );
	TCM_NV_DATA_PUBLIC np;
    STACK_TCM_BUFFER(tb);	
    ubcap.used= 4;
	if(nvpasswd == NULL) return TSS_ERR_PARAMETER;
	sm3 (nvpasswd, strlen ((const char *)nvpasswd), nvauth);
	TCM_setlog(0);	

	/**Get nvindex**/
	home = getenv("HOME");
	loginname = getlogin();
	sprintf((char *)nvinfofilename,"%s/%s/%s.nvinfo",home,HTTC_TSS_PRIV_PREFIX,loginname);

	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	nvindex = httc_util_file_read_full((const char *)nvinfofilename, (unsigned long *)&indexlen);
	if(nvindex == NULL || indexlen != sizeof(uint32_t)){
		httc_util_pr_error(" Reading nvinfo file\n");
        ret = TSS_ERR_READ;
		goto out_release;
	}
	if(0 != (ret = TCM_Open())) goto out_release;
	/** Get Datalength **/
	STORE32(ubcap.buffer, 0, *nvindex);
    ret = TCM_GetCapability(cap, &ubcap, &rep);
    if (0 != ret) {
	   httc_util_pr_error("TCM_GetCapability return %s.\n", TCM_GetErrMsg(ret));
	    goto out_close;
	}
	
    TSS_SetTCMBuffer(&tb, rep.buffer, rep.used);
    ret = TCM_ReadNVDataPublic(&tb, 0, &np);
    if ( ( ret & ERR_MASK) != 0) {
       httc_util_pr_error(" Coulnot serialsize the TCM_NV_DATA_PUBLIC structure.\n");
        goto out_close;
    }
	
	nvlen = (uint32_t)np.dataSize;
	if(NULL == (data = httc_malloc (nvlen))){
		httc_util_pr_error (" Req Alloc error!\n");
		ret = TSS_ERR_NOMEM;
		goto out_close;
	}
	
	/**Get private_keytree data **/
	ret = TCM_NV_ReadValueAuth(*nvindex, 0, nvlen, data, &nvlen, nvauth);
	if(ret != 0){
		httc_util_pr_error("Error from TCM_NV_ReadValueAuth %s\n", TCM_GetErrMsg(ret));
		//goto out_close;
	}	

	TCM_Close();
	//tcs_util_sem_release (TCS_SEM_INDEX_KEY);
	
	/** Create private keytree**/
	memcpy(&datalen, data, sizeof(uint64_t));	
	ret = tcs_utils_import_keytree_dirlocked((const char *)"p://",(unsigned char *)data + sizeof(uint64_t),datalen,1);
	goto out_release;
out_close:
	TCM_Close();
	//goto out_two;
out_release:
	tcs_util_sem_release(TCS_SEM_INDEX_KEY);
out_free:
	//TCM_Close();
	if(nvindex) httc_free(nvindex);
	if(data) httc_free(data);
	return ret;
}


/*
 * 导出密钥树
 * 可用于备份
 */
int tcs_export_keytree(const char *keypath,unsigned char **pbuffer,int *obuf_len){

	int ret = 0;
	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) return ret;
	ret = tcs_utils_export_keytree_dirlocked(keypath,pbuffer,obuf_len);
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
	return ret; 
}

/*
 * 导入密钥树
 * 可恢复备份
 */
int tcs_import_keytree(const char *keypath,unsigned char *pbuffer,int buf_len){

	int ret = 0;

	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) return ret;	
	if(0 != (ret = TCM_Open())){
		tcs_util_sem_release (TCS_SEM_INDEX_KEY);
		return ret;
	};
	ret = tcs_utils_import_keytree_dirlocked(keypath,pbuffer,buf_len,1);
	TCM_Close();
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
	return ret; 
}

/*
 * 	读取密钥树
 */
int tcs_read_keytree(const char *keypath,struct key_node **node,unsigned int level){

	int n = 0;
	int ret = 0;
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	unsigned int actlevel = level;

	if(NULL == (buf = httc_malloc(2*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		return TSS_ERR_NOMEM;
	}
	memset(buf,0,2*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	key_name = (unsigned char **)(buf + CMD_DEFAULT_ALLOC_SIZE);

	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	ret = tcs_utils_analysis_keypath((unsigned char *)keypath, key_name, &number,(unsigned char *) cur_key_path);
	if(ret) goto out_release;
	strncat((char *)cur_key_path,(const char *)keypath + USED_PATH,strlen((const char *)keypath) - USED_PATH);
	ret = tcs_utils_get_node_number((char *)cur_key_path,&n);
	if(ret) goto out_release;
	
	if (NULL == (*node = (struct key_node *)httc_malloc (sizeof(struct key_node) + (n+1)*8*(sizeof(char*))))){
		httc_util_pr_error (" Req Alloc error!\n");
		ret =  TSS_ERR_NOMEM;
		goto out_release;
	}
	/**Get actual name**/
	memset(*node,0,sizeof(struct key_node) + (n+1)*8*(sizeof(char*)));
	if(number){
		memcpy((*node)->name,key_name[number - 1],strlen((const char *)key_name[number - 1]));
	}else{
		memcpy((*node)->name,cur_key_path,strlen((const char *)cur_key_path));
	}
	(*node)->children_number = n;
	actlevel -= 1;
	/** loop get node**/
	ret = tcs_utils_read_dir((char *)cur_key_path, *node, &actlevel);
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);	
	if(buf) httc_free(buf);
	if(ret && *node) tcs_free_keynode(node,1);
	return ret;
}

/*
 *	释放密钥节点内存
 */
int tcs_free_keynode(struct key_node **node,int recurive){

	int i = 0;
	int n = (*node)->children_number;
	
	if(node == NULL) return TSS_ERR_PARAMETER;

	struct key_node *curnode = *node;
	while(1){
//		httc_util_pr_error("inumberrecurive\n",i,n,recurive);
		if(recurive && n && curnode->children[i]){
			tcs_free_keynode(&(curnode->children[i]), recurive);
			i++;
			n--;
		}else{
//			httc_util_pr_error("httc_free name\n",curnode->name);
			if(curnode->policy.process_or_role){
				httc_free(curnode->policy.process_or_role);
				curnode->policy.process_or_role = NULL;
			}
			
			if(curnode){
				httc_free(curnode);
				curnode = NULL;
			}
			
			break;
		}
	}
	
	return TSS_SUCCESS;
}

/*
  *  删除密钥树
 */
int tcs_delete_keytree(const char *keypath){

	int ret = 0;
	
	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) return ret;
	ret = tcs_utils_delete_keytree(keypath);	
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);	
	return ret;
}


/*
 *	准备认证数据
 */
int tcs_get_migrate_auth(unsigned char **auth, int *auth_length){

	int ret = 0;
	int number = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	uint8_t keyauth[DEFAULT_HASH_SIZE] = {0};
	
	uint8_t *keyblobpath = NULL;
	unsigned char *keyblob = NULL;
	uint64_t bloblen = 0;
		
	if(auth == NULL || auth_length == NULL) return TSS_ERR_PARAMETER;
	
	if(NULL == (buf = httc_malloc(CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	keyblobpath = buf + CMD_DEFAULT_ALLOC_SIZE/4;
	key_name = (unsigned char **)(keyblobpath + CMD_DEFAULT_ALLOC_SIZE/2);
	
	/** Create migratable_key**/
	NODEAUTH(keyauth);
	
	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath((unsigned char *)"s://KeyForMigrate", key_name, &number,(unsigned char *) cur_key_path))) {
		goto out_release;
	}
	if(0 != (ret = TCM_Open())) goto out_release;
	if(0 != (ret = tcs_utils_tree_key_create_tcmlocked(KEY_TYPE_SM2_128, MIGRATE_KEY, keyauth, key_name,number, cur_key_path, NULL, 0,INSIDE_KEY,UNMIGRATABLE_KEY))) {
		TCM_Close();
		goto out_release;
	}
	TCM_Close();

	/**Get migrata key blob**/
	sprintf((char *)keyblobpath ,"%sKeyForMigrate/KeyForMigrate.key",sharepath);	
	keyblob = httc_util_file_read_full((const char *)keyblobpath,(unsigned long *)&bloblen);
	if(keyblob == NULL){
		httc_util_pr_error("Read data fail! (%s)",keyblobpath);
		ret = TSS_ERR_WRITE;
		goto out_release;
	}	
	/**Create migratable_data**/	
	if(NULL == (*auth = httc_malloc(bloblen))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_release;
	}
	memcpy(*auth, keyblob, bloblen);
	*auth_length = bloblen;
	ret = tcs_utils_delete_keytree((const char *)"s://KeyForMigrate");	
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);	
	if(buf) httc_free(buf);
	if(keyblob) httc_free(keyblob);
	return ret;
}

int tcs_emigrate_keytree(const char *keypath, unsigned char *passwd,	unsigned char *ownerpass, unsigned char *auth, int authlength,unsigned char **pbuffer,int *obuf_len){
	
	int ret = 0;
	int number = 0;
	int usedlen = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	struct key_info *info = NULL;
	uint32_t infolen;
	uint32_t namelen = 0;
	unsigned char *keytree = NULL;
	unsigned char *encblob = NULL;
	unsigned char *rnblob = NULL;
	unsigned char *outblob = NULL;
	uint32_t keytreelength = 0;	
    uint32_t encblen = 0;	
    uint32_t rnblen = 256;
    uint32_t outblen = 256;
	uint32_t phandle = 0;
	uint32_t out_length = 0;
	char * migkeyfilename = NULL;
	
	uint8_t mauth[DEFAULT_HASH_SIZE] = {0};
	uint8_t pauth[DEFAULT_HASH_SIZE] = {0};
	uint8_t ownerauth[DEFAULT_HASH_SIZE] = {0};
	
	keydata migkey;
	keydata authkey;
	STACK_TCM_BUFFER(keybuf);
	STACK_TCM_BUFFER(keyblob);
	STACK_TCM_BUFFER(migkeybuffer);

	if(keypath == NULL || pbuffer == NULL || obuf_len == NULL || auth == NULL || ownerpass == NULL) return TSS_ERR_PARAMETER;

	if(NULL == (buf = httc_malloc(3*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,3*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	migkeyfilename = (char *)cur_key_path + CMD_DEFAULT_ALLOC_SIZE;
	key_name = (unsigned char **)(migkeyfilename  + CMD_DEFAULT_ALLOC_SIZE);	
	encblob = (unsigned char *)migkeyfilename + CMD_DEFAULT_ALLOC_SIZE + CMD_DEFAULT_ALLOC_SIZE/4;
	rnblob = encblob + CMD_DEFAULT_ALLOC_SIZE/4;
	outblob = rnblob + CMD_DEFAULT_ALLOC_SIZE/4;
	
	TCM_setlog(0);
	if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	if(0 != (ret = tcs_utils_analysis_keypath((unsigned char *)keypath, key_name, &number,(unsigned char *) cur_key_path))) {
		goto out_release;
	}
	
	/**Create migrate auth**/	
    SET_TCM_BUFFER(&keybuf, auth, authlength);
    memset(&authkey, 0x0, sizeof(keydata));
    if (authlength != TSS_KeyExtract(&keybuf, 0, &authkey)) {
		httc_util_pr_error("Could not get auth key(%d).\n",authlength);
		ret = TSS_ERR_PARAMETER;
        goto out_release;
    }	
	ret = TCM_WritePubKeyData(&keyblob, &authkey);
    if ( ( ret & ERR_MASK ) != 0 ) {
        httc_util_pr_error("Could not serialize key.\n");
        goto out_release;
    }
	
	sm3(ownerpass,strlen((const char *)ownerpass),ownerauth);
	if(0 != (ret = TCM_Open())) goto out_release;
	ret = TCM_AuthorizeMigrationKey(ownerauth, TCM_MS_MIGRATE, &keyblob, &migkeybuffer);
	if(ret){
		httc_util_pr_error("AuthorizeMigrationKey returned '%s' (0x%x).\n", TCM_GetErrMsg(ret), ret);
		goto out_close;
	}

	/**Get parenthandle and migratehandle**/
	if( number == 0){
		httc_util_pr_error("Path error %s .\n", keypath);
		ret = TSS_ERR_NOT_SUPPORT;
		goto out_close;
	}
	else if(number == 1){
		phandle = SMK_HANDLE;
		strncat((char *)cur_key_path,(const char *)key_name[number - 1],strlen((const char *)key_name[number - 1]));
		strncat((char *)cur_key_path,"//",1);
	}else{
		if(0 != (ret = tcs_utils_tree_key_achieve_tcmlocked(TCM_SM4KEY_STORAGE, key_name, number - 1, cur_key_path, &phandle))) {
			goto out_close;
		}
		strncat((char *)cur_key_path,(const char *)key_name[number - 1],strlen((const char *)key_name[number - 1]));
		strncat((char *)cur_key_path,"//",1);
	}
	
	/**Get pauth and mauth**/
	sprintf(migkeyfilename,"%s%s.info",cur_key_path,key_name[number - 1]);
	ret = TCM_ReadFile((const char *)migkeyfilename, (unsigned char **)&info, &infolen);
	if(ret){
       httc_util_pr_error(" Coulnot read keyinfo from file.\n");
		ret = TSS_ERR_READ;
		goto out_close;
    }
	
	if(info->migratable != MIGRATABLE_KEY){
		ret = TSS_ERR_PARAMETER;
		goto out_close;
	}

	NODEAUTH(pauth);
	if(info->attribute == LEAF_KEY){
		if(0 != (ret = tcs_utils_get_policy_passwd(cur_key_path, key_name[number -1], passwd, mauth))) {
			goto out_close;
		}

	}else{
		NODEAUTH(mauth);
	}

	/**Get migrate key**/
	memset(migkeyfilename,0,CMD_DEFAULT_ALLOC_SIZE);	
	sprintf(migkeyfilename,"%s%s.key",cur_key_path,key_name[number - 1]);
//	printf("key:%s\n",migkeyfilename);
	ret = TCM_ReadKeyfile(migkeyfilename,&migkey);
	if(ret){
       httc_util_pr_error(" Coulnot reakey from file.\n");
		ret = TSS_ERR_READ;
		goto out_close;
     }
	
	if(migkey.encData.size > CMD_DEFAULT_ALLOC_SIZE/2){
		httc_util_pr_error(" migkey.encData too long %d.\n",migkey.encData.size);
		ret = TSS_ERR_OUTPUT_EXCEED;
		goto out_close;

	}	
	memcpy(encblob, migkey.encData.buffer, migkey.encData.size);	
    encblen = migkey.encData.size;

	/**Create migrate authorization data**/	
	TCM_setlog(0);
	
//	httc_util_dump_hex((const char *)"migkeybuffer.buffer",auth,authlength);
//	httc_util_dump_hex((const char *)"encblob",encblob,encblen);	
	ret = TCM_CreateMigrationBlob(phandle, pauth, mauth, TCM_MS_MIGRATE, migkeybuffer.buffer, migkeybuffer.used,
                                     encblob, encblen, rnblob, &rnblen, outblob,&outblen);
	if(ret){
		 httc_util_pr_error("CreateMigrationBlob returned '%s' (%d).\n",
                   TCM_GetErrMsg(ret),
                   ret);
		 TCM_Close();
		 goto out_release;
	}
	TCM_Close();

	ret = tcs_utils_export_keytree_dirlocked(keypath,&keytree,(int *)&keytreelength);
	if(ret){
		httc_util_pr_error("tcs_export_keytree error.\n");
		goto out_release;
	}
	//release
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
	
	namelen = strlen((const char *)key_name[number - 1]);
	out_length = rnblen + outblen + 6*sizeof(uint32_t) + namelen + keytreelength + authlength;	
	if(NULL == (*pbuffer = httc_malloc(out_length))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	
	memcpy((*pbuffer + usedlen),&out_length,sizeof(uint32_t));
	usedlen += sizeof(uint32_t);
	memcpy((*pbuffer + usedlen),&rnblen,sizeof(uint32_t));
 	usedlen += sizeof(uint32_t);
	memcpy((*pbuffer + usedlen),rnblob,rnblen);
 	usedlen += rnblen;
	memcpy((*pbuffer + usedlen),&outblen,sizeof(uint32_t));
 	usedlen += sizeof(uint32_t);
	memcpy((*pbuffer + usedlen),outblob,outblen);
 	usedlen += outblen;	
	memcpy((*pbuffer + usedlen),&namelen,sizeof(uint32_t));
 	usedlen += sizeof(uint32_t);
	memcpy((*pbuffer + usedlen),key_name[number - 1],namelen);
 	usedlen += namelen;
	memcpy((*pbuffer + usedlen),&authlength,sizeof(uint32_t));
 	usedlen += sizeof(uint32_t);
	memcpy((*pbuffer + usedlen),auth,authlength);
 	usedlen += authlength;
	memcpy((*pbuffer + usedlen),&keytreelength,sizeof(uint32_t));
 	usedlen += sizeof(uint32_t);
	memcpy((*pbuffer + usedlen),keytree,keytreelength);	
	
	*obuf_len = out_length;
	goto out_free;
out_close:
	TCM_Close();
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:

	while (number--) if(key_name[number]) httc_free(key_name[number]);	
	if(buf) httc_free(buf);
	if(info) free(info);
	if(keytree) httc_free(keytree);
	return ret;	
}

/*
 * 迁入密钥树
 */
int tcs_immigrate_keytree(const char *keypath, unsigned char *pbuffer, int buf_len){

	int ret = 0;
	int err = 0;
	int number = 0;
	int usedlen = 0;
	uint8_t *buf = NULL;
	uint8_t *cur_key_path = NULL;
	unsigned char **key_name = NULL;
	unsigned char *keyblob = NULL;
	unsigned char *rnblob = NULL;
	unsigned char *outblob = NULL;
	unsigned char *filename = NULL;
	unsigned char *cur_key_name = NULL;
	unsigned char *import_path = NULL;
	uint32_t cur_key_name_len = 0;
	uint32_t keytreelength = 0;
	uint32_t keyblen = CMD_DEFAULT_ALLOC_SIZE/4;
    uint32_t rnblen = CMD_DEFAULT_ALLOC_SIZE/4;   
    uint32_t outblen = CMD_DEFAULT_ALLOC_SIZE/4;	
	uint32_t phandle = 0;
	uint32_t mhandle = 0;
	uint32_t in_len = 0;
//	uint64_t mhandlelength = 0;
	uint8_t mauth[DEFAULT_HASH_SIZE];
	uint8_t pauth[DEFAULT_HASH_SIZE];

	keydata key;
	STACK_TCM_BUFFER( buffer );
	keydata migkey;
	STACK_TCM_BUFFER( migbuffer );
	unsigned char *migblob = NULL;
	uint32_t migbloblen = 0;

	if(keypath == NULL || pbuffer == NULL || buf_len < 0) return TSS_ERR_PARAMETER;

	if(NULL == (buf = httc_malloc(4*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error(" Malloc error\n");
		ret = TSS_ERR_NOMEM;
		goto out_free;
	}
	memset(buf,0,4*CMD_DEFAULT_ALLOC_SIZE);
	
	cur_key_path = buf;
	filename = cur_key_path + CMD_DEFAULT_ALLOC_SIZE;
	key_name = (unsigned char **)(filename + CMD_DEFAULT_ALLOC_SIZE);
	keyblob = filename + CMD_DEFAULT_ALLOC_SIZE + CMD_DEFAULT_ALLOC_SIZE/4;
	rnblob = keyblob + CMD_DEFAULT_ALLOC_SIZE/4;
	outblob = rnblob + CMD_DEFAULT_ALLOC_SIZE/4;
	cur_key_name = outblob + CMD_DEFAULT_ALLOC_SIZE/2;
	import_path = cur_key_name + CMD_DEFAULT_ALLOC_SIZE/4;
	migblob = import_path + CMD_DEFAULT_ALLOC_SIZE/4;
	
	/**Key	immigration**/
	memcpy(&in_len,pbuffer + usedlen,sizeof(uint32_t));
	usedlen += sizeof(uint32_t);
	if(buf_len != in_len){
		httc_util_pr_error("Buffer data error\n");
		ret = TSS_ERR_PARAMETER;
		goto out_free;
	}
	memcpy(&rnblen,pbuffer + usedlen,sizeof(uint32_t));
	usedlen += sizeof(uint32_t);
	memcpy(rnblob,pbuffer + usedlen,rnblen);
	usedlen += rnblen;
	memcpy(&keyblen,pbuffer + usedlen,sizeof(uint32_t));
 	usedlen += sizeof(uint32_t);
	memcpy(keyblob,pbuffer + usedlen,keyblen);
 	usedlen += keyblen;
	memcpy(&cur_key_name_len,pbuffer + usedlen,sizeof(uint32_t));
 	usedlen += sizeof(uint32_t);
	memcpy(cur_key_name,pbuffer + usedlen,cur_key_name_len);
 	usedlen += cur_key_name_len;
	memcpy(&migbloblen,pbuffer + usedlen, sizeof(uint32_t));
	usedlen += sizeof(uint32_t);
	memcpy(migblob,pbuffer + usedlen, migbloblen);
	usedlen += migbloblen;
	memcpy(&keytreelength,pbuffer + usedlen,sizeof(uint32_t));
 	usedlen += sizeof(uint32_t);	
	
	/**Get migratehandle**/
	sm3(smkpasswd,strlen((const char *)smkpasswd),pauth);
	sm3(smkpasswd,strlen((const char *)smkpasswd),mauth);

	SET_TCM_BUFFER(&buffer, migblob, migbloblen);
    TSS_KeyExtract(&buffer, 0, &migkey);
    if(0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_KEY))) goto out_free;
	TCM_setlog(0);
	if(0 != (ret = TCM_Open())) goto out_release;
	if (0 != (ret = TCM_LoadKey(SMK_HANDLE, pauth, &migkey, &mhandle))){
		httc_util_pr_error("TCM_LoadKey return error '%s' (%d).\n", TCM_GetErrMsg(ret), ret);
		goto out_close;
	}
	
	/**Get new parenthandle**/

	if(0 != (ret = tcs_utils_analysis_keypath((unsigned char *)keypath, key_name, &number,(unsigned char *)cur_key_path))) {
		goto out_close;
	}
	if(number == 0){
		phandle = SMK_HANDLE;
	}else if(number > 0){
		if(0 != (ret = tcs_utils_tree_key_create_tcmlocked(KEY_TYPE_SM4_128, STORE_KEY, pauth, key_name, number, cur_key_path, &phandle, 0,INSIDE_KEY,UNMIGRATABLE_KEY))) {
			goto out_close;
		}
	}else{
		httc_util_pr_error(" Path error %s\n",keypath);
		ret = TSS_ERR_PARAMETER;
		goto out_close;
	}	
	
	TCM_setlog(0);
	ret = TCM_ConvertMigrationBlob(phandle, mhandle, pauth, mauth, rnblob,
                                   rnblen, keyblob, keyblen, outblob, &outblen);
	if(ret){
		 httc_util_pr_error("ConvertMigrationBlob returned '%s' (0x%x).\n", TCM_GetErrMsg(ret), ret);
		goto out_close;

	}
	/**Create key three**/
	if(number > 0){
		sprintf((char *)import_path,"%s/%s",keypath,cur_key_name);  
	}else{
		import_path = (unsigned char *)keypath;
	}
	//path_check = 0;
	ret = tcs_utils_import_keytree_dirlocked((const char *)import_path,pbuffer + usedlen,keytreelength,0);
	if(ret){
		httc_util_pr_error("tcs_utils_import_keytree_dirlocked error.\n");
		goto out_close;
	}
	
	/**Save keyblob**/
	memset(filename,0,CMD_DEFAULT_ALLOC_SIZE);
//	printf("cur_key_name:%s cur_key_path:%s \n",cur_key_name,cur_key_path);
	sprintf((char *)filename, "%s%s/%s.key", cur_key_path, cur_key_name,cur_key_name);

	ret = TCM_ReadKeyfile((const char *)filename,&key);
	if(ret){
       httc_util_pr_error(" Coulnot readkey from file (%s).\n",filename);
		ret = TSS_ERR_READ;
		err = tcs_utils_delete_keytree((const char *)import_path);
		if(err){
			httc_util_pr_error("Recovery error 0x%04X",err);
		}
        goto out_close;
    }
	
	STACK_TCM_BUFFER(keybuf);	
	memcpy(key.encData.buffer,  outblob, outblen);
	key.encData.size = outblen;	
	keyblen = TCM_WriteKey(&keybuf, &key);
	
	memset(filename,0,CMD_DEFAULT_ALLOC_SIZE);	
	sprintf((char *)filename, "%s%s/%s.key", cur_key_path, cur_key_name,cur_key_name);	
	ret = httc_util_file_write((const char *)filename, (const char *)keybuf.buffer, (unsigned int)keyblen);
	if(ret != keyblen){
		httc_util_pr_error(" Writing file fail!\n");
		ret = TSS_ERR_WRITE;
		err = tcs_utils_delete_keytree((const char *)import_path);
		if(err){
			httc_util_pr_error("Recovery error 0x%04X",err);
		}
		goto out_close;
	}
	
	/** Save pubkey **/	
	memset(filename,0,CMD_DEFAULT_ALLOC_SIZE);
	sprintf((char *)filename, "%s%s/%s.pub", cur_key_path, cur_key_name,cur_key_name);
	ret = httc_util_file_write((const char *)filename, (const char *)key.pub.pubKey.modulus, 
															(unsigned int)key.pub.pubKey.keyLength);
	if(ret != key.pub.pubKey.keyLength){
		httc_util_pr_error(" Writing file fail!\n");
		ret = TSS_ERR_WRITE;
		err = tcs_utils_delete_keytree((const char *)import_path);
		if(err){
			httc_util_pr_error("Recovery error 0x%04X",err);
		}
		goto out_close;
	}
	ret = TSS_SUCCESS;
out_close:
	TCM_Close();
out_release:
	tcs_util_sem_release (TCS_SEM_INDEX_KEY);
out_free:
	while (number--) if(key_name[number]) httc_free(key_name[number]);	
	if(buf) httc_free(buf);
	return ret;	
                                   
}
