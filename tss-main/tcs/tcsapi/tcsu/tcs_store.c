#include <stdio.h>
#include <string.h>
#include <sys/types.h>    
#include <sys/stat.h>
#include <mcheck.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h> 

#include "sm3.h"
#include "tcm.h"
#include "tcmfunc.h"
#include "tcm_error.h"

#include "file.h"
#include "sys.h"
#include "mem.h"
#include "debug.h"
#include "convert.h"

#include "tcs.h"
#include "uutils.h"
#include "transmit.h"
#include "tcs_config.h"
#include "tpcm_command.h"
#include "tcs_constant.h"
#include "tcs_attest.h"
#include "tcs_store.h"
#include "tcs_error.h"

#ifndef NO_TSB
#include <tsbapi/tsb_measure_user.h>
#endif

#define AUTH_TO_SAVE 0
#define SAVE_TO_AUTH 1
#define DEFAULT_NAME_INDEX 0x00020000
#define MAX_NV_INDEX 0xFFFFFF
#define MAX_USER_OR_GROUP_ID 65535
#define NV_PATH HTTC_TSS_CONFIG_PATH"nvinfo"

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

struct nv_save_info{
	uint32_t index;
	int size;	
	char name[MAX_NV_NAME_SIZE];
	unsigned int policy_flags;
	unsigned int user_or_group;
	uint64_t prlength;
	uint8_t data[0];
};

typedef struct{
	COMMAND_HEADER;
	uint32_t uiIndex;
	uint32_t uiDatalen;
	uint32_t uiPasswdlen;
	uint8_t  uaData[0];
}tcs_req_save_mem_data;

typedef struct{
	COMMAND_HEADER;
	uint32_t uiIndex;
	uint32_t uiPasswdlen;
	uint8_t  uaData[0];
}tcs_req_read_mem_data;

typedef struct{
	RESPONSE_HEADER;
	uint32_t uiDatalen;
	uint8_t  uaData[0];
}tcs_rsp_read_mem_data;
#pragma pack(pop)

//static const char *nv_version_path=(const char *)HTTC_TSS_CONFIG_PATH"nv.version";

static int tcs_utils_nv_info_convert(struct nv_info *act_info, struct nv_save_info **act_save_info, int *length, int flag){

	int info_length = 0;
	
	if(flag == AUTH_TO_SAVE){
		if(act_info->auth_policy.process_or_role) info_length = strlen((const char *)act_info->auth_policy.process_or_role) + 1;
		
		if(NULL == (*act_save_info = (struct nv_save_info *)httc_malloc(info_length + sizeof(struct nv_save_info) ))){
			httc_util_pr_error("httc_malloc error\n");
			return TSS_ERR_NOMEM;
		}
		memset(*act_save_info,0,sizeof(struct nv_save_info) + info_length );		
		
		(*act_save_info)->index = act_info->index;
		(*act_save_info)->size = act_info->size;
		memcpy((*act_save_info)->name,act_info->name,MAX_NV_NAME_SIZE);
		(*act_save_info)->policy_flags = act_info->auth_policy.policy_flags;
		(*act_save_info)->user_or_group = act_info->auth_policy.user_or_group;

		if(act_info->auth_policy.process_or_role){
			(*act_save_info)->prlength = strlen((const char *)act_info->auth_policy.process_or_role) + 1;
			memcpy((*act_save_info)->data,act_info->auth_policy.process_or_role,(*act_save_info)->prlength);
		}
				
		if(length) *length = (*act_save_info)->prlength + sizeof(struct nv_save_info);
		return 0;

	}
	if(flag == SAVE_TO_AUTH){
		memset(act_info,0,sizeof(struct nv_info));
		act_info->index = (*act_save_info)->index;
		act_info->size = (*act_save_info)->size;
		memcpy(act_info->name,(*act_save_info)->name,MAX_NV_NAME_SIZE);
		act_info->auth_policy.policy_flags = (*act_save_info)->policy_flags;
		act_info->auth_policy.user_or_group = (*act_save_info)->user_or_group;		

		if((*act_save_info)->prlength){
			if(NULL == (act_info->auth_policy.process_or_role = httc_malloc((*act_save_info)->prlength))){
				httc_util_pr_error("httc_malloc error\n");
				return TSS_ERR_NOMEM;
			}
			memset(act_info->auth_policy.process_or_role,0,(*act_save_info)->prlength);
			memcpy(act_info->auth_policy.process_or_role,(*act_save_info)->data,(*act_save_info)->prlength);
		}
		if(length) *length = sizeof(struct nv_save_info) + (*act_save_info)->prlength ;
	}
	
	return TSS_SUCCESS;	
}

static int tcs_utils_get_nv_info(uint32_t *info_index,const char *name, uint32_t index ,struct nv_save_info **act_save_info){
	int ret = 0;
	uint32_t length = 0;
	uint32_t uselen = 0;
	uint32_t info_length = 0;
	FILE *fp = NULL;
	char *data = NULL;
	struct nv_save_info *curnv = NULL;	
	struct stat nvstat;
	
	char *nvfilename = NV_PATH;
	
	if( 0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_NV))) goto out;
	fp = fopen(nvfilename,"r");
	if(fp == NULL){ 
		httc_util_pr_error("Open file error %s\n",nvfilename);
		ret = TSS_ERR_FILE;
		goto out;
	}
	
	stat(nvfilename, &nvstat);
	length = (uint32_t)nvstat.st_size;

	if(length == 0 ){
		httc_util_pr_error("[%s:%d] NV file does not exist or does not match\n", __func__, __LINE__);
		ret = TSS_ERR_FILE;
		goto out;
	}
	
	if(NULL == (data = httc_malloc(length))){
		httc_util_pr_error("[%s:%d] Malloc error\n", __func__, __LINE__);
		ret = TSS_ERR_NOMEM; 
		goto out;
	}
	
	ret = fread(data,1,length,fp);
	if(ret != length){
		httc_util_pr_error("ret:%d length:%d\n",ret,length);
		ret = TSS_ERR_WRITE;
		goto out;
	}

	do{
		curnv = (struct nv_save_info *)(data + uselen);
		if(name){
			if(!strcmp(curnv->name,name)){
				if(info_index) *info_index = curnv->index;
				if((curnv->policy_flags != -1 )&& act_save_info != NULL){
					info_length = curnv->prlength + sizeof(struct nv_save_info) ;
					if(NULL == (*act_save_info = (struct nv_save_info *)httc_malloc(info_length))){
						httc_util_pr_error("httc_malloc error\n");
						ret = TSS_ERR_NOMEM;
						goto out;
					}
					memset(*act_save_info,0,info_length);
					memcpy(*act_save_info,curnv,info_length);
				}
				ret = TSS_SUCCESS;
				goto out;
			}
		}else{
			if(curnv->index == index){
				if(info_index) *info_index = curnv->index;
				if((curnv->policy_flags != -1 ) && act_save_info != NULL){
					info_length = curnv->prlength + sizeof(struct nv_save_info) ;
					if(NULL == (*act_save_info = (struct nv_save_info *)httc_malloc(info_length))){
						httc_util_pr_error("httc_malloc error\n");
						ret = TSS_ERR_NOMEM;
						goto out;
					}
					memset(*act_save_info,0,info_length);
					memcpy(*act_save_info,curnv,info_length);
				}
				ret = TSS_SUCCESS;
				goto out;
			}
		}
		uselen += sizeof(struct nv_save_info);
		uselen += curnv->prlength;		
	}while(uselen < length);
	
	ret = TSS_ERR_PARAMETER;
out:
	tcs_util_sem_release (TCS_SEM_INDEX_NV);
	if(fp) fclose(fp);
	if(data) httc_free(data);
	return ret;	

}
static int tcs_utils_nv_info_list_delete(uint32_t index){

	int ret = 0;
	int check = 0;
	uint32_t length = 0;
	uint32_t uselen = 0;
	uint32_t curlen = 0;
	FILE *fp = NULL;
	char *oldinfo = NULL;
	char *newinfo = NULL;
	struct nv_save_info *curnv = NULL;	
	struct stat nvstat;
	char *nvfilename = NV_PATH;	

	if( 0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_NV))) return ret;
	fp = fopen(nvfilename,"r+");
	if(fp == NULL){
		ret = TSS_ERR_FILE;
		goto out;
	}
	
	stat(nvfilename, &nvstat);
	length = (uint32_t)nvstat.st_size;	
	if(length == 0) goto out;
	
	if(NULL == (oldinfo = httc_malloc(length))){
		printf("[%s:%d] Malloc error\n", __func__, __LINE__);
		ret = TSS_ERR_NOMEM; 
		goto out;
	}
	
	ret = fread(oldinfo,1,length,fp);
	if(ret != length){
		ret = TSS_ERR_WRITE;
		goto out;
	}
	if(fp){
		fclose(fp);
		fp = NULL;
	}
	
	do{
		curnv = (struct nv_save_info *)(oldinfo + uselen);
		curlen = sizeof(struct nv_save_info) + curnv->prlength ; 		
		if(curnv->index == index){
			//printf("length:%d tlength:%d curlen:%d\n",length,uselen + curlen,curlen);
			if(NULL == (newinfo = httc_malloc(length))){
				printf("[%s:%d] Malloc error\n", __func__, __LINE__);
				ret = TSS_ERR_NOMEM; 
				goto out;
			}
			check = 1;
			memcpy(newinfo,oldinfo,uselen);
			if(length != uselen + curlen) memcpy(newinfo + uselen,oldinfo + uselen + curlen,length - uselen - curlen);
			length -= curlen;
			break;
		}
		uselen += curlen;
		
	}while(uselen < length);
	
	if(check){
		fp = fopen(nvfilename,"w");
		if(fp == NULL) {
			ret = TSS_ERR_FILE;
			goto out;
		}
		ret = fwrite(newinfo,1,length,fp);
		if(ret != length){
			ret = fwrite(oldinfo,1,length + curlen,fp);
			ret = TSS_ERR_WRITE;
			goto out;
		}
	}
	ret = TSS_SUCCESS;
out:
	tcs_util_sem_release (TCS_SEM_INDEX_NV);
	if(fp) fclose(fp);
	if(oldinfo) httc_free(oldinfo);
	if(newinfo) httc_free(newinfo);
	return ret;	
}

static int tcs_utils_nv_info_list_add(uint8_t *data, uint32_t len){

	int ret = 0;	
	FILE *fp = NULL;
	char *nvfilename = NV_PATH;

	if(access((const char *)HTTC_TSS_CONFIG_PATH,0)!=0)
			mkdir((const char *)HTTC_TSS_CONFIG_PATH, 0777);

	if( 0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_NV))) return ret;
	fp = fopen(nvfilename,"a");
	if(fp == NULL) {
		tcs_util_sem_release (TCS_SEM_INDEX_NV);
		return TSS_ERR_FILE;
	}

	httc_util_system_args("chmod 0666 %s",nvfilename);
	//printf("Writing data length %d\n",len);
	//sleep(1);
	ret = fwrite(data,1,len,fp);	
	if(ret != len){
		printf("ret:%d length:%d\n",ret,len);
		fclose(fp);
		tcs_util_sem_release (TCS_SEM_INDEX_NV);
		return TSS_ERR_WRITE; 
	}

	fclose(fp);
	tcs_util_sem_release (TCS_SEM_INDEX_NV);
	return TSS_SUCCESS;	
}


#ifndef NO_TSB
static int tcs_utils_policy_passwd(struct auth_policy *policy,unsigned char *passwd){
	
	int ret = 0;
	sm3_context ctx;
	sm3_init (&ctx);

	/**Check whether the policy meets the specification**/
	if((policy->policy_flags & POLICY_FLAG_USER_ID && policy->policy_flags & POLICY_FLAG_GROUP_ID) ||
#
	  (policy->policy_flags & POLICY_FLAG_PROCESS_IDENTITY && policy->policy_flags & POLICY_FLAG_PROCESS_ROLE) ||
	  ((policy->policy_flags & POLICY_FLAG_USER_ID || policy->policy_flags & POLICY_FLAG_GROUP_ID) && policy->user_or_group > MAX_USER_OR_GROUP_ID) || 
	  ((policy->policy_flags & POLICY_FLAG_PROCESS_IDENTITY || policy->policy_flags& POLICY_FLAG_PROCESS_ROLE) && strlen((const char *)policy->process_or_role) > MAX_NAME_LENGTH)){
		httc_util_pr_error("Error policy.\n");
		return TSS_ERR_PARAMETER;
	 }

	sm3_update (&ctx, (const unsigned char *)&(policy->policy_flags), sizeof(unsigned int));
	if(policy->policy_flags & POLICY_FLAG_USER_ID || policy->policy_flags & POLICY_FLAG_GROUP_ID)
		sm3_update (&ctx, (const unsigned char *)&(policy->user_or_group), sizeof(unsigned int));
	if(policy->policy_flags & POLICY_FLAG_PROCESS_IDENTITY || policy->policy_flags & POLICY_FLAG_PROCESS_ROLE)		
		sm3_update (&ctx, (const unsigned char *)policy->process_or_role , strlen((const char *)policy->process_or_role) + 1);	
	if(policy->policy_flags & POLICY_FLAG_USED_PASSWD)		
		sm3_update (&ctx, (const unsigned char *)policy->password, strlen((const char *)policy->password) + 1);
	sm3_finish (&ctx, passwd);
	
	return ret;	
}
#endif

static int tcs_utils_get_policy_passwd(const char *name, uint32_t index, unsigned char *passwd, unsigned char *auth, uint32_t *act_index){
	

	__attribute__((unused))	 int ret = 0 ;
	__attribute__((unused))	 struct nv_save_info *act_save_info = NULL;

	uint8_t process_or_role[MAX_PROCESS_NAME_LENGTH] = {0};
	int process_length = MAX_PROCESS_NAME_LENGTH;
	uid_t uid = -1;
	gid_t gid = -1;

	sm3_context ctx;
	struct nv_info act_info;


//#ifndef platform_2700
	ret = tcs_utils_get_nv_info(act_index,name,index,&act_save_info);
	if(ret && name != 0) return ret;
//else try no save info .
//#endif
#ifndef NO_TSB
	if(act_save_info){
		ret = tcs_utils_nv_info_convert(&act_info, &act_save_info, NULL,SAVE_TO_AUTH);
		if(ret){
			if(act_save_info) httc_free(act_save_info);
			return ret;
		}
		//ret = tcs_utils_policy_passwd(&(act_info.auth_policy), auth);
		sm3_init (&ctx);
		
		if (act_info.auth_policy.policy_flags & POLICY_FLAG_ENV){
			if (0 != (ret = tsb_measure_kernel_memory_all ())){
				httc_util_pr_error ("tcs_util_tsb_measure_env error: %d(0x%x)\n", ret, ret);
				ret =  TSS_ERR_ADMIN_AUTH;
				return ret;
			}
		}
		sm3_update (&ctx, (const unsigned char *)&(act_info.auth_policy.policy_flags), sizeof(unsigned int));
		if(act_info.auth_policy.policy_flags & POLICY_FLAG_USER_ID ){
#ifndef TSS_DEBUG
			uid = getuid();
			sm3_update (&ctx, (const unsigned char *)&(uid), sizeof (uid_t));
#else
			sm3_update (&ctx, (const unsigned char *)&(act_info.auth_policy.user_or_group), sizeof (unsigned int));
#endif
		}else if( act_info.auth_policy.policy_flags & POLICY_FLAG_GROUP_ID){
#ifndef TSS_DEBUG
			gid = getgid();
			sm3_update (&ctx, (const unsigned char *)&(gid), sizeof (gid_t));
#else
			sm3_update (&ctx, (const unsigned char *)&(act_info.auth_policy.user_or_group), sizeof (unsigned int));
#endif
		}
		
		
#ifndef TSS_DEBUG
		if(act_info.auth_policy.policy_flags & POLICY_FLAG_PROCESS_IDENTITY){
			ret = tsb_get_process_identity(process_or_role,&process_length);
			if(ret){
				httc_util_pr_error("Error tsb_get_process_identity %d\n",ret);
				ret =  TSS_ERR_ADMIN_AUTH;
				return ret;
			}
			
			sm3_update (&ctx, (const unsigned char *)process_or_role, process_length);
		}else if(act_info.auth_policy.policy_flags & POLICY_FLAG_PROCESS_ROLE){
			if(!tsb_is_role_member((const unsigned char *)act_info.auth_policy.process_or_role)){
				httc_util_pr_error("Error tsb_is_role_member %s\n",act_info.auth_policy.process_or_role);
				ret =  TSS_ERR_ADMIN_AUTH;
				return ret;
			}
			sm3_update (&ctx, (const unsigned char *)act_info.auth_policy.process_or_role, strlen((const char *)act_info.auth_policy.process_or_role) + 1);
		}
#else
		if(act_info.auth_policy.policy_flags & POLICY_FLAG_PROCESS_IDENTITY || act_info.auth_policy.policy_flags & POLICY_FLAG_PROCESS_ROLE){
            sm3_update (&ctx, (const unsigned char *)act_info.auth_policy.process_or_role , strlen((const char *)act_info.auth_policy.process_or_role) + 1);
		}
#endif

		if(act_info.auth_policy.policy_flags & POLICY_FLAG_USED_PASSWD){			
			if(!passwd){
				httc_util_pr_error("Passwd is null.\n");
				if(act_save_info) httc_free(act_save_info);
				if(act_info.auth_policy.process_or_role) httc_free(act_info.auth_policy.process_or_role);
				return TSS_ERR_PARAMETER;
			}
			
			sm3_update (&ctx, (const unsigned char *)passwd, strlen((const char *)passwd) + 1);	
		}
		sm3_finish (&ctx, auth);
		
		if(act_save_info) httc_free(act_save_info);
		if(act_info.auth_policy.process_or_role) httc_free(act_info.auth_policy.process_or_role);
	}else
#endif
	{
		if(!passwd){
			httc_util_pr_error("Passwd is null.\n");
			return TSS_ERR_PARAMETER;
		}
		sm3 (passwd,strlen((const char *)passwd),auth);	
	}	
	return TSS_SUCCESS;	
}

int tcs_is_nv_index_defined(uint32_t index){

	int ret = 0;
	uint32_t cap = TCM_CAP_NV_INDEX;
	STACK_TCM_BUFFER(resp);
	STACK_TCM_BUFFER( subcap );
	
	STORE32(subcap.buffer, 0, index);
    subcap.used = 4;			
	TCM_setlog(0);
	/** Get Datalength **/
	if(0 != (ret = TCM_Open())) return ret;
    ret = TCM_GetCapability(cap, &subcap, &resp);
    if(ret == TCM_BADINDEX){
		TCM_Close();
		return 0;
	}
	if(ret){
	    httc_util_pr_error("TCM_GetCapability returned %s.\n",
	           TCM_GetErrMsg(ret));
		TCM_Close();
	    return 1;
	}
	TCM_Close();
	return 1;
}


int tcs_is_nv_name_defined(const char *name){
	int ret = 0;
	char *nvfilename = NV_PATH;
	struct stat nvstat;

	nvstat.st_size = 0;
	stat(nvfilename, &nvstat);

	if(nvstat.st_size == 0) return 0;
	
	ret = tcs_utils_get_nv_info(NULL,name,0,NULL);
	if(!ret) return 1;
	if(ret == TSS_ERR_PARAMETER)return 0;
	return ret;
}

static int tcs_utils_nv_define_space(uint32_t index, int size,	unsigned char *ownerpasswd,unsigned char *nvauth, uint32_t policy_flags){
	
	int ret = 0;
	int i = 0;
	int pcr_number = 0;
	uint32_t status = 0;
	uint8_t *ownerauth = NULL;
	uint8_t owauth[DEFAULT_HASH_SIZE] = {0};
	TCM_PCR_COMPOSITE pcrComp;
	TCM_PCR_INFO_SHORT pcrInfoRead;
	TCM_PCR_INFO_SHORT pcrInfoWrite;
	
	uint32_t permissions = TCM_NV_PER_AUTHREAD | TCM_NV_PER_AUTHWRITE;	

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

	ret = tcs_is_nv_index_defined(index);
	if(ret && size){
		httc_util_pr_error("Index recreate: %d\n",index);
		return TSS_ERR_RECREATE;
	}else if(!ret && !size){
		httc_util_pr_error("no space\n");
		return TSS_SUCCESS;	
	}

	sm3 (ownerpasswd,strlen((const char *)ownerpasswd),owauth);
	ownerauth = owauth;

	TCM_setlog(0);
	if(0 != (ret = TCM_Open())) return ret;
	
	memset(&pcrInfoRead, 0x0, sizeof(pcrInfoRead));	
	memset(&pcrInfoWrite, 0x0, sizeof(pcrInfoWrite));
	memset(&pcrComp, 0x0, sizeof(pcrComp));	
	
	pcrInfoRead.localityAtRelease = TCM_LOC_ZERO;
	pcrInfoRead.pcrSelection.sizeOfSelect = 4;
    if(policy_flags & POLICY_FLAG_TRUST_BIOS_OR_FIRMWARE){
	   pcrInfoRead.pcrSelection.pcrSelect[PCR_TYPE_BIOS >> 3] |= (1 << (PCR_TYPE_BIOS & 0x7));
	   pcr_number++;
    }
	if(policy_flags & POLICY_FLAG_TRUST_BOOTLOADER){
	   pcrInfoRead.pcrSelection.pcrSelect[PCR_TYPE_BOOTLOADER >> 3] |= (1 << (PCR_TYPE_BOOTLOADER & 0x7));
	   pcr_number++;
    }
	if(policy_flags & POLICY_FLAG_TRUST_KERNEL){
	   pcrInfoRead.pcrSelection.pcrSelect[PCR_TYPE_KERNAL >> 3] |= (1 << (PCR_TYPE_KERNAL & 0x7));
	   pcr_number++;
    }
	if(policy_flags & POLICY_FLAG_TRUST_BOOT){
	   pcrInfoRead.pcrSelection.pcrSelect[PCR_TYPE_BOOT_ALL >> 3] |= (1 << (PCR_TYPE_BOOT_ALL & 0x7));
	   pcr_number++;
    }
	if(policy_flags & POLICY_FLAG_TRUST_DMEASURE){
		pcrInfoRead.pcrSelection.pcrSelect[PCR_TYPE_DMEASURE >> 3] |= (1 << (PCR_TYPE_DMEASURE & 0x7));
		pcr_number++;
	}
	if(policy_flags & POLICY_FLAG_TRUST_APP_LOAD){
	   pcrInfoRead.pcrSelection.pcrSelect[PCR_TYPE_APP_LOAD>> 3] |= (1 << (PCR_TYPE_APP_LOAD & 0x7));
	   pcr_number++;
    }
	/*
	if(policy_flags & POLICY_FLAG_TRUST_INIT_ROOT){
		pcrInfoRead.pcrSelection.pcrSelect[PCR_TYPE_INIT_ROOT >> 3] |= (1 << (PCR_TYPE_INIT_ROOT & 0x7));
		pcr_number++;
	}
	if(policy_flags & POLICY_FLAG_TRUST_BOOT_CONFIG){
		pcrInfoRead.pcrSelection.pcrSelect[PCR_TYPE_BOOT_CONFIG >> 3] |= (1 << (PCR_TYPE_BOOT_CONFIG & 0x7));
		pcr_number++;
	}
	*/

    pcrComp.select.sizeOfSelect = 4;
    pcrComp.pcrValue.size = pcr_number * TCM_HASH_SIZE;
	

	/*
     * Get pcr hash.
     */	
     if(pcr_number){
	 	
	 	pcrComp.pcrValue.buffer  = httc_malloc(pcrComp.pcrValue.size);
		if(pcrComp.pcrValue.buffer == NULL){
			httc_util_pr_error (" Req Alloc error!\n");
			ret = TSS_ERR_NOMEM;
			goto out;
		}
		
		if(policy_flags & POLICY_FLAG_TRUST_BIOS_OR_FIRMWARE){
			pcrComp.select.pcrSelect[PCR_TYPE_BIOS >> 3] |= (1 << (PCR_TYPE_BIOS & 0x7));
			ret = TCM_PcrRead(PCR_TYPE_BIOS,(unsigned char *)pcrComp.pcrValue.buffer + i*TCM_HASH_SIZE);
			if(ret){
				httc_util_pr_error (" TCM_PcrRead error 0x%08X!\n",ret);
				if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
				goto out;
			}
			i++;
		}
		if(policy_flags & POLICY_FLAG_TRUST_BOOTLOADER){
			pcrComp.select.pcrSelect[PCR_TYPE_BOOTLOADER >> 3] |= (1 << (PCR_TYPE_BOOTLOADER & 0x7));
			ret = TCM_PcrRead(PCR_TYPE_BOOTLOADER,(unsigned char *)pcrComp.pcrValue.buffer + i*TCM_HASH_SIZE);
			if(ret){
				httc_util_pr_error (" TCM_PcrRead error 0x%08X!\n",ret);
				if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
				goto out;
			}
			i++;
		}
		if(policy_flags & POLICY_FLAG_TRUST_KERNEL){
			pcrComp.select.pcrSelect[PCR_TYPE_KERNAL >> 3] |= (1 << (PCR_TYPE_KERNAL & 0x7));
			ret = TCM_PcrRead(PCR_TYPE_KERNAL,(unsigned char *)pcrComp.pcrValue.buffer + i*TCM_HASH_SIZE);
			if(ret){
				httc_util_pr_error (" TCM_PcrRead error 0x%08X!\n",ret);
				if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
				goto out;
			}
			i++;
		}
		if(policy_flags & POLICY_FLAG_TRUST_BOOT){
			pcrComp.select.pcrSelect[PCR_TYPE_BOOT_ALL >> 3] |= (1 << (PCR_TYPE_BOOT_ALL & 0x7));
			ret = TCM_PcrRead(PCR_TYPE_BOOT_ALL,(unsigned char *)pcrComp.pcrValue.buffer + i*TCM_HASH_SIZE);
			if(ret){
				httc_util_pr_error (" TCM_PcrRead error 0x%08X!\n",ret);
				if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
				goto out;
			}
			i++;
		}
		if(policy_flags & POLICY_FLAG_TRUST_DMEASURE){
			pcrComp.select.pcrSelect[PCR_TYPE_DMEASURE >> 3] |= (1 << (PCR_TYPE_DMEASURE & 0x7));
			ret = TCM_PcrRead(PCR_TYPE_DMEASURE,(unsigned char *)pcrComp.pcrValue.buffer + i*TCM_HASH_SIZE);
			if(ret){
				httc_util_pr_error (" TCM_PcrRead error 0x%08X!\n",ret);
				if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
				goto out;
			}
			i++;
		}
		if(policy_flags & POLICY_FLAG_TRUST_APP_LOAD){
			pcrComp.select.pcrSelect[PCR_TYPE_APP_LOAD >> 3] |= (1 << (PCR_TYPE_APP_LOAD & 0x7));
			ret = TCM_PcrRead(PCR_TYPE_APP_LOAD,(unsigned char *)pcrComp.pcrValue.buffer + i*TCM_HASH_SIZE);
			if(ret){
				httc_util_pr_error (" TCM_PcrRead error 0x%08X!\n",ret);
				if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
				goto out;
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
				goto out;
			}
			i++;
		}
		if(policy_flags & POLICY_FLAG_TRUST_BOOT_CONFIG){
			pcrComp.select.pcrSelect[PCR_TYPE_BOOT_CONFIG >> 3] |= (1 << (PCR_TYPE_BOOT_CONFIG & 0x7));
			ret = TCM_PcrRead(PCR_TYPE_BOOT_CONFIG,(unsigned char *)pcrComp.pcrValue.buffer + i*TCM_HASH_SIZE);
			if(ret){
				httc_util_pr_error (" TCM_PcrRead error 0x%08X!\n",ret);
				if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
				goto out;
			}
			i++;
		}
		*/

		for (i = 0; i < sizeof(pcrInfoRead.pcrSelection.pcrSelect); i++)
			httc_util_pr_dev ("pcrInfoRead.PcrAtRelease.pcrSelect[%d]: 0x%x\n", i, pcrInfoRead.pcrSelection.pcrSelect[i]);
		for (i = 0; i < sizeof(pcrComp.select.pcrSelect); i++)
			httc_util_pr_dev ("pcrComp.select.pcrSelect[%d]: 0x%x\n", i, pcrComp.select.pcrSelect[i]);
		httc_util_dump_hex ("pcrComp.pcrValue.buffer", (unsigned char *)pcrComp.pcrValue.buffer, pcr_number*TCM_HASH_SIZE);
		
		TCM_HashPCRComposite(&pcrComp, pcrInfoRead.digestAtRelease);
		if(pcrComp.pcrValue.buffer) httc_free(pcrComp.pcrValue.buffer);
    }
	 
	memcpy(&pcrInfoWrite,&pcrInfoRead,sizeof(TCM_PCR_INFO_SHORT));
	/** Definespace **/
	ret = TCM_NV_DefineSpace2(ownerauth, index, size,
					permissions, nvauth, &pcrInfoRead, &pcrInfoWrite);
	if (0 != ret) {
		printf("ret =%d\r\n",ret);
		printf("Got error '%s' from TCM_NV_DefineSpace2().\n", TCM_GetErrMsg(ret));
	}
out:
	 TCM_Close();
	return ret;

}

static int tcs_utils_get_random(void){

		int number = DEFAULT_NAME_INDEX;		
		int i = 0;
		struct timeval tv;
		pthread_t tid;
		int arg[10] = {0};
		
		tid = pthread_self();

		gettimeofday(&tv,NULL);
		arg[0] = tv.tv_usec;
		arg[1] = tv.tv_sec;
		for(i = 2; i < 10 ; i++){
			arg[i] = tid + i;
 		}
		gettimeofday(&tv,NULL);
		number = arg[tv.tv_usec%10];		
		if(number < 0) number = number * -1;
		number = number > MAX_NV_INDEX ? ((number >> (tv.tv_sec%16)) & MAX_NV_INDEX) : number;
		
		while(tcs_is_nv_index_defined(number)){
			number ++;
		}		
		httc_util_pr_info("random number :%d\n",number);
		return number;
}


int tcs_nv_define_space(uint32_t index, int size,	unsigned char *ownerpasswd,unsigned char *usepasswd){

	int ret = 0;
	int err = 0;
	uint8_t *nvauth = NULL;
	uint8_t auth[DEFAULT_HASH_SIZE] = {0};
	struct nv_save_info info;
	
	if(size < 0 ) return TSS_ERR_PARAMETER;
	
	if(usepasswd){
		sm3 (usepasswd,strlen((const char *)usepasswd),auth);
		nvauth = auth;
	}
	
	ret = tcs_utils_nv_define_space(index,size,ownerpasswd,nvauth,0);
	if(ret) return ret;
	
	memset(&info,0,sizeof(struct nv_save_info));	
	info.index = index;
	info.size = size;
	info.policy_flags = -1;
	ret = tcs_utils_nv_info_list_add((uint8_t *)&info,sizeof(struct nv_save_info));
	if(ret){
		err = tcs_utils_nv_define_space(index,0,ownerpasswd,NULL,0);
		if(err){
			httc_util_pr_error("Recovery error 0x%04X",err);
		}
		return ret;
	}
	
	return ret;
}

/*
 * 	根据策略定义非易失存储空间 */
#ifdef NO_TSB
int tcs_nv_define_space_on_policy(		uint32_t index, int size,	unsigned char *ownerpasswd,
															struct auth_policy *policy){
	index = index;
	size = size;
	ownerpasswd = ownerpasswd;
	policy = policy;
	return TSS_ERR_NOT_SUPPORT;
}
#else
int tcs_nv_define_space_on_policy(		uint32_t index, int size,	unsigned char *ownerpasswd,
															struct auth_policy *policy){
	int ret = 0;
	struct nv_info nvinfo;
	struct nv_save_info *snvinfo = NULL;
	int length = 0;
	int err = 0;
	uint8_t *nvauth = NULL;
	uint8_t passwd[DEFAULT_HASH_SIZE] = {0};

	if(policy == NULL || size < 0 ) return TSS_ERR_PARAMETER;
	
	memset(&nvinfo,0,sizeof(struct nv_info));

	if(tcs_is_nv_index_defined(index)) return TSS_ERR_RECREATE;


	ret = tcs_utils_policy_passwd(policy, passwd);
	if(ret) return ret;
	nvauth = passwd;
	//httc_util_dump_hex((const char *)"nv nvauth", nvauth, DEFAULT_HASH_SIZE);
	//sleep(1);
	ret = tcs_utils_nv_define_space(index,size,ownerpasswd,nvauth,policy->policy_flags);
	if(ret) return ret;
	
	nvinfo.index = index;
	nvinfo.size = size;
	nvinfo.auth_policy.policy_flags = policy->policy_flags;
	nvinfo.auth_policy.user_or_group = policy->user_or_group;
	nvinfo.auth_policy.process_or_role = policy->process_or_role;
	nvinfo.auth_policy.password = policy->password;

	ret = tcs_utils_nv_info_convert(&nvinfo, &snvinfo, &length, AUTH_TO_SAVE);
	if(ret){ 
		err = tcs_utils_nv_define_space(index,0,ownerpasswd,NULL,0);
		if(err){
			httc_util_pr_error("Recovery error 0x%04X",err);
		}
		goto out;
	}
	ret = tcs_utils_nv_info_list_add((uint8_t *)snvinfo,length);
	if(ret){
		err = tcs_utils_nv_define_space(index,0,ownerpasswd,NULL,0);
		if(err){
			httc_util_pr_error("Recovery error 0x%04X",err);
		}
		goto out;
	}

out:	
	if(snvinfo) httc_free(snvinfo);
	return ret;
}
#endif

int tcs_nv_define_named_space(const char *name,int size,
		unsigned char *ownerpasswd,unsigned char *usepasswd){

		int ret = 0;
		int err = 0;
		int name_index = DEFAULT_NAME_INDEX;
		struct nv_save_info nvinfo;
		uint8_t *nvauth = NULL;
		uint8_t passwd[DEFAULT_HASH_SIZE] = {0};
		memset(&nvinfo,0,sizeof(struct nv_save_info));
		err += 0;

		if(name == NULL || size < 0 ) return TSS_ERR_PARAMETER;		
		if(strlen(name) > MAX_NV_NAME_SIZE) return TSS_ERR_INPUT_EXCEED;
		if(tcs_is_nv_name_defined(name)) return TSS_ERR_RECREATE;

		if(usepasswd){
			sm3 (usepasswd,strlen((const char *)usepasswd),passwd);
			nvauth = passwd;
		}

		while(1){		
			while(1){
				ret = tcs_is_nv_index_defined(name_index);
				if(ret){
					name_index = tcs_utils_get_random();
					continue;
				}else if(!ret){
						break;		
					}			
			}

			ret = tcs_utils_nv_define_space(name_index,size,ownerpasswd,nvauth,0);
			if(ret == TSS_ERR_RECREATE) continue;
			if(ret == 0) break;
			if(ret) return ret;
		}
		nvinfo.index = name_index;
		nvinfo.size = size;
		nvinfo.policy_flags = -1;
		memcpy(nvinfo.name,name,strlen(name));
		
		ret = tcs_utils_nv_info_list_add((uint8_t *)&nvinfo,sizeof(nvinfo));
		if(ret) {
			err = tcs_utils_nv_define_space(name_index,0,ownerpasswd,NULL,0);
			if(err){
				httc_util_pr_error("Recovery error 0x%04X",err);
			}
			return ret;
		}
		
		return ret;
}

/*
 *	根据策略定义有名字的非易失存储空间	会建立名字与索引的映射关系 */
#ifdef NO_TSB
int tcs_nv_define_named_space_on_policy(const char *name,	int size,unsigned char *ownerpasswd,
														struct auth_policy *policy){
	name = name;
	size = size;
	ownerpasswd = ownerpasswd;
	policy = policy;
	return TSS_ERR_NOT_SUPPORT;
}
#else
int tcs_nv_define_named_space_on_policy(const char *name,	int size,unsigned char *ownerpasswd,
														struct auth_policy *policy){

	int ret = 0;
	int name_index = DEFAULT_NAME_INDEX;
	int err = 0;
	struct nv_info nvinfo;
	struct nv_save_info *snvinfo = NULL;
	int length = 0;
	uint8_t *nvauth = NULL;
	uint8_t passwd[DEFAULT_HASH_SIZE] = {0};
	err += 0;
	memset(&nvinfo,0,sizeof(struct nv_info));

	if(policy == NULL || name == NULL || size < 0 ) return TSS_ERR_PARAMETER;
	if(strlen(name) > MAX_NV_NAME_SIZE) return TSS_ERR_INPUT_EXCEED;
	if(tcs_is_nv_name_defined(name)) return TSS_ERR_RECREATE;
	
	ret = tcs_utils_policy_passwd(policy, passwd);
	if(ret) return ret;
	nvauth = passwd;
	
	while(1){		
		while(1){
			ret = tcs_is_nv_index_defined(name_index);
			if(ret){
				name_index = tcs_utils_get_random();
				continue;
			}else if(!ret){
					break;		
				}			
		}

		ret = tcs_utils_nv_define_space(name_index,size,ownerpasswd,nvauth,policy->policy_flags);
		if(ret == TSS_ERR_RECREATE) continue;
		if(ret == 0) break;
		if(ret) return ret;
	}
	
	nvinfo.index = name_index;
	nvinfo.size = size;
	memcpy(nvinfo.name,name,strlen(name));
	nvinfo.auth_policy.policy_flags = policy->policy_flags;
	nvinfo.auth_policy.user_or_group = policy->user_or_group;
	nvinfo.auth_policy.process_or_role = policy->process_or_role;
	nvinfo.auth_policy.password = policy->password;
	
	ret = tcs_utils_nv_info_convert(&nvinfo, &snvinfo, &length, AUTH_TO_SAVE);
	if(ret){ 
		err = tcs_utils_nv_define_space(name_index,0,ownerpasswd,NULL,0);
		if(err){
			httc_util_pr_error("Recovery error 0x%04X",err);
		}
		goto out;
	}
	ret = tcs_utils_nv_info_list_add((uint8_t *)snvinfo,length);
	if(ret){
		err = tcs_utils_nv_define_space(name_index,0,ownerpasswd,NULL,0);
		if(err){
			httc_util_pr_error("Recovery error 0x%04X",err);
		}
		goto out;
	}	
out:
	if(snvinfo) httc_free(snvinfo);
	return ret;

}
#endif		

int tcs_nv_delete_space(uint32_t index,unsigned char *ownerpasswd){

	int ret = 0;
	ret = tcs_utils_nv_define_space(index,0,ownerpasswd,NULL,0);
	if(ret) return ret;
	ret = tcs_utils_nv_info_list_delete(index);
	return ret;
}


int tcs_nv_delete_named_space(const char *name,unsigned char *ownerpasswd){

	int ret = 0;
	uint32_t index = 0;

	if(ownerpasswd == NULL || name == NULL ) return TSS_ERR_PARAMETER;
	if(0 == (ret = tcs_is_nv_name_defined(name))) return TSS_SUCCESS;	
	if(0 != (ret = tcs_utils_get_nv_info(&index,name,0,NULL))) return ret;

	ret = tcs_utils_nv_define_space(index,0,ownerpasswd,NULL,0);
	if(ret) return ret;

	ret = tcs_utils_nv_info_list_delete(index);
	return ret;
}


int tcs_nv_write(uint32_t index,int length,unsigned char *data,unsigned char *usepasswd){

	uint32_t ret = 0;
	uint8_t nvauth[DEFAULT_HASH_SIZE] = {0};

	if(data == NULL || length < 0 ) return TSS_ERR_PARAMETER;
	
	ret = tcs_utils_get_policy_passwd(NULL, index, usepasswd, nvauth, NULL);
	if(ret) return ret;
	
	TCM_setlog(0);
	if(0 != (ret = TCM_Open())) return ret;
	//httc_util_dump_hex((const char *)"nv nvauth", nvauth, DEFAULT_HASH_SIZE);
	//sleep(1);
	/** Write Data **/
	ret = TCM_NV_WriteValueAuth(index, 0, data, length, nvauth);
	if(ret != 0){
		printf("ret =%d\r\n",ret);
		printf("Error %s from NV_WriteValueAuth\n", TCM_GetErrMsg(ret));		
	}
	TCM_Close();
	return ret;
}

int tcs_nv_named_write(const char *name,int length,unsigned char *data,unsigned char *usepasswd){

	int ret = 0;
	uint32_t index = 0;	
	uint8_t nvauth[DEFAULT_HASH_SIZE] = {0};

	if(name == NULL || data == NULL || length < 0) return TSS_ERR_PARAMETER;

	ret = tcs_utils_get_policy_passwd(name, 0, usepasswd, nvauth, &index);
	if(ret) return ret;

	TCM_setlog(0);
	if(0 != (ret = TCM_Open())) return ret;
	/** Write Data **/	
	ret = TCM_NV_WriteValueAuth(index, 0, data, length, nvauth);
	if(ret != 0){
		printf("ret =%d\r\n",ret);
		printf("Error %s from NV_WriteValueAuth\n", TCM_GetErrMsg(ret));
	}
	TCM_Close();
	return ret;
}

int tcs_nv_read(uint32_t index,int *length_inout,unsigned char *data,unsigned char *usepasswd){

	uint32_t ret = 0;
	uint32_t cap = TCM_CAP_NV_INDEX;
	STACK_TCM_BUFFER(resp);
	STACK_TCM_BUFFER( subcap );
	TCM_NV_DATA_PUBLIC ndp;
    STACK_TCM_BUFFER(tb);

	uint8_t nvauth[DEFAULT_HASH_SIZE] = {0};

	if(data == NULL || length_inout == NULL || *length_inout < 0) return TSS_ERR_PARAMETER;

	ret = tcs_utils_get_policy_passwd(NULL, index, usepasswd, nvauth, NULL);
	if(ret) return ret;
	
	TCM_setlog(0);
	if(0 != (ret = TCM_Open())) return ret;
	
	STORE32(subcap.buffer, 0, index);
    subcap.used = 4;			
	
	/** Get Datalength **/
    ret = TCM_GetCapability(cap, &subcap, &resp);
    if (0 != ret) {
	    printf("TCM_GetCapability returned %s.\n",
	           TCM_GetErrMsg(ret));
	    goto out;
	}
	
    TSS_SetTCMBuffer(&tb, resp.buffer, resp.used);
    ret = TCM_ReadNVDataPublic(&tb, 0, &ndp);
    if ( ( ret & ERR_MASK) != 0) {
        printf("Could not deserialize the TCM_NV_DATA_PUBLIC structure.\n");
        goto out;
    }
	if(*length_inout < (int)ndp.dataSize) {
		ret = TSS_ERR_OUTPUT_EXCEED;
		goto out;
	}
	*length_inout = (*length_inout < (unsigned int)ndp.dataSize)? *length_inout : (unsigned int)ndp.dataSize;

	/** Read Data **/
	ret = TCM_NV_ReadValueAuth(index, 0, *length_inout, data, (uint32_t *)length_inout, nvauth);
	if(ret != 0){
		printf("Error %s from TCM_NV_ReadValueAuth\n",
	    TCM_GetErrMsg(ret));
	}

out:

	 TCM_Close();
	return ret;

}

int tcs_nv_named_read(const char *name,int *length_inout,unsigned char *data,unsigned char *usepasswd){

	int ret = 0;
	uint32_t index = 0;
	uint32_t cap = TCM_CAP_NV_INDEX;
	STACK_TCM_BUFFER(resp);
	STACK_TCM_BUFFER( subcap );
	TCM_NV_DATA_PUBLIC ndp;
    STACK_TCM_BUFFER(tb);
	uint8_t nvauth[DEFAULT_HASH_SIZE] = {0};

	if(name == NULL || length_inout == NULL || data == NULL || *length_inout < 0) return TSS_ERR_PARAMETER;

	ret = tcs_utils_get_policy_passwd(name, 0, usepasswd, nvauth, &index);
	if(ret) return ret;
	TCM_setlog(0);
	if(0 != (ret = TCM_Open())) return ret;
	
	STORE32(subcap.buffer, 0, index);
    subcap.used = 4;			
	
	/** Get Datalength **/
    ret = TCM_GetCapability(cap, &subcap, &resp);
    if (0 != ret) {
		TCM_Close();
	    printf("TCM_GetCapability returned %s.\n",
	           TCM_GetErrMsg(ret));
	    return ret;
	}
	
    TSS_SetTCMBuffer(&tb, resp.buffer, resp.used);
    ret = TCM_ReadNVDataPublic(&tb, 0, &ndp);
    if ( ( ret & ERR_MASK) != 0) {
		TCM_Close();
        printf("Could not deserialize the TCM_NV_DATA_PUBLIC structure.\n");
        return ret;
    }
	if(*length_inout < (int)ndp.dataSize) {
		ret = TSS_ERR_OUTPUT_EXCEED;
		goto out;
	}
	*length_inout = (*length_inout < (unsigned int)ndp.dataSize)? *length_inout : (unsigned int)ndp.dataSize;
	
	/** Read Data **/
	ret = TCM_NV_ReadValueAuth(index, 0, *length_inout, data, (uint32_t *)length_inout, nvauth);
	if(ret != 0){
		TCM_Close();
		printf("Error %s from TCM_NV_ReadValueAuth\n",
	    TCM_GetErrMsg(ret));
	}
out:
	TCM_Close();
	return ret;
}

int tcs_read_nv_list(struct nv_info **array,int *number){
	
	int i = 0;
	int ret = 0;	
	uint32_t length = 0;
	uint32_t uselen = 0;
	uint32_t curlen = 0;
	
	uint8_t *buf = NULL;
	struct nv_info info;
	struct nv_info *infos = NULL;
	struct nv_info *curinfo = NULL;
	struct nv_save_info *cursinfo = NULL;
	
	FILE *fp = NULL;	
	struct stat nvstat;
	char *nvfilename = NV_PATH;

	if(array == NULL || number == NULL ) return TSS_ERR_PARAMETER;

	if(access((const char *)HTTC_TSS_CONFIG_PATH,0)!=0)
			mkdir((const char *)HTTC_TSS_CONFIG_PATH, 0755);

	if( 0 != (ret = tcs_util_sem_get (TCS_SEM_INDEX_NV))) goto out;
	if(access((const char *)nvfilename,0)!=0){
			fp = fopen(nvfilename,"a");
			if(fp) fclose(fp);
			fp = NULL;			
	}

	fp = fopen(nvfilename,"r");
	if(fp == NULL) return TSS_ERR_FILE;	
	stat(nvfilename, &nvstat);
	length = (uint32_t)nvstat.st_size;	
			
	if(NULL == (buf = httc_malloc(length))){
		printf("[%s:%d] Malloc error.\n", __func__, __LINE__);
		ret = TSS_ERR_NOMEM; 
		goto out;
	}	
	
	ret = fread(buf,1,length,fp);
	if(ret != length){
		ret = TSS_ERR_WRITE;
		goto out;
	}
#ifdef TSS_DEBUG	
	ret = httc_util_file_write("nvinfos", (const char *)buf, (unsigned int)length);
#endif
	
	while(uselen < length){
		cursinfo = (struct nv_save_info *)((uint8_t *)buf + uselen);
		ret = tcs_utils_nv_info_convert(&info,&cursinfo,(int *)&curlen,SAVE_TO_AUTH);
		if(info.auth_policy.process_or_role){
			httc_free(info.auth_policy.process_or_role);
		}
		uselen += curlen;		
		i++;
	}
	
	if(NULL == (infos = (struct nv_info *)httc_malloc(i * sizeof(struct nv_info)))){
		printf("[%s:%d] Malloc error.\n", __func__, __LINE__);
		ret = TSS_ERR_NOMEM; 
		goto out;
	}
//	httc_util_dump_hex((const char *)"nv list", buf, length);
	uselen = 0;
	i = 0;
	while(uselen < length){
		curinfo = infos + i;
		cursinfo = (struct nv_save_info *)((uint8_t *)buf + uselen);
		ret = tcs_utils_nv_info_convert(curinfo,&cursinfo,(int *)&curlen,SAVE_TO_AUTH);
		curinfo->auth_policy.password = NULL;				
		uselen += curlen;		
		i++;
	}
	*array = infos;
	*number = i;
	ret = TSS_SUCCESS;

out:
	tcs_util_sem_release (TCS_SEM_INDEX_NV);
	if(fp) fclose(fp);
	if(buf) httc_free(buf);
	return ret;

}

/*
 * 	释放NV信息内存
 */
void tcs_free_nv_list(struct nv_info *array,int number){
	if(array){
		while(number --){
			if((array + number)->auth_policy.process_or_role)
				httc_free((array + number)->auth_policy.process_or_role);
		}
		httc_free(array);				
	}	
}

/*
 * 	设置nv信息列表
 */
int tcs_set_nv_list(struct nv_info *array,int number){

	 int ret = 0;
	 int i = 0;
	 int curlen = 0;
	 struct nv_save_info *act_save_info = NULL;

	 if(array == NULL || number < 0) return TSS_ERR_PARAMETER;
	 
	 while(i < number){
	 	ret = tcs_utils_nv_info_convert(array + i, &act_save_info, &curlen, AUTH_TO_SAVE);
		if(ret) goto out;
//		printf("len:%d\n",curlen);
	 	ret = tcs_utils_nv_info_list_add((uint8_t *)act_save_info,curlen);
		if(ret) goto out;
		if(act_save_info) httc_free(act_save_info);
		act_save_info = NULL;
		i++;
	 }	 
out:
	 if(act_save_info) httc_free(act_save_info);
	 return ret;
}




/*
 * 保存易失数据
 */
int tcs_save_mem_data(uint32_t index, int length, unsigned char *data, char *usepasswd){

	int ret = 0;	
	uint8_t *cmd = NULL;
	uint32_t op = 0;
	uint32_t cmdlen = 0;
	uint32_t total_length = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE;
	tcs_req_save_mem_data *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if(data == NULL || usepasswd == NULL || strlen((const char *)usepasswd) < 8 ||  strlen((const char *)usepasswd) > 32)  return TSS_ERR_PARAMETER;

	total_length = rspLen + length + sizeof(tcs_req_save_mem_data) + HTTC_ALIGN_SIZE(strlen((const char *)usepasswd),4);
	if (NULL == (cmd = httc_malloc (total_length))){
		printf ("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	req = (tcs_req_save_mem_data *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + (total_length - rspLen));

	req->uiIndex = htonl(index);
	req->uiDatalen = htonl(length);
	req->uiPasswdlen = htonl((uint32_t)strlen((const char *)usepasswd));
	memcpy(req->uaData,data,length);
	op = HTTC_ALIGN_SIZE(length,4);
	memcpy(req->uaData + op,usepasswd,strlen((const char *)usepasswd));
	op += HTTC_ALIGN_SIZE(strlen((const char *)usepasswd),4);
	
	cmdlen = sizeof(tcs_req_save_mem_data) + op;
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_SaveMemData);
	
	if (0 != (ret = tpcm_transmit (cmd, cmdlen, rsp, &rspLen))) goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		printf ("[%s:%d] Invalid tpcm rsp tag(0x%02X)\n", __func__, __LINE__, tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	
	ret = tpcmRspRetCode (rsp);	

out:
	if(cmd) httc_free(cmd);
	return ret;	
	

}

/*
 * 读取易失数据
 */
int tcs_read_mem_data(uint32_t index, int *length_inout, unsigned char *data, char *usepasswd){

	int ret = 0;	
	uint8_t *cmd = NULL;
	uint32_t op = 0;
	uint32_t cmdlen = CMD_DEFAULT_ALLOC_SIZE;
	int rspLen = 0;
	uint32_t length = 0;
	tcs_req_read_mem_data *req = NULL;
	tcs_rsp_read_mem_data *rsp = NULL;

	if(data == NULL || usepasswd == NULL || length_inout == NULL ||
		strlen((const char *)usepasswd) < 8 ||  strlen((const char *)usepasswd) > 32)  return TSS_ERR_PARAMETER;
	
	length = *length_inout + cmdlen + sizeof(tcs_rsp_read_mem_data);
	
	if (NULL == (cmd = httc_malloc (length))){
		printf ("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	req = (tcs_req_read_mem_data *)cmd;
	rsp = (tcs_rsp_read_mem_data *)(cmd + cmdlen);

	req->uiIndex = htonl(index);
	req->uiPasswdlen = htonl((uint32_t)strlen((const char *)usepasswd));
	memcpy(req->uaData,usepasswd,strlen((const char *)usepasswd));
	op = HTTC_ALIGN_SIZE (strlen((const char *)usepasswd), 4);
	
	cmdlen = sizeof(tcs_req_read_mem_data) + op;
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_ReadMemData);
	
	rspLen = length + cmdlen;
	
	if (0 != (ret = tpcm_transmit (cmd, cmdlen, rsp, &rspLen))) goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		printf ("[%s:%d] Invalid tpcm rsp tag(0x%02X)\n", __func__, __LINE__, tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 == (ret = tpcmRspRetCode (rsp))){
		if(tpcmRspLength (rsp) != HTTC_ALIGN_SIZE(ntohl(rsp->uiDatalen) + sizeof(tcs_rsp_read_mem_data),4)){
				httc_util_pr_error ("Error response steam, bad length %d %ld.\n",tpcmRspLength (rsp),
				(long int)HTTC_ALIGN_SIZE(ntohl(rsp->uiDatalen) + sizeof(tcs_rsp_read_mem_data),4));
				ret = TSS_ERR_BAD_RESPONSE;
				goto out;
		}
	
		if ((int)ntohl(rsp->uiDatalen) > *length_inout){
			httc_util_pr_error ("Space not enought.\n");
			ret = TSS_ERR_OUTPUT_EXCEED;
			goto out;
		}

		*length_inout = ntohl(rsp->uiDatalen);
		memcpy(data,rsp->uaData,*length_inout);
	}

out:
	if(cmd) httc_free(cmd);
	return ret;
}




