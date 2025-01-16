#include <stdio.h>
#include <string.h>

#include "tcsapi/tcs_constant.h"
#include "tcfapi/tcf_fileacl.h"
#include "tcfapi/tcf_error.h"
#include "tsbapi/tsb_admin.h"

#include "httcutils/mem.h"
#include "httcutils/file.h"
#include "httcutils/debug.h"
#include "httcutils/convert.h"

#define FILE_PROTECT_POLICY_PATH 			HTTC_TSS_CONFIG_PATH"file_protect.data"
#define PRIVILEGE_PROCESS_POLICY_PATH		HTTC_TSS_CONFIG_PATH"privilege_process.data"

int tcf_set_file_protect_policy(struct tcf_file_protect *ppolicy,int num){

	int ret = 0;
	int i = 0;
	int data_length = 0;
	int op = 0;
	char * data = NULL;
	int trans = 0;	
	
	if(num && ppolicy == NULL) return TCF_ERR_PARAMETER;

	/**Get data length**/
	for(;i < num;i++){
		data_length += sizeof(int);
		data_length += ppolicy[i].length;
		if(ppolicy[i].length != 0 && ppolicy[i].pattern == NULL){
			httc_util_pr_error("Policy error i:%d length:%d add:%p\n",i,ppolicy[i].length,ppolicy[i].pattern);
			return TCF_ERR_PARAMETER;
		}
	}
	data_length += sizeof(int);

	if(NULL == (data = httc_malloc(data_length))){
		httc_util_pr_error("no memory! length:%d\n",data_length);
		return TCF_ERR_NOMEM;
	}
	memset(data, 0 ,data_length);
	
	trans = ntohl(num);
	memcpy(data,&trans,sizeof(int));
	op += sizeof(int);

	for(i =0;i < num;i++){
		trans = ntohl(ppolicy[i].length);
		memcpy(data + op,&trans,sizeof(int));
		op += sizeof(int);
		memcpy(data + op,ppolicy[i].pattern,ppolicy[i].length);
		op += ppolicy[i].length;		
		if(op > data_length){
			httc_util_pr_error("Policy length error op:%d length:%d \n",op,data_length);
			if(data) httc_free(data);
			return TCF_ERR_PARAMETER;
		}
	}

	ret  =  httc_util_file_write(FILE_PROTECT_POLICY_PATH,data,data_length);
	if( ret != data_length){
		httc_util_pr_error("Write file error ret:%d,length:%d \n",ret,data_length);
		if(data) httc_free(data);
		return TCF_ERR_FILE;
	}
	ret = tsb_reload_file_protect_policy();
	if(ret){
		httc_util_pr_error("tsb_reload_file_protect_policy error ret:%d\n",ret);
		ret = TCF_ERR_TSB;
	}

	if(data) httc_free(data);
	return ret;
}

int tcf_set_privilege_process_policy(struct tcf_privilege_process *ppolicy,int num){

	int ret = 0;
	int i = 0;
	int data_length = 0;
	int op = 0;
	char * data = NULL;
	int trans = 0;
	
	if(num && ppolicy == NULL) return TCF_ERR_PARAMETER;

	/**Get data length**/
	for(;i < num;i++){
		data_length += sizeof(int);
		data_length += DEFAULT_HASH_SIZE;
		data_length += ppolicy[i].length;
		if(ppolicy[i].length != 0 && ppolicy[i].pattern == NULL){
			httc_util_pr_error("Policy error i:%d length:%d add:%p\n",i,ppolicy[i].length,ppolicy[i].pattern);
			return TCF_ERR_PARAMETER;
		}
	}
	data_length += sizeof(int);

	if(NULL == (data = httc_malloc(data_length))){
		httc_util_pr_error("no memory! length:%d\n",data_length);
		return TCF_ERR_NOMEM;
	}
	memset(data, 0 ,data_length);
	
	trans = ntohl(num);
	memcpy(data,&trans,sizeof(int));
	op += sizeof(int);

	for(i =0;i < num;i++){
		trans = ntohl(ppolicy[i].length);
		memcpy(data + op,&trans,sizeof(int));
		op += sizeof(int);
		memcpy(data + op,ppolicy[i].hash, DEFAULT_HASH_SIZE);
		op += DEFAULT_HASH_SIZE;
		memcpy(data + op,ppolicy[i].pattern,ppolicy[i].length);
		op += ppolicy[i].length;		
		if(op > data_length){
			httc_util_pr_error("Policy length error op:%d length:%d\n",op,data_length);
			if(data) httc_free(data);
			return TCF_ERR_PARAMETER;
		}
	}

	ret  =  httc_util_file_write(PRIVILEGE_PROCESS_POLICY_PATH,data,data_length);
	if( ret != data_length){
		httc_util_pr_error("Write file error ret:%d,length:%d \n",ret,data_length);
		if(data) httc_free(data);
		return TCF_ERR_FILE;
	}
	ret = 0;
	/*ret = tsb_reload_privilege_process_policy();
	if(ret){
		httc_util_pr_error("tsb_reload_privilege_process_policy error ret:%d\n",ret);
		ret = TCF_ERR_TSB;
	} */

	if(data) httc_free(data);
	return ret;

}


