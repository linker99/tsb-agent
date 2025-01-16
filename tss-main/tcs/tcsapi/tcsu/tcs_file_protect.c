#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "mem.h"
#include "file.h"
#include "debug.h"
#include "convert.h"
#include "uutils.h"
#include "transmit.h"
#include "tcs_config.h"
#include "tcs_constant.h"
#include "tpcm_command.h"
#include "tcs_error.h"

#include "tcs_auth_def.h"
#include "tcs_file_protect.h"
#include "tcs_file_protect_def.h"
#include "tcs_auth.h"
#include "tcs_cert_verify.h"

#pragma pack(push, 1)
typedef struct{
	COMMAND_HEADER;
	uint8_t  uaData[0];
}tcs_req_file_protect_policy;

#pragma pack(pop)


static int check_buffer(unsigned char *buffer, int length, int num){
	int j;
	struct file_protect_item *cur_item;
	int offset = 0;
	for(j = 0;j < num; j++){
		cur_item = (struct file_protect_item *)(buffer + offset);
		offset += sizeof(struct file_protect_item);
		if(offset > length ||
					(offset += 	ntohs(cur_item->be_privileged_process_num)
							* sizeof(struct file_protect_privileged_process)
							) > length
		){
			httc_util_pr_error("Length error exp:%d act:%d \n",offset,length);
			return TSS_ERR_PARAMETER;
		}
	}
	if(offset != length){
		httc_util_pr_error("Length error exp:%d act:%d \n",offset,length);
		return TSS_ERR_PARAMETER;
	}
	return 0;
}

static int httc_add_file_protect_policy(unsigned char *item, int length, int num){

	int i = 0;
	int j = 0;
	int ret = 0;
	int number = 0;
	int old_offset = 0;
	int offset = 0;
	int new_len = 0;
	uint8_t *buffer =  NULL;
	unsigned long old_len = 0;
	struct file_protect_item *cur_item= NULL;
	struct file_protect_item *cur_item_add = NULL;


	if(item == NULL) return TSS_ERR_PARAMETER;
	if(!num) return TSS_SUCCESS;

	if((ret = check_buffer(item,length,num))){
		httc_util_pr_error("Add policy param error %d\n",ret);
		return ret;
	}
	/*Get file_protect_policy data*/
	buffer = httc_util_file_read_full(FILE_PROTECT_POLICY_PATH,&old_len);
	if(buffer == NULL || old_len == 0){
		httc_util_pr_error("httc_util_file_read_full error path:%s length:%ld\n",FILE_PROTECT_POLICY_PATH,old_len);
		return TSS_ERR_READ;
	}

	new_len = old_len + length;
	//memcpy(&number,buffer+sizeof(int),sizeof(int));
	number = *(int *)(buffer+sizeof(int));

	old_offset += sizeof(int);
	old_offset += sizeof(int);

	if((ret = check_buffer(buffer + old_offset,old_len - old_offset,number)) ){
		httc_util_pr_error("Add policy old policy error %d\n",ret);
		if(buffer) httc_free(buffer);
		return ret;
	}

	for(;i < number; i++){
		offset = 0;
		cur_item = (struct file_protect_item *)(buffer + old_offset);
		old_offset += sizeof(struct file_protect_item);
		old_offset += ntohs(cur_item->be_privileged_process_num) *
							sizeof(struct file_protect_privileged_process);
//		if(old_offset > old_len
//			|| 	() > 	old_len
//		){
//			httc_util_pr_error("Length error exp:%d act:%ld \n",old_offset,old_len);
//			httc_free(buffer);
//			return TSS_ERR_PARAMETER;
//		}
		for(j = 0;j < num; j++){
			cur_item_add = (struct file_protect_item *)(item + offset);
			offset += sizeof(struct file_protect_item);
			offset += ntohs(cur_item_add->be_privileged_process_num)
						* sizeof(struct file_protect_privileged_process);
//			if(offset > length ||
//						(offset += HTTC_ALIGN_SIZE(
//								ntohs(cur_item_add->be_privileged_process_num)
//								* sizeof(struct file_protect_privileged_process)
//										,4)) > length
//			){
//				httc_util_pr_error("Length error exp:%d act:%d \n",offset,length);
//				httc_free(buffer);
//				return TSS_ERR_PARAMETER;
//			}
			if(!strcmp((const char *)cur_item->path,(const char *)cur_item_add->path)){
				if(cur_item->measure_flags == cur_item_add->measure_flags ||
				  cur_item->type == cur_item_add->type){
					 httc_util_pr_error("The same item path:%s \n",cur_item_add->path);
					 httc_free(buffer);
					 return TSS_ERR_PARAMETER;
				  }
			}

		}
	}

	number += num;
    ret = httc_util_file_write(FILE_PROTECT_POLICY_PATH,(const char *)&new_len,sizeof(int));
	if(ret != sizeof(int)){
		httc_util_pr_error("httc_util_file_write error path:%s exp_length:%d act_length:%d\n",FILE_PROTECT_POLICY_PATH,(int)sizeof(int),ret);
		if(buffer) httc_free(buffer);
		return TSS_ERR_WRITE;
	}

	ret = httc_util_file_write_offset(FILE_PROTECT_POLICY_PATH,(const char *)&number,(int)sizeof(int),sizeof(int));
	if(ret != sizeof(int)){
		httc_util_pr_error("httc_util_file_write error path:%s exp_length:%d act_length:%d\n",FILE_PROTECT_POLICY_PATH,(int)sizeof(int),ret);
		if(buffer) httc_free(buffer);
		return TSS_ERR_WRITE;
	}

	ret = httc_util_file_write_offset(FILE_PROTECT_POLICY_PATH,(const char *)(buffer + sizeof(int)+sizeof(int)),sizeof(int)+sizeof(int),(old_len - sizeof(int)- sizeof(int)));
	if(ret != (old_len - sizeof(int) - sizeof(int))){
		httc_util_pr_error("httc_util_file_write error path:%s exp_length:%d act_length:%d\n",FILE_PROTECT_POLICY_PATH,(int)(old_len - sizeof(int)- sizeof(int)),ret);
		if(buffer) httc_free(buffer);
		return TSS_ERR_WRITE;
	}

	ret = httc_util_file_write_offset(FILE_PROTECT_POLICY_PATH,(const char *)item, old_len, length);
	if(ret != length){
		httc_util_pr_error("httc_util_file_write error path:%s exp_length:%d act_length:%d\n",FILE_PROTECT_POLICY_PATH,length,ret);
		if(buffer) httc_free(buffer);
		return TSS_ERR_WRITE;
	}

	if(buffer) httc_free(buffer);
	return TSS_SUCCESS;
}

static int httc_delete_file_protect_policy(unsigned char *item, int length, int num){

	int i = 0;
	int j = 0;
	int k = 0;
	int ret = 0;
	int number = 0;
	int del = 0;
	int old_offset = 0;
	int offset = 0;
	int save_length = 0;
	uint8_t *old_buffer =  NULL;
	unsigned long old_len = 0;
	uint8_t *buf =  NULL;
	int buf_len = 0;
	int new_len = 0;
	struct file_protect_item *cur_item= NULL;
	struct file_protect_item *cur_item_del = NULL;

	if(item == NULL) return TSS_ERR_PARAMETER;
	if(!num) return TSS_SUCCESS;

	if((ret = check_buffer(item,length,num)) ){
		httc_util_pr_error("Delete policy param error %d\n",ret);
		return ret;
	}

	/*Get file_protect_policy data*/
	old_buffer = httc_util_file_read_full(FILE_PROTECT_POLICY_PATH,&old_len);
	if(old_buffer == NULL || old_len == 0){
		httc_util_pr_error("httc_util_file_read_full error path:%s length:%ld\n",FILE_PROTECT_POLICY_PATH,old_len);
		return TSS_ERR_READ;
	}

	buf_len = old_len;
	if (NULL == (buf = httc_malloc (buf_len))){
		httc_util_pr_error ("Req Alloc error!\n");
		httc_free(old_buffer);
		return TSS_ERR_NOMEM;
	}

	//memcpy(&number, buffer+sizeof(int), sizeof(int));
	number = *(int *)(old_buffer + sizeof(int));
	old_offset += (sizeof(int)+ sizeof(int));

	if((ret = check_buffer(old_buffer + old_offset,old_len - old_offset,number)) ){
		httc_util_pr_error("Delete policy old policy error %d\n",ret);
		if(old_buffer) httc_free(old_buffer);
		if(buf) httc_free(buf);
		return ret;
	}

	/*Get delete policy data*/
	for(;i < number; i++){
		offset = 0;
		del = 0;
		cur_item = (struct file_protect_item *)(old_buffer + old_offset);
		old_offset += sizeof(struct file_protect_item);
		old_offset += ntohs(cur_item->be_privileged_process_num) *
							sizeof(struct file_protect_privileged_process);
//		if(old_offset > old_len
//			|| 	(old_offset += HTTC_ALIGN_SIZE(
//					ntohs(cur_item->be_privileged_process_num) *
//					sizeof(struct file_protect_privileged_process),
//					4)) > 	old_len
//		){
//			httc_util_pr_error("Length error exp:%d act:%ld \n",old_offset,old_len);
//			httc_free(old_buffer);
//			return TSS_ERR_PARAMETER;
//		}
		for(j = 0;j < num; j++){
			cur_item_del = (struct file_protect_item *)(item + offset);
			offset += sizeof(struct file_protect_item);
			offset += ntohs(cur_item_del->be_privileged_process_num)
									* sizeof(struct file_protect_privileged_process);
//			if(offset > length
//				|| (offset += HTTC_ALIGN_SIZE(
//						ntohs(cur_item_del->be_privileged_process_num)
//						* sizeof(struct file_protect_privileged_process),
//						4)) > length
//			){
//				httc_util_pr_error("Length error exp:%d act:%d \n",offset,length);
//				if(old_buffer) httc_free(old_buffer);
//				if(buf) httc_free(buf);
//				return TSS_ERR_PARAMETER;
//			}
			if(!strcmp((const char *)cur_item->path,(const char *)cur_item_del->path)){
				if(cur_item->measure_flags == cur_item_del->measure_flags ||
				  cur_item->type == cur_item_del->type){
					del = 1;
					k++;
					break;
				  }
			}
		}
		save_length = HTTC_ALIGN_SIZE((sizeof(struct file_protect_item) + (ntohs(cur_item->be_privileged_process_num) * sizeof(struct file_protect_privileged_process))),4);
		//httc_util_pr_error("number:%d save_length:%d op:%d\n",number,save_length,op);
		if(!del){
			memcpy(buf + new_len,old_buffer + old_offset - save_length , save_length);
			new_len += save_length;
		}
	}

	old_offset = sizeof(int);
	number -= k;

    ret = httc_util_file_write(FILE_PROTECT_POLICY_PATH,(const char *)&new_len,sizeof(int));
	if(ret != sizeof(int)){
		httc_util_pr_error("httc_util_file_write error path:%s exp_length:%d act_length:%d\n",FILE_PROTECT_POLICY_PATH,(int)sizeof(int),ret);
		if(old_buffer) httc_free(old_buffer);
		if(buf) httc_free(buf);
		return TSS_ERR_WRITE;
	}
	ret = httc_util_file_write_offset(FILE_PROTECT_POLICY_PATH,(const char *)&number,(int)sizeof(int), sizeof(int));
	if(ret != sizeof(int)){
		httc_util_pr_error("httc_util_file_write error path:%s exp_length:%d act_length:%d\n",FILE_PROTECT_POLICY_PATH,new_len,ret);
		if(old_buffer) httc_free(old_buffer);
		if(buf) httc_free(buf);
		return TSS_ERR_WRITE;
	}

	ret = httc_util_file_write_offset(FILE_PROTECT_POLICY_PATH,(const char *)buf, (int)sizeof(int)+(int)sizeof(int), new_len);
	if(ret != new_len){
		httc_util_pr_error("httc_util_file_write error path:%s exp_length:%d act_length:%d\n",FILE_PROTECT_POLICY_PATH,new_len,ret);
		if(old_buffer) httc_free(old_buffer);
		if(buf) httc_free(buf);
		return TSS_ERR_WRITE;
	}

	if(old_buffer) httc_free(old_buffer);
	if(buf) httc_free(buf);
	return TSS_SUCCESS;
}



static int httc_set_file_protect_policy(unsigned char *item, int length, int num){

	int ret = 0;


	if((ret = check_buffer(item,length,num)) ){
		httc_util_pr_error("Set policy param error %d\n",ret);
		return ret;
	}

    ret = httc_util_file_write(FILE_PROTECT_POLICY_PATH,(const char *)&length,sizeof(int));
	if(ret != sizeof(int)){
		httc_util_pr_error("httc_util_file_write error path:%s exp_length:%d act_length:%d\n",FILE_PROTECT_POLICY_PATH,(int)sizeof(int),ret);
		return TSS_ERR_WRITE;
	}
	ret = httc_util_file_write_offset(FILE_PROTECT_POLICY_PATH,(const char *)&num,(int)sizeof(int),sizeof(int));
	if(ret != sizeof(int)){
		httc_util_pr_error("httc_util_file_write error path:%s exp_length:%d act_length:%d\n",FILE_PROTECT_POLICY_PATH,(int)sizeof(int),ret);
		return TSS_ERR_WRITE;
	}

	ret = httc_util_file_write_offset(FILE_PROTECT_POLICY_PATH,(const char *)item, (int)sizeof(int)+(int)sizeof(int), length);
	if(ret != length){
		httc_util_pr_error("httc_util_file_write error path:%s exp_length:%d act_length:%d\n",FILE_PROTECT_POLICY_PATH,length,ret);
		return TSS_ERR_WRITE;
	}
	return TSS_SUCCESS;
}



/*
 * 	更新文件保护策略
 * 	设置、增加、删除。
 */

int tcs_update_file_protect_policy(
		struct file_protect_update *references,
		const char *uid,int auth_type,
		int auth_length,unsigned char *auth){

	int ret = 0;
	int action = 0;
	int data_len = 0;
	uint32_t num = 0;
	//uint8_t *cmd = NULL;
//	uint32_t op = 0;
	//uint32_t cmdlen = 0;
	//uint32_t no_use_type = 0;
	int length = 0;
	//int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	//tcs_req_file_protect_policy *req = NULL;
//	tpcm_rsp_header_st *rsp = NULL;
    struct admin_cert_item cert;

	if( references == NULL) return TSS_ERR_PARAMETER;

	if(ntohl(references->be_size) != sizeof(struct file_protect_update)){
		httc_util_pr_error ("cert size error exp:%ld act:%d!\n",(long int)sizeof(struct file_protect_update),ntohl(references->be_size));
		return TSS_ERR_PARAMETER;
	}


	/*Get cert*/
	if( 0 != (ret = tcs_dev_get_cert_by_uid ((const char *)uid, &cert))) return ret;
	/*Verify update*/
	length = sizeof(struct file_protect_update) + ntohl(references->be_data_length);

	if( 0 != (ret = tcs_dev_verify_update(&cert, auth_type, auth_length, auth, references, length))) return ret;
	/*Update policy*/

	action = ntohl(references->be_action);
	num = ntohl(references->be_item_number);
	data_len = ntohl(references->be_data_length);

	if(action == POLICY_ACTION_SET){
		ret = httc_set_file_protect_policy(references->data,data_len,num);
	}else if(action == POLICY_ACTION_ADD){
		ret = httc_add_file_protect_policy(references->data,data_len,num);



	}else if(action == POLICY_ACTION_DELETE){
		ret = httc_delete_file_protect_policy(references->data,data_len,num);

	}else{
		ret = TSS_ERR_NOT_SUPPORT;
	}


	return ret;
}



/*
 *	读取文件保护策略
 */
int tcs_get_file_protect_policy(struct file_protect_item **items, int *num, int *length){

	unsigned long data_len = 0;
	uint8_t *data = NULL;
	struct stat nvstat;
	int i;
	int old_offset=0;
	int ret;
	struct file_protect_item *cur_item;
	nvstat.st_size = 0;
	stat(FILE_PROTECT_POLICY_PATH, &nvstat);
	if(nvstat.st_size == 0){
		*num = 0;
		*length = 0;
		return TSS_SUCCESS;
	}

	data = httc_util_file_read_full(FILE_PROTECT_POLICY_PATH,&data_len);


	if(data == NULL || data_len == 0){
		httc_util_pr_error("httc_util_file_read_full error path:%s length:%ld\n",FILE_PROTECT_POLICY_PATH,data_len);
		*num = 0;
		*length = 0;
		return TSS_ERR_READ;
	}


	//memcpy(num,data+sizeof(int),sizeof(int));
	*num = *(int *)(data+sizeof(int));
	*length = data_len - sizeof(int)- sizeof(int);
	old_offset += sizeof(int)+ sizeof(int);
	if((ret = check_buffer(data + old_offset,data_len - old_offset,*num)) ){
		httc_util_pr_error("Get policy old policy error %d\n",ret);
		if(data) httc_free(data);
		return ret;
	}



	if (NULL == (*items = (struct file_protect_item *)httc_malloc (*length))){
		httc_util_pr_error ("Req Alloc error!\n");
		if(data) httc_free(data);
		return TSS_ERR_NOMEM;
	}

	for(i=0;i < *num; i++){
		cur_item = (struct file_protect_item *)(data + old_offset);
		old_offset += sizeof(struct file_protect_item);
		if(old_offset > data_len
			|| 	(old_offset += HTTC_ALIGN_SIZE(
					ntohs(cur_item->be_privileged_process_num) *
					sizeof(struct file_protect_privileged_process),
					4)) > 	data_len
		){
			httc_util_pr_error("Length error exp:%d act:%ld \n",old_offset,data_len);
			if(data) httc_free(data);
			return TSS_ERR_PARAMETER;
		}
	}


	memcpy((uint8_t *)*items,data + sizeof(int)+ sizeof(int), *length);

	if(data) httc_free(data);
	return TSS_SUCCESS;

}



