#include <stdio.h>
#include <string.h>

#include "tutils.h"
#include "tcfapi/tcf_attest.h"
#include "tcsapi/tcs_constant.h"
#include "tcsapi/tcs_file_protect.h"
#include "tcsapi/tcs_file_protect_def.h"
#include "tcfapi/tcf_file_protect.h"
#include "tcfapi/tcf_error.h"
#include "tsbapi/tsb_admin.h"

#include "tcfapi/tcf_dev_version.h"
#include "tcsapi/tcs_attest.h"
#include "tcsapi/tcs_attest_def.h"

#include "httcutils/mem.h"
#include "httcutils/file.h"
#include "httcutils/debug.h"
#include "httcutils/convert.h"

 uint32_t get_file_protect_date_len(uint8_t *items, uint32_t items_num)
{
	uint32_t date_len = 0;
	uint32_t i = 0;
	struct file_protect_item *items_tmp = NULL;
	//httc_util_pr_dev("items_num[%d]\n",items_num);
	for (i = 0; i < items_num; ++i)
	{
		items_tmp = (struct file_protect_item *)(items + date_len);
		httc_util_pr_dev("i[%d],be_privileged_process_num[%d]\n",i,items_tmp->be_privileged_process_num);
		date_len += sizeof(struct file_protect_item) + ntohs(items_tmp->be_privileged_process_num) * sizeof(struct file_protect_privileged_process);
	}

	return date_len;
}
int tcf_util_check_file_protect_update(struct file_protect_update *update)
{
	uint32_t rc = 0;
    uint32_t ref_total_len=0;
    uint64_t replay_counter = 0;
    uint8_t id[128] = {0};
	int id_len = sizeof(id);


    do{
	  if (ntohl(update->be_size) != sizeof(struct file_protect_update))
		{
			rc = TCF_ERR_NOMEM;
			httc_util_pr_error("be_size[%llu] != [%d]\n", (unsigned long long )ntohl(update->be_size), (int)sizeof(struct file_protect_update));
			break;
		}

	   replay_counter = ntohll(update->be_replay_counter);
		if (tcf_set_file_protect_version(replay_counter) != 0)
		{


			httc_util_pr_error("replay error update->be_replay_counter:%llu\r\n", (unsigned long long)replay_counter);
			rc = TCF_ERR_VERSION;
			break;
		}


		rc = tcs_get_tpcm_id(id, &id_len);
		if (rc)
		{
			httc_util_pr_dev("[tcs_get_tpcm_id] ret: 0x%08x\n", rc);
			rc=TCF_ERR_BAD_DATA;
			break;
		}
		rc = memcmp(update->tpcm_id, id, MAX_TPCM_ID_SIZE);
		if (rc != 0)
		{
			httc_util_pr_error("check tpcm id error \r\n");
			rc=TCF_ERR_BAD_DATA;
			break;
		}

		ref_total_len = get_file_protect_date_len(update->data,ntohl(update->be_item_number));
		if (ref_total_len != ntohl(update->be_data_length))
		{
			rc = TCF_ERR_BAD_DATA;
			httc_util_pr_error("cal data_size[%d],update->be_data_length[%d]\n", ref_total_len, ntohl(update->be_data_length));
			break;
		}
    }while(0);
	return rc;
}

static int tcf_util_file_protect_policy_serialize (struct file_protect_item_user *user_items, int num, int *length, struct file_protect_item **items){

	int i = 0;
	int j = 0;
	int ret = 0;
	int op = 0;
	int opt = 0;
	int buf_len = 0;
	int process_num = 0;
	int path_len  = 0;
	struct file_protect_item *cur_item = NULL;
	struct file_protect_privileged_process *cur = NULL;

 	/*Get length*/
	for(;i < num; i++){
		buf_len += sizeof(struct file_protect_item);
		buf_len += (user_items[i].privileged_process_num * sizeof(struct file_protect_privileged_process));
		buf_len = HTTC_ALIGN_SIZE(buf_len, 4);
	}
	if(NULL == (*items = httc_malloc(buf_len))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TCF_ERR_NOMEM;
	}

	for(i = 0; i < num; i++){
		cur_item = (struct file_protect_item *)((uint8_t *)*items + op);
		cur_item->measure_flags = (uint8_t)user_items[i].measure_flags;
		cur_item->type = (uint8_t)user_items[i].type;
		process_num = user_items[i].privileged_process_num;
		cur_item->be_privileged_process_num = htons((uint16_t)process_num);
		if (NULL == user_items[i].path){
			httc_util_pr_error ("user_items[%d].path is null\n", i);
			if(*items) httc_free(*items);
			ret = TCF_ERR_PARAMETER;
			goto out;
		}
		path_len = strlen((const char *)user_items[i].path);
		if(path_len + 1 > 256){
			httc_util_pr_error ("Path length error %s(%d)!\n",user_items[i].path,path_len);
			if(*items) httc_free(*items);
			ret = TCF_ERR_INPUT_EXCEED;
			goto out;
		}
		memset(cur_item->path, 0, 256);
		memcpy(cur_item->path,user_items[i].path,path_len);
		opt = 0;
		for(j = 0; j < process_num; j++){
			//httc_util_pr_dev ("process num :%d j %d opt:%d\n",process_num,j, opt);
			cur = (struct file_protect_privileged_process *)((uint8_t *)cur_item->privileged_processes + opt);
			//httc_util_pr_dev ("be_privi_type  :%d \n",(*(user_items[i].privileged_processes[j])).privi_type);
			if (NULL == user_items[i].privileged_processes[j]){
				httc_util_pr_error ("user_items[%d].privileged_processes[%d] is null\n", i, j);
				if(*items) httc_free(*items);
				ret =  TCF_ERR_PARAMETER;
				goto out;
			}
			if (NULL == user_items[i].privileged_processes[j]->path){
				httc_util_pr_error ("user_items[%d].privileged_processes[%d]->path is null\n", i, j);
				if(*items) httc_free(*items);
				ret = TCF_ERR_PARAMETER;
				goto out;
			}

			cur->be_privi_type = htonl(user_items[i].privileged_processes[j]->privi_type);
			//httc_util_pr_dev ("user_items[%d].privileged_processes[%d]->path: %s\n", i, j, user_items[i].privileged_processes[j]->path);
			path_len = strlen((const char *)user_items[i].privileged_processes[j]->path);
			//user_items("path:%s pathlen:%d \n",user_items[i].privileged_processes[j]->path,path_len);
			if(path_len + 1 > 256){
				httc_util_pr_error ("Process path length error %s(%d)!\n",user_items[i].privileged_processes[j]->path,path_len);
				if(*items) httc_free(*items);
				ret =  TCF_ERR_INPUT_EXCEED;
				goto out;
			}
			memset(cur->path, 0, 256);
			memcpy(cur->path, user_items[i].privileged_processes[j]->path,path_len);
			memcpy(cur->hash, user_items[i].privileged_processes[j]->hash,32);
			opt += sizeof(struct file_protect_privileged_process);
		}

		op += sizeof(struct file_protect_item);
		op += opt;
		op = HTTC_ALIGN_SIZE(op, 4);
		if(op > buf_len)
		{
			httc_util_pr_error ("Length error %d(%d)!\n",op,buf_len);
			ret =  TCF_ERR_INPUT_EXCEED;
			if(*items) httc_free(*items);
			goto out;
		}
	}
	*length = buf_len;
out:
	return ret;
}


static int tcf_util_file_protect_policy_extract(struct file_protect_item *items, int length, int num, struct file_protect_item_user **user_items){

	int i = 0;
	int j = 0;
	int op = 0;
	int opt = 0;
	int path_len  = 0;
	struct file_protect_item *cur_item = NULL;
	struct file_protect_privileged_process *cur = NULL;

	struct file_protect_item_user *uitems;
	*user_items = uitems = httc_malloc(num * sizeof(struct file_protect_item_user));
	if(!uitems){
		httc_util_pr_error ("Req Alloc error!\n");
		return TCF_ERR_NOMEM;
	}

	for(;i < num ; i++){
		cur_item = (struct file_protect_item *)((uint8_t *)items + op);
		uitems[i].measure_flags = (int)cur_item->measure_flags;
		uitems[i].type = (int)cur_item->type;
		uitems[i].privileged_process_num = (int)ntohs(cur_item->be_privileged_process_num);
		path_len = strlen((const char *)cur_item->path);
		if(NULL == (uitems[i].path = httc_malloc(path_len + 1))){
			httc_util_pr_error ("Req Alloc error!\n");
			tcf_free_file_protect_policy(*user_items, i + 1);
			return TCF_ERR_NOMEM;
		}

		memset(uitems[i].path, 0, path_len + 1);
		memcpy(uitems[i].path, cur_item->path, path_len);

		if(NULL == (uitems[i].privileged_processes = httc_malloc(uitems[i].privileged_process_num * sizeof(struct file_protect_privileged_process_user **)))){
			tcf_free_file_protect_policy(*user_items, i + 1);
			return TCF_ERR_NOMEM;
		}
		opt = 0;
		for(j = 0; j < uitems[i].privileged_process_num; j++){

			if(NULL == (uitems[i].privileged_processes[j] = (struct file_protect_privileged_process_user *)httc_malloc(sizeof(struct file_protect_privileged_process_user)))){
				tcf_free_file_protect_policy(*user_items, i + 1);
				return TCF_ERR_NOMEM;
			}

			cur = (struct file_protect_privileged_process *)((uint8_t *)cur_item->privileged_processes + opt);
			uitems[i].privileged_processes[j]->privi_type = ntohl(cur->be_privi_type);
			path_len = strlen((const char *)cur->path);
			if(NULL == (uitems[i].privileged_processes[j]->path = httc_malloc(path_len + 1))){
				httc_util_pr_error ("Req Alloc error!\n");
				tcf_free_file_protect_policy(*user_items, i + 1);
				return TCF_ERR_NOMEM;
			}

			memset(uitems[i].privileged_processes[j]->path, 0, path_len + 1);
			memcpy(uitems[i].privileged_processes[j]->path, cur->path, path_len);

			if(NULL == (uitems[i].privileged_processes[j]->hash = httc_malloc(32))){
				httc_util_pr_error ("Req Alloc error!\n");
				tcf_free_file_protect_policy(*user_items, i + 1);
				return TCF_ERR_NOMEM;
			}

			memcpy(uitems[i].privileged_processes[j]->hash, cur->hash, 32);
			opt += sizeof(struct file_protect_privileged_process);
		}
		op += sizeof(struct file_protect_item);
		op += opt;
		op = HTTC_ALIGN_SIZE(op, 4);
		if(op > length)
		{
			httc_util_pr_error ("Length error %d(%d)!\n",op,length);
			tcf_free_file_protect_policy(*user_items, i + 1);
			return TCF_ERR_OUTPUT_EXCEED;
		}

	}
	return TCF_SUCCESS;
}

/*
 * 	准备更新策略库。
 */
int tcf_prepare_update_file_protect_policy(
		struct file_protect_item_user *items,unsigned int num,
		unsigned char *tpcm_id,unsigned int tpcm_id_length,
		int action,uint64_t replay_counter,
		struct file_protect_update **buffer,unsigned int *prepare_size){

	int ret = 0;
	int length = 0;
	struct file_protect_item *data = NULL;

	if(tpcm_id_length != MAX_TPCM_ID_SIZE || buffer == NULL || prepare_size == NULL || tpcm_id == NULL) return TCF_ERR_PARAMETER;

	/*serialize file_protect_item_user data*/
	ret = tcf_util_file_protect_policy_serialize(items,num,&length, &data);
	if(ret) return ret;
	if(NULL == (*buffer = httc_malloc(length + sizeof(struct file_protect_update)))){
		httc_util_pr_error ("Req Alloc error!\n");
		if(data) httc_free(data);
		return TCF_ERR_NOMEM;
	}
//	httc_util_dump_hex((const char *)"tcf_util_file_protect_policy_serialize",(uint8_t *)data,length);

	(*buffer)->be_size = ntohl(sizeof(struct file_protect_update));
	(*buffer)->be_action = ntohl(action);
	(*buffer)->be_replay_counter = ntohll(replay_counter);
	(*buffer)->be_item_number = ntohl(num);
	(*buffer)->be_data_length = ntohl(length);
	memcpy((*buffer)->tpcm_id,tpcm_id,tpcm_id_length);

 if(length!=0)
 {
	memcpy((*buffer)->data, data, length);
}
//	httc_util_dump_hex((const char *)"update",(uint8_t *)*buffer,length + sizeof(struct file_protect_update));

	*prepare_size = length + sizeof(struct file_protect_update);

	if(data) httc_free(data);
	return TCF_SUCCESS;
}

/*
 * 	更新文件保护策略
 * 	设置、增加、删除。
 */

int tcf_update_file_protect_policy(
		struct file_protect_update *references,
		const char *uid,int cert_type,
		unsigned int auth_length,unsigned char *auth){

	int ret = 0;
	/*Check policy*/
	if( 0 != (ret = tcf_util_check_file_protect_update(references))) return ret;

	ret = tcs_update_file_protect_policy(references, uid, cert_type, auth_length, auth);
	if(ret) return ret;

	if ((ret = tsb_reload_file_protect_policy())){
		if(ret == -1){
			httc_util_pr_info ("tsb_reload_file_protect_policy : %d(0x%x)\n", ret, ret);
		}
		//return TCF_ERR_TSB;
	}
	//	httc_util_dump_hex((const char *)"references",(void *)references,1024);
	httc_write_version_notices (htonll (references->be_replay_counter), POLICY_TYPE_FILE_PROTECT);

	return TCF_SUCCESS;
}

/*
 *	读取文件保护策略
 */
int tcf_get_file_protect_policy(struct file_protect_item_user **references, unsigned int *inout_num){

		int ret = TCF_SUCCESS;
		int num = 0;
		int length = 0;
		struct file_protect_item *items = NULL;

		ret = tcs_get_file_protect_policy(&items, &num, &length);
		if(ret){
			goto out;
		}

		ret = tcf_util_file_protect_policy_extract(items, length, num, references);
		if(ret){
			goto out;
		}

		*inout_num = num;
out:
		if(items) httc_free(items);
		return ret;
}


/*
 *	释放文件保护内存
 */
void tcf_free_file_protect_policy(struct file_protect_item_user * pp,unsigned int num){
	if(pp){
		while (num--){
			if ((pp + num)->path) httc_free ((pp + num)->path);
			while ((pp + num)->privileged_process_num--){
				if ((pp + num)->privileged_processes[(pp + num)->privileged_process_num]){
					if ((*((pp + num)->privileged_processes[(pp + num)->privileged_process_num])).path) httc_free ((*((pp + num)->privileged_processes[(pp + num)->privileged_process_num])).path);
					if ((*((pp + num)->privileged_processes[(pp + num)->privileged_process_num])).hash) httc_free ((*((pp + num)->privileged_processes[(pp + num)->privileged_process_num])).hash);
					httc_free ((pp + num)->privileged_processes[(pp + num)->privileged_process_num]);
				}
			}
			if((pp + num)->privileged_processes) httc_free((pp + num)->privileged_processes);

		}
		httc_free(pp);
	}

}


