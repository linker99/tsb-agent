#include <stdio.h>
#include <string.h>

#include "tutils.h"
#include "tcfapi/tcf_attest.h"
#include "tcsapi/tcs_constant.h"
#include "tcsapi/tcs_network_control.h"
#include "tcsapi/tcs_network_control_def.h"
#include "tcfapi/tcf_network_control.h"
#include "tcfapi/tcf_error.h"
#include "tsbapi/tsb_admin.h"

#include "tcfapi/tcf_dev_version.h"
#include "tcsapi/tcs_attest.h"
#include "tcsapi/tcs_attest_def.h"

#include "httcutils/mem.h"
#include "httcutils/file.h"
#include "httcutils/debug.h"
#include "httcutils/convert.h"


 uint32_t get_network_control_date_len(uint8_t *items, uint32_t items_num)
{
	uint32_t date_len = 0;
	uint32_t i = 0;
	struct network_config_item *items_tmp = NULL;
	//httc_util_pr_dev("items_num[%d]\n",items_num);
	for (i = 0; i < items_num; ++i)
	{
		items_tmp = (struct network_config_item *)(items + date_len);
		httc_util_pr_dev("i[%d],be_privileged_process_num[%d]\n",i,ntohl(items_tmp->be_total_num));
		date_len += sizeof(struct network_config_item) + ntohl(items_tmp->be_total_num) * sizeof(struct ip_config);
	}

	return date_len;
}
int tcf_util_check_network_control_update(struct network_control_update *update)
{
	uint32_t rc = 0;
    uint32_t ref_total_len=0;
    uint64_t replay_counter = 0;
    uint8_t id[128] = {0};
	int id_len = sizeof(id);


    do{
	  if (ntohl(update->be_size) != sizeof(struct network_control_update))
		{
			rc = TCF_ERR_NOMEM;
			httc_util_pr_error("be_size[%llu] != [%d]\n", (unsigned long long )ntohl(update->be_size), (int)sizeof(struct network_control_update));
			break;
		}

	   replay_counter = ntohll(update->be_replay_counter);
		if (tcf_set_network_version(replay_counter) != 0)
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

		ref_total_len = get_network_control_date_len(update->data,ntohl(update->be_item_number));
		if (ref_total_len != ntohl(update->be_data_length))
		{
			rc = TCF_ERR_BAD_DATA;
			httc_util_pr_error("cal data_size[%d],update->be_data_length[%d]\n", ref_total_len, ntohl(update->be_data_length));
			break;
		}
    }while(0);
	return rc;
}
static int tcf_util_network_control_policy_serialize (struct network_config_item_user *user_items, int num, int *length, struct network_config_item **items){

	int i = 0;
	int j = 0;
	int ret = 0;
	int op = 0;
	int opt = 0;
	int buf_len = 0;
	int process_num = 0;

	struct network_config_item *cur_item = NULL;
	struct ip_config *cur = NULL;

 	/*Get length*/
	for(;i < num; i++){
		buf_len += sizeof(struct network_config_item);
		buf_len += (user_items[i].total_num * sizeof(struct ip_config));
		buf_len = HTTC_ALIGN_SIZE(buf_len, 4);
	}
	if(NULL == (*items = httc_malloc(buf_len))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TCF_ERR_NOMEM;
	}

	for(i = 0; i < num; i++){
		cur_item = (struct network_config_item *)((uint8_t *)*items + op);
		cur_item->be_port_sw = htonl(user_items[i].port_sw);


		process_num = user_items[i].total_num;
		cur_item->be_total_num = htonl((uint32_t)process_num);

		opt = 0;
		for(j = 0; j < process_num; j++){

			cur = (struct ip_config *)((uint8_t *)cur_item->item + opt);
			cur->be_from = htonl((*(user_items[i].item[j])).from);
			cur->be_id = htonl((*(user_items[i].item[j])).id);
			cur->be_status = htonl((*(user_items[i].item[j])).status);
			cur->be_to = htonl((*(user_items[i].item[j])).to);

			opt += sizeof(struct ip_config);
		}

		op += sizeof(struct network_config_item);
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


static int tcf_util_network_control_policy_extract(struct network_config_item *items, int length, int num, struct network_config_item_user **user_items){

	int i = 0;
	int j = 0;
	int op = 0;
	int opt = 0;

	struct network_config_item *cur_item = NULL;
	struct ip_config *cur = NULL;

	struct network_config_item_user *uitems;
	*user_items = uitems = httc_malloc(num * sizeof(struct network_config_item_user));
	if(!uitems){
		httc_util_pr_error ("Req Alloc error!\n");
		return TCF_ERR_NOMEM;
	}

	for(;i < num ; i++){
		cur_item = (struct network_config_item *)((uint8_t *)items + op);
		uitems[i].port_sw = ntohl(cur_item->be_port_sw);
		uitems[i].total_num = ntohl(cur_item->be_total_num);


		if(NULL == ((uitems[i].item) = httc_malloc(uitems[i].total_num * sizeof(struct ip_config_user **)))){
			tcf_free_network_control_policy(*user_items, i + 1);

			return TCF_ERR_NOMEM;
		}
		opt = 0;
		for(j = 0; j < uitems[i].total_num; j++){

			if(NULL == (uitems[i].item[j] = (struct ip_config_user *)httc_malloc(sizeof(struct ip_config_user)))){
				tcf_free_network_control_policy(*user_items, i + 1);
				return TCF_ERR_NOMEM;
			}

			cur = (struct ip_config *)((uint8_t *)cur_item->item + opt);
			(*(uitems[i].item[j])).from = ntohl(cur->be_from);
			(*(uitems[i].item[j])).id = ntohl(cur->be_id);
			(*(uitems[i].item[j])).status = ntohl(cur->be_status);
			(*(uitems[i].item[j])).to = ntohl(cur->be_to);


			opt += sizeof(struct ip_config);
		}
		op += sizeof(struct network_config_item);
		op += opt;
		op = HTTC_ALIGN_SIZE(op, 4);
		if(op > length)
		{
			httc_util_pr_error ("Length error %d(%d)!\n",op,length);
			tcf_free_network_control_policy(*user_items, i + 1);
			return TCF_ERR_OUTPUT_EXCEED;
		}

	}
	return TCF_SUCCESS;
}

/*
 * 	准备更新策略库。
 */
int tcf_prepare_update_network_control_policy(
		struct network_config_item_user *items,unsigned int num,
		unsigned char *tpcm_id,unsigned int tpcm_id_length,
		int action,uint64_t replay_counter,
		struct network_control_update **buffer,unsigned int *prepare_size){

	int ret = 0;
	int length = 0;
	struct network_config_item *data = NULL;

	if(tpcm_id_length != MAX_TPCM_ID_SIZE || buffer == NULL || prepare_size == NULL || tpcm_id == NULL) return TCF_ERR_PARAMETER;

	/*serialize file_protect_item_user data*/
	ret = tcf_util_network_control_policy_serialize(items,num,&length, &data);
	if(ret) return ret;
	if(NULL == (*buffer = httc_malloc(length + sizeof(struct network_control_update)))){
		httc_util_pr_error ("Req Alloc error!\n");
		if(data) httc_free(data);
		return TCF_ERR_NOMEM;
	}
//	httc_util_dump_hex((const char *)"tcf_util_network_control_policy_serialize",(uint8_t *)data,length);

	(*buffer)->be_size = ntohl(sizeof(struct network_control_update));
	(*buffer)->be_action = ntohl(action);
	(*buffer)->be_replay_counter = ntohll(replay_counter);
	(*buffer)->be_item_number = ntohl(num);
	(*buffer)->be_data_length = ntohl(length);
	memcpy((*buffer)->tpcm_id,tpcm_id,tpcm_id_length);

 if(length!=0)
 {
	memcpy((*buffer)->data, data, length);
}
//	httc_util_dump_hex((const char *)"update",(uint8_t *)*buffer,length + sizeof(struct network_control_update));

	*prepare_size = length + sizeof(struct network_control_update);

	if(data) httc_free(data);
	return TCF_SUCCESS;
}

/*
 * 	更新网络控制策略
 * 	设置、增加、删除。
 */
int tcf_update_network_control_policy(
		struct network_control_update *references,
		const char *uid,int cert_type,
		unsigned int auth_length,unsigned char *auth){

	int ret = 0;
	/*Check policy*/
	if( 0 != (ret = tcf_util_check_network_control_update(references))) return ret;

	ret = tcs_update_network_control_policy(references, uid, cert_type, auth_length, auth);

	if(ret) return ret;


	if ((ret = tsb_reload_network())){
		if(ret == -1){
			httc_util_pr_info ("tsb_reload_network : %d(0x%x)\n", ret, ret);
		}
		//return TCF_ERR_TSB;
	}
	//	httc_util_dump_hex((const char *)"references",(void *)references,1024);
	httc_write_version_notices (htonll (references->be_replay_counter), POLICY_TYPE_NETWORK_CONTROL);

	return 0;
}

/*
 *	读取网络控制策略
 */
int tcf_get_network_control_policy(struct network_config_item_user **references, unsigned int *inout_num){

		int ret = 0;
		int num = 0;
		int length = 0;
		struct network_config_item *items = NULL;

		ret = tcs_get_network_control_policy(&items, &num, &length);
		if(ret){
			if(items) httc_free(items);
			return ret;
		}

		ret = tcf_util_network_control_policy_extract(items, length, num, references);
		if(ret){
			if(items) httc_free(items);
			return ret;
		}
		*inout_num = num;
		if(items) httc_free(items);
		return TCF_SUCCESS;
}


/*
 *	释放文件保护内存
 */
void tcf_free_network_control_policy(struct network_config_item_user * pp,unsigned int num){
	if(pp){
		while (num--){

			while ((pp + num)->total_num--){
				if ((pp + num)->item[(pp + num)->total_num]){

					httc_free ((pp + num)->item[(pp + num)->total_num]);
				}
			}
			if((pp + num)->item) httc_free((pp + num)->item);

		}
		httc_free(pp);
	}

}




