/*
 * @Description:
 * @Author: huatai
 * @Date: 2022-05-20 14:12:28
 * @LastEditTime: 2022-06-08 09:47:19
 * @LastEditors: huatai
 */
#include <stdio.h>
#include <string.h>

#include "tutils.h"
#include "tcfapi/tcf_attest.h"
#include "tcsapi/tcs_constant.h"
#include "tcsapi/tcs_udisk_protect.h"
#include "tcsapi/tcs_udisk_protect_def.h"
#include "tcfapi/tcf_udisk_protect.h"
#include "tcfapi/tcf_error.h"
#include "tsbapi/tsb_admin.h"

#include "tcfapi/tcf_dev_version.h"
#include "tcsapi/tcs_attest.h"
#include "tcsapi/tcs_attest_def.h"

#include "httcutils/mem.h"
#include "httcutils/file.h"
#include "httcutils/debug.h"
#include "httcutils/convert.h"

int tcf_util_check_udisk_protect_update(struct udisk_protect_update *update)
{
	uint32_t rc = 0;
    uint32_t ref_total_len=0;
    uint64_t replay_counter = 0;
    uint8_t id[128] = {0};
	int id_len = sizeof(id);


    do{
	  if (ntohl(update->be_size) != sizeof(struct udisk_protect_update))
		{
			rc = TCF_ERR_NOMEM;
			httc_util_pr_error("be_size[%llu] != [%d]\n", (unsigned long long )ntohl(update->be_size), (int)sizeof(struct udisk_protect_update));
			break;
		}

	   replay_counter = ntohll(update->be_replay_counter);
		if (tcf_set_udisk_version(replay_counter) != 0)
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

		ref_total_len=sizeof(struct udisk_conf_item)*ntohl(update->be_item_number);

		if (ref_total_len != ntohl(update->be_data_length))
		{
			rc = TCF_ERR_BAD_DATA;
			httc_util_pr_error("cal data_size[%d],update->be_data_length[%d]\n", ref_total_len, ntohl(update->be_data_length));
			break;
		}
    }while(0);
	return rc;
}

/*
 * 	准备更新策略库。
 */
int tcf_prepare_update_udisk_protect_policy(
		struct udisk_conf_item *items,unsigned int num,
		unsigned char *tpcm_id,unsigned int tpcm_id_length,
		int action,uint64_t replay_counter,
		struct udisk_protect_update **buffer,unsigned int *prepare_size){


	int length = 0;
	int i=0,offset=0;
	uint32_t access_ctrl=0;
	if(tpcm_id_length != MAX_TPCM_ID_SIZE || buffer == NULL || prepare_size == NULL || tpcm_id == NULL) return TCF_ERR_PARAMETER;
	length=num*sizeof(struct udisk_conf_item);

	if(NULL == (*buffer = httc_malloc(length + sizeof(struct udisk_protect_update)))){
		httc_util_pr_error ("Req Alloc error!\n");

		return TCF_ERR_NOMEM;
	}

	(*buffer)->be_size = ntohl(sizeof(struct udisk_protect_update));
	(*buffer)->be_action = ntohl(action);
	(*buffer)->be_replay_counter = ntohll(replay_counter);
	(*buffer)->be_item_number = ntohl(num);
	(*buffer)->be_data_length = ntohl(length);
	memcpy((*buffer)->tpcm_id,tpcm_id,tpcm_id_length);

	if(length!=0)
	{
		for(i=0;i<num;i++)
		{
		access_ctrl=ntohl(items[i].access_ctrl);
		memcpy((*buffer)->data+offset, &access_ctrl, sizeof(uint32_t));
		offset+=sizeof(uint32_t);
		memcpy((*buffer)->data+offset, items[i].guid, __GUID_LENGTH);
		offset+=__GUID_LENGTH;
		}
	}
	//httc_util_dump_hex((const char *)"update",(uint8_t *)*buffer,length + sizeof(struct udisk_protect_update));

	*prepare_size = length + sizeof(struct udisk_protect_update);


	return TCF_SUCCESS;
}


/*
 * 	更新光驱保护策略
 * 	支持设置。
 */


int tcf_update_udisk_protect_policy(struct udisk_protect_update *references,const char *uid,int cert_type,
		unsigned int auth_length,unsigned char *auth){

	int ret = 0;
/*Check policy*/
	if( 0 != (ret = tcf_util_check_udisk_protect_update(references))) return ret;


	ret = tcs_update_udisk_protect_policy(references, uid, cert_type, auth_length, auth);
	if(ret) return ret;

	if ((ret = tsb_reload_udisk_config())){
		//if(ret == -1){
			httc_util_pr_info ("tsb_reload_file_protect_policy : %d(0x%x)\n", ret, ret);
	//	}
		//return TCF_ERR_TSB;
	}
	//	httc_util_dump_hex((const char *)"references",(void *)references,1024);
	httc_write_version_notices (htonll (references->be_replay_counter), POLICY_TYPE_UDISK_PROTECT);

	return 0;
}

/*
 *	读取光驱保护策略
 */

int tcf_get_udisk_protect_policy(struct udisk_conf_item **references, unsigned int *inout_num){

		int ret = 0;
		int num = 0;
		int length = 0;
		int i=0;

		struct udisk_conf_item *local_item;

		ret = tcs_get_udisk_protect_policy(references, &num, &length);
		local_item=*references;
		for(i=0;i<num;i++)
		{
			local_item[i].access_ctrl=ntohl(local_item[i].access_ctrl);

		}
		*inout_num = num;
		return ret;
}



/*
 *	释放文件保护内存
 */
void tcf_free_udisk_protect_policy(struct udisk_conf_item * pp){
	if(pp){
		httc_free(pp);
	}

}






