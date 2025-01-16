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
#include "tcsapi/tcs_dev_protect.h"
#include "tcsapi/tcs_dev_protect_def.h"
#include "tcfapi/tcf_dev_protect.h"
#include "tcfapi/tcf_error.h"
#include "tsbapi/tsb_admin.h"

#include "tcfapi/tcf_dev_version.h"
#include "tcsapi/tcs_attest.h"

#include "httcutils/mem.h"
#include "httcutils/file.h"
#include "httcutils/debug.h"
#include "httcutils/convert.h"

int tcf_util_check_dev_protect_update(struct cdrom_protect_update *update)
{
	uint32_t rc = 0;
    uint32_t ref_total_len=0;
    uint64_t replay_counter = 0;
    uint8_t id[128] = {0};
	int id_len = sizeof(id);


    do{
	  if (ntohl(update->be_size) != sizeof(struct cdrom_protect_update))
		{
			rc = TCF_ERR_NOMEM;
			httc_util_pr_error("be_size[%u] != [%u]\n", (unsigned int)ntohl(update->be_size), (unsigned int)sizeof(struct cdrom_protect_update));
			break;
		}

	   replay_counter = ntohll(update->be_replay_counter);
		if (tcf_set_cdrom_version(replay_counter) != 0)
		{

			httc_util_pr_error("replay error update->be_replay_counter:%llu\r\n", (unsigned long long)replay_counter);
			rc = TCF_ERR_VERSION;
			break;
		}


		rc = tcs_get_tpcm_id(id, &id_len);
		if (rc)
		{
			httc_util_pr_error("[tcs_get_tpcm_id] ret: 0x%08x\n", rc);
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

		ref_total_len=sizeof(struct cdrom_protect_item)*ntohl(update->be_item_number);

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
int tcf_prepare_update_cdrom_protect_policy(
		struct cdrom_protect_item *items,unsigned int num,
		unsigned char *tpcm_id,unsigned int tpcm_id_length,
		int action,uint64_t replay_counter,
		struct cdrom_protect_update **buffer,unsigned int *prepare_size){


	int length = 0;
	int i=0;
	int offset=0;
	uint32_t be_flag=0;
	if(tpcm_id_length != MAX_TPCM_ID_SIZE || buffer == NULL || prepare_size == NULL || tpcm_id == NULL) return TCF_ERR_PARAMETER;
	length=num*sizeof(struct cdrom_protect_item);

	if(NULL == (*buffer = httc_malloc(length + sizeof(struct cdrom_protect_update)))){
		httc_util_pr_error ("Req Alloc error!\n");

		return TCF_ERR_NOMEM;
	}
//	httc_util_dump_hex((const char *)"tcf_util_file_protect_policy_serialize",(uint8_t *)data,length);

	(*buffer)->be_size = ntohl(sizeof(struct cdrom_protect_update));
	(*buffer)->be_action = ntohl(action);
	(*buffer)->be_replay_counter = ntohll(replay_counter);
	(*buffer)->be_item_number = ntohl(num);
	(*buffer)->be_data_length = ntohl(length);
	memcpy((*buffer)->tpcm_id,tpcm_id,tpcm_id_length);


 if(length!=0)
 {


//	httc_util_dump_hex((const char *)"update",(uint8_t *)*buffer,length + sizeof(struct cdrom_protect_update));
		for(i=0;i<num;i++)
		{
		be_flag=ntohl(items[i].be_flags);
		memcpy((*buffer)->data+offset, &be_flag, sizeof(uint32_t));
		offset+=sizeof(items[i].be_flags);
		}
 }



	*prepare_size = length + sizeof(struct cdrom_protect_update);


	return TCF_SUCCESS;
}

/*
 * 	更新光驱保护策略
 * 	支持设置。
 */


int tcf_update_cdrom_protect_policy(struct cdrom_protect_update *references,const char *uid,int cert_type,
		unsigned int auth_length,unsigned char *auth){

	int ret = 0;
/*Check policy*/
	if((ret = tcf_util_check_dev_protect_update(references)))
	{
		httc_util_pr_error("tcf_util_check_dev_protect_update:%d\r\n",ret);
		return ret;
	}

	ret = tcs_update_cdrom_protect_policy(references, uid, cert_type, auth_length, auth);
	if(ret)
	{
		httc_util_pr_error("tcs_update_cdrom_protect_policy:%d\r\n",ret);
		return ret;
	}

	if ((ret = tsb_reload_cdrom_config())){
		//if(ret == -1){
			httc_util_pr_info("tsb_reload_file_protect_policy : %d(0x%x)\n", ret, ret);
		//}

	}
	//	httc_util_dump_hex((const char *)"references",(void *)references,1024);
	httc_write_version_notices (htonll (references->be_replay_counter), POLICY_TYPE_DEV_PROTECT);

	return 0;
}

/*
 *	读取光驱保护策略
 */

int tcf_get_cdrom_protect_policy(struct cdrom_protect_item **references, unsigned int *inout_num){

		int ret = 0;
		int num = 0;
		int length = 0;
		int i=0;
		struct cdrom_protect_item *local_item;

		ret = tcs_get_cdrom_protect_policy(references, &num, &length);

		local_item=*references;
		for(i=0;i<num;i++)
		{
			local_item[i].be_flags=ntohl(local_item[i].be_flags);
		}
		*inout_num = num;

	//	httc_util_dump_hex((const char *)"references",(void *)*references,sizeof(struct cdrom_protect_item));
		return ret;
}



/*
 *	释放文件保护内存
 */
void tcf_free_dev_protect_policy(struct cdrom_protect_item * pp){
	if(pp){
		httc_free(pp);
	}

}






