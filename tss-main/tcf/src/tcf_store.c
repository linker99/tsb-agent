#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "tcf.h"
#include "tutils.h"
#include "httcutils/debug.h"
#include "tcsapi/tcs_constant.h"
#include "tcsapi/tcs_notice.h"
#include "tcsapi/tcs_store.h"
#include "tcfapi/tcf_store.h"
#include "tcfapi/tcf_error.h"
#include "tcfapi/tcf_attest.h"


/*
 * 	定义非易失存储空间
 */
int tcf_nv_define_space(
		uint32_t index, int size,
		unsigned char *ownerpasswd,unsigned char *usepasswd, uint32_t source){

	int ret =0;
	
	ret =  tcs_nv_define_space(index,size,ownerpasswd,usepasswd);	
	if(ret) return ret;

	httc_write_source_notices (source, POLICY_TYPE_STORE);
	return ret;
}

/*
 * 	根据策略定义非易失存储空间
 */
int tcf_nv_define_space_on_policy(
		uint32_t index, int size,
		unsigned char *ownerpasswd,
		struct auth_policy *policy, uint32_t source){

	int ret =0;
	
	
	ret =  tcs_nv_define_space_on_policy(index,size,ownerpasswd,policy);
	
	if(ret) return ret;
	
	httc_write_source_notices (source, POLICY_TYPE_STORE);
	return ret;
}
/*
 *	定义有名字的非易失存储空间
 *	会建立名字与索引的映射关系
 */
int tcf_nv_define_named_space(
		const char *name, int size,
		unsigned char *ownerpasswd,
		unsigned char *usepasswd,uint32_t source){

	int ret =0;
	
	
	ret =  tcs_nv_define_named_space(name,size,ownerpasswd,usepasswd);
	
	if(ret) return ret;
	
	httc_write_source_notices (source, POLICY_TYPE_STORE);
	return ret;
}

/*
 *	根据策略定义有名字的非易失存储空间
 *	会建立名字与索引的映射关系
 */
int tcf_nv_define_named_space_on_policy(
		const char *name,	int size,
		unsigned char *ownerpasswd,
		struct auth_policy *policy,uint32_t source){

	int ret =0;
	
	
	ret =  tcs_nv_define_named_space_on_policy(name,size,ownerpasswd,policy);
	
	if(ret) return ret;
	
	httc_write_source_notices (source, POLICY_TYPE_STORE);
	return ret;
}
/*
 * 	删除非易失存储空间
 */
int tcf_nv_delete_space(uint32_t index,unsigned char *ownerpasswd, uint32_t source){

	int ret =0;
	
	

	ret =  tcs_nv_delete_space(index,ownerpasswd);
	
	if(ret) return ret;
	
	httc_write_source_notices (source, POLICY_TYPE_STORE);
	return ret;
}

/*
 * 	通过名字删除非易失存储空间
 */
int tcf_nv_delete_named_space(const char *name,unsigned char *ownerpasswd, uint32_t source){

	int ret =0;
	
	
	ret =  tcs_nv_delete_named_space(name,ownerpasswd);
	
	if(ret) return ret;
	
	httc_write_source_notices (source, POLICY_TYPE_STORE);
	return ret;
}

/*
 * 写入非易失数据
 */
int tcf_nv_write(
		uint32_t index, int length,
		unsigned char *data, unsigned char *usepasswd){
	int ret;
	
	ret = tcs_nv_write(index,length,data,usepasswd);
	
	return ret;
}

/*
 * 	通过名字写入非易失数据
 */
int tcf_nv_named_write(
		const char *name, int length,
		unsigned char *data, unsigned char *usepasswd){
	int ret;
	
	ret = tcs_nv_named_write(name,length,data,usepasswd);
	
	return ret;
}
/*
 * 	读取非易失数据
 */
int tcf_nv_read(
		uint32_t index, int *length_inout,
		unsigned char *data, unsigned char *usepasswd){
	int ret;
	
	ret = tcs_nv_read(index,length_inout,data,usepasswd);
	
	return ret;
}

/*
 * 	通过名字读取非易失数据
 */
int tcf_nv_named_read(
		const char *name, int *length_inout,
		unsigned char *data, unsigned char *usepasswd){
	int ret;
	
	ret = tcs_nv_named_read(name,length_inout,data,usepasswd);
	
	return ret;
}

/*
 * 	读取命名非易失存储空间列表
 */
int tcf_read_nv_list(struct nv_info **array,int *number){
	int ret;
	
	ret = tcs_read_nv_list(array,number);
	
	return ret;
}

/*
 * 	释放NV信息内存
 */
void tcf_free_nv_list(struct nv_info *array,int number){
	return tcs_free_nv_list(array,number);
}

/*
 * 	设置nv信息列表
 */
int tcf_set_nv_list(struct nv_info *array, int number, uint32_t source){

	int ret =0;
	
	

	ret =  tcs_set_nv_list(array,number);
	
	if(ret) return ret;
	
	httc_write_source_notices (source, POLICY_TYPE_STORE);
	return ret;
}


/*
 * 	根据index查看nv是否已定义
 */
int tcf_is_nv_index_defined(uint32_t index){
	return tcs_is_nv_index_defined(index);
}

/*
 * 	根据name查看nv是否已定义
 */
int tcf_is_nv_name_defined(const char *name){
	return tcs_is_nv_name_defined(name);
}


/*
 * 保存易失数据
 */
int tcf_save_mem_data(
		uint32_t index, int length,
		unsigned char *data, char *usepasswd){

		return tcs_save_mem_data(index, length, data, usepasswd);
}

/*
 * 读取易失数据
 */
int tcf_read_mem_data(
		uint32_t index, int *length_inout,
		unsigned char *data, char *usepasswd){
	return tcs_read_mem_data(index, length_inout, data, usepasswd);
}


