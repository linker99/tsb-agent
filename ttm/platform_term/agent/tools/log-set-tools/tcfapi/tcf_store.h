/*
 * tcf_store.h
 *
 *  Created on: 2021��8��10��
 *      Author: qiuyao
 */

#ifndef TCFAPI_TCF_STORE_H_
#define TCFAPI_TCF_STORE_H_

#include "../tcsapi/tcs_auth_def.h"
#include "../tcsapi/tcs_store_def.h"

/*
 * 	定义非易失存储空间
 */
int tcf_nv_define_space(
		uint32_t index, int size,
		unsigned char *ownerpasswd,unsigned char *usepasswd, uint32_t source);

/*
// * 	根据策略定义非易失存储空间
 */
int tcf_nv_define_space_on_policy(
		uint32_t index, int size,
		unsigned char *ownerpasswd,
		struct auth_policy *policy, uint32_t source);
/*
 *	定义有名字的非易失存储空间
 *	会建立名字与索引的映射关系
 */
int tcf_nv_define_named_space(
		const char *name, int size,
		unsigned char *ownerpasswd,
		unsigned char *usepasswd,uint32_t source);

/*
 *	根据策略定义有名字的非易失存储空间
 *	会建立名字与索引的映射关系
 */
int tcf_nv_define_named_space_on_policy(
		const char *name,	int size,
		unsigned char *ownerpasswd,
		struct auth_policy *policy,uint32_t source);

/*
 * 	删除非易失存储空间
 */
int tcf_nv_delete_space(uint32_t index,unsigned char *ownerpasswd, uint32_t source);

/*
 * 	通过名字删除非易失存储空间
 */
int tcf_nv_delete_named_space(const char *name,unsigned char *ownerpasswd, uint32_t source);

/*
 * 写入非易失数据
 */
int tcf_nv_write(
		uint32_t index, int length,
		unsigned char *data, unsigned char *usepasswd);

/*
 * 	通过名字写入非易失数据
 */
int tcf_nv_named_write(
		const char *name, int length,
		unsigned char *data, unsigned char *usepasswd);
/*
 * 	读取非易失数据
 */
int tcf_nv_read(
		uint32_t index, int *length_inout,
		unsigned char *data, unsigned char *usepasswd);

/*
 * 	通过名字读取非易失数据
 */
int tcf_nv_named_read(
		const char *name, int *length_inout,
		unsigned char *data, unsigned char *usepasswd);

/*
 * 	读取命名非易失存储空间列表
 */
int tcf_read_nv_list(struct nv_info **array,int *number);

/*
 * 	释放NV信息内存
 */
void tcf_free_nv_list(struct nv_info *array,int number);

/*
 * 	设置nv信息列表
 */
int tcf_set_nv_list(struct nv_info *array, int number, uint32_t source);

/*
 *	根据index查看nv是否已定义
 */
int tcf_is_nv_index_defined(uint32_t index);

/*
 *	根据name查看nv是否已定义
 */
int tcf_is_nv_name_defined(const char *name);


/*
 * 保存易失数据
 */
int tcf_save_mem_data(
		uint32_t index, int length,
		unsigned char *data, char *usepasswd);

/*
 * 读取易失数据
 */
int tcf_read_mem_data(
		uint32_t index, int *length_inout,
		unsigned char *data, char *usepasswd);




#endif /* TCFAPI_TCF_STORE_H_ */
