#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include <httcutils/sys.h>
#include <httcutils/mem.h>
#include <httcutils/file.h>
#include <httcutils/convert.h>
#include <httcutils/debug.h>
#include "tcfapi/tcf_file_integrity.h"
#include "tcsapi/tcs_file_integrity.h"
#include "tsbapi/tsb_admin.h"
#include "tcfapi/tcf_error.h"
#include "tcfapi/tcf_attest.h"

#include "tcsapi/tcs_notice.h"
#include "tcsapi/tcs_constant.h"
#include "tcf.h"
#include "tutils.h"
#include "file_integrity.h"

#define FILE_INTEGRITY_PATH 					HTTC_TSS_CONFIG_PATH"integrity.data"
#define CRITICAL_FILE_INTEGRITY_PATH 			HTTC_TSS_CONFIG_PATH"critical_integrity.data"
#define FILE_INTEGRITY_FILE_PATH 				HTTC_TSS_CONFIG_PATH"file_integrity_update/"
#define FILE_INTEGRITY_VERSION_PATH 			HTTC_TSS_CONFIG_PATH"integrity.version"
extern int is_intercept_measure_supported (void);

enum{
	FILE_INTEGRITY,
};


//static int build_ok;
static int build_integrity_data(void){
	unsigned long size = 0;
	int r;
	struct file_integrity_item **array = 0;
	unsigned int valid,total;
	//if(build_ok)return 0;
	void *rbuffer = 0;
	file_integrity_reset();
	r =  httc_util_file_size(FILE_INTEGRITY_PATH,&size);
	if(r && is_intercept_measure_supported()){
		uint32_t num;
		int length;
		httc_util_pr_dev("INTEGRITY File does not exist,Try to reading from TPCM\n");
		r = tcs_get_file_integrity((struct file_integrity_item **)&rbuffer,
				&num, &length);
		if(r){
			httc_util_pr_error("Reading from tpcm failed,r=%d\n",r);
			return r;
		}
		else{
			size = length;
			if ((r = httc_util_create_path_of_fullpath (FILE_INTEGRITY_PATH))){
				httc_util_pr_error("Create INTEGRITY File path failed\n");
				if(rbuffer)httc_free(rbuffer);
				return TCF_ERR_DIR;
			}
			r = httc_util_file_write(FILE_INTEGRITY_PATH,rbuffer,length);
			if(r != length){
				httc_util_pr_error("Writing INTEGRITY File failed\n");
				if(rbuffer)httc_free(rbuffer);
				return TCF_ERR_FILE;
			}
		}
	}
	if(size == 0){
		//build_ok =1;
		return 0;
	}
	if(!rbuffer){
		rbuffer = httc_util_file_read_full(FILE_INTEGRITY_PATH,&size);
		if(!rbuffer){
			httc_util_pr_error("Reading INTEGRITY File failed\n");
			return TCF_ERR_FILE;
		}
	}

	//httc_util_dump_hex("INTEGRITY data ", rbuffer,size);

	r = file_integrity_hash_policy_data(rbuffer,size,
				&array,&total,&valid);
	if(array){
		file_integrity_append_hashed_array(array,total,valid,size);
		httc_free(array);
	}
	//r = file_integrity_add_policy_data(rbuffer,size,0);
	httc_free(rbuffer);
	//if(!r)build_ok =1;
	return r;
}
void reset_integrity_data(void){
	//clear all;
	file_integrity_reset();
	//build_ok = 1;

}
static void httc_free_file_integrity_item_user(
		struct file_integrity_item_user *references,int item_number){
	int i;
	struct file_integrity_item_user *item = references;
	for(i=0;i<item_number;i++,item++){
		if(item->hash)httc_free(item->hash);
		//if(item->name)httc_free(item->name);
		//if(item->path)httc_free(item->path);
		//if(item->extend_buffer)httc_free(item->extend_buffer);
	}
	httc_free(references);
}

struct parse_context{
	struct file_integrity_item_user  *data;
	unsigned int valid;
};
static int file_integrity_parser(struct file_integrity_item_info *item,void *context){
	struct parse_context *pcontex = context;
	struct file_integrity_item_user *item_data =
			pcontex->data + pcontex->valid;
	item_data->hash = httc_malloc(item->aligned_size);
	if(!item_data->hash){
		httc_util_pr_error("no memory\n");
		return TCF_ERR_NOMEM;
	}
	memset(item_data->hash,0,item->aligned_size);
	item_data ->hash_length = DEFAULT_HASH_SIZE;
	item_data->extend_size = item->data.extend_size;
	item_data->path_length = item->path_length;
	item_data->is_enable = item->data.flags & (1 << FILE_INTEGRITY_FLAG_ENABLE)?1:0;
	item_data->is_control = item->data.flags & (1 << FILE_INTEGRITY_FLAG_CONTROL)?1:0;
	item_data->is_full_path = item->data.flags & (1 << FILE_INTEGRITY_FLAG_FULL_PATH)?1:0;
	memcpy(item_data->hash,item->data.data,item->size);
	// tcf_util_dump_hex("data ",item->data.data,item->size);
	if(item_data->extend_size != 0){
		item_data->extend_buffer = 	item_data->hash + item_data ->hash_length;
	}
	if(item_data->path_length != 0){
		item_data->path = item_data->hash + item_data ->hash_length + item_data->extend_size;
	}
	pcontex->valid++;
	return 0;
}


// white list (program reference) interface
/*
 * 	读取基准库
 */
int tcf_get_file_integrity(struct file_integrity_item_user **references,
		unsigned int from,unsigned int *inout_num){
	int r = 0;
	struct file_integrity_item_user  *data;
	unsigned int max_num = *inout_num;
	struct parse_context pcontext;

	if ((r = tcf_util_sem_get (TCF_SEM_INDEX_INTEGRITY)))	return r;

	if((r = build_integrity_data())){
		tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
		return r;
	}
	if(file_integrity_valid() < from){
		*inout_num = 0;
		tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
		return 0;
	}
	if(max_num > file_integrity_valid() - from) max_num = file_integrity_valid() - from;
	if(max_num == 0){
		//if(rbuffer)httc_free(rbuffer);
		*inout_num = 0;
		tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
		return 0;
	}
	data = httc_calloc(max_num,sizeof(struct file_integrity_item_user));
	if(!data){
		httc_util_pr_error("No memory\n");
		tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
		return TCF_ERR_NOMEM;
	}
	memset(data,0,sizeof(struct file_integrity_item_user) * max_num);
	pcontext.data = data;
	pcontext.valid = 0;
	r = file_integrity_iterator(from,*inout_num,file_integrity_parser,&pcontext);
	if(r){
		httc_free_file_integrity_item_user(data,pcontext.valid);
	}
	else{
		*references = data;
		*inout_num = pcontext.valid;
	}

	tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
	return r;
}//proc 导出


/*
 * 	准备更新基准库。
 */
int tcf_prepare_update_file_integrity(
		struct file_integrity_item_user *items,unsigned int num,
		unsigned char *tpcm_id,unsigned int tpcm_id_length,
		int action,uint64_t replay_counter,
		struct file_integrity_update **buffer,unsigned int *prepare_size){
	unsigned char *data,*pos;
	int i;
	int r = 0;
	unsigned int data_len;
	if(tpcm_id_length == 0  || tpcm_id_length > MAX_TPCM_ID_SIZE){
		httc_util_pr_error("bad id length\n");
		return TCF_ERR_PARAMETER;
	}
//	for(i=0;i<num;i++){
//
//	}
	data = httc_malloc(sizeof(struct file_integrity_update)
			+ MAX_FILE_INTEGRITY_ITEM_SIZE * num);
	if(!data){
		httc_util_pr_error("No memory\n");
		return TCF_ERR_NOMEM;
	}
	struct file_integrity_update *update = (struct file_integrity_update *)data;
	update->be_action = htonl((uint32_t)action);
	//update->be_data_length
	update->be_item_number = htonl((uint32_t)num);
	update->be_replay_counter = htonll(replay_counter);
	update->be_size = htonl (sizeof(struct file_integrity_update));
	memcpy(update->tpcm_id,tpcm_id,tpcm_id_length);
	pos = (unsigned char *)(update + 1);
	for(i=0;i<num;i++){
		struct file_integrity_item *item  = (struct file_integrity_item *)pos;
		if(!items[i].hash){
			r = TCF_ERR_PARAMETER;
			httc_util_pr_error("Hash required\n");
			break;
		}
		if(items[i].extend_buffer &&
				(items[i].extend_size <= 0 ||
						items[i].extend_size >= ((1 << 8 * sizeof(item->extend_size)) - 1))){
			r = TCF_ERR_PARAMETER;
			httc_util_pr_error("Invalid extend_size\n");
			break;
		}
		if(items[i].hash_length != DEFAULT_HASH_SIZE){
			r = TCF_ERR_PARAMETER;
			httc_util_pr_error("Invalid hash_length\n");
			break;
		}
		if(items[i].path &&
			((!items[i].is_full_path && items[i].path_length != DEFAULT_HASH_SIZE)
				||(items[i].path_length < 0 || items[i].path_length > MAX_PATH_LENGTH))
			){
			r = TCF_ERR_PARAMETER;
			httc_util_pr_error("Invalid path_length\n");
			break;
		}

		if (!is_bool_value_legal(items[i].is_enable)){
			r = TCF_ERR_PARAMETER;
			httc_util_pr_error ("Invalid flag, is_enable:%d, not in (ture,false)\n", items[i].is_enable);
			break;
		}
		if (!is_bool_value_legal(items[i].is_control)){
			r = TCF_ERR_PARAMETER;
			httc_util_pr_error ("Invalid flag, is_control:%d, not in (ture,false)\n", items[i].is_control);
			break;
		}
		if (!is_bool_value_legal(items[i].is_full_path)){
			r = TCF_ERR_PARAMETER;
			httc_util_pr_error ("Invalid flag, is_full_path:%d, not in (ture,false)\n", items[i].is_full_path);
			break;
		}
		item->flags = items[i].is_enable ?
				1  << FILE_INTEGRITY_FLAG_ENABLE :0;
		if(items[i].is_control) item->flags |= 1 << FILE_INTEGRITY_FLAG_CONTROL;
		if(items[i].is_full_path) item->flags |= 1 << FILE_INTEGRITY_FLAG_FULL_PATH;
		item->extend_size = items[i].extend_size;
		item->be_path_length = htons(items[i].path_length);
		memcpy(item->data,items[i].hash,items[i].hash_length);
		data_len =  items[i].hash_length;
		if(items[i].extend_buffer){
			memcpy(item->data + data_len,items[i].extend_buffer,items[i].extend_size);
			data_len += items[i].extend_size;
		}
		if(items[i].path){
			memcpy(item->data + data_len,items[i].path,items[i].path_length);
			data_len += items[i].path_length;
		}
		pos += sizeof(struct file_integrity_item) + HTTC_ALIGN_SIZE(data_len,4);
	}

	if(r){
		httc_free(data);
		return r;
	}
	update->be_data_length = htonl((uint32_t)(pos - data - sizeof(struct file_integrity_update)));
	*prepare_size = pos - data;
	*buffer = update;
	return 0;
}
struct delete_item{
	struct file_integrity_item *item;
	const char *path;
	int path_length;
	int finished;
};

int tcf_update_file_integrity_digest (unsigned char *digest ,unsigned int digest_len);

static int file_integrity_set(
				struct file_integrity_update *references,
				const char *uid,int cert_type,
				int auth_length,unsigned char *auth){
	int r ;
	struct file_integrity_item **array = 0;
	unsigned int valid,total;
	unsigned data_length = 	ntohl(references->be_data_length);
	uint8_t digest[DEFAULT_HASH_SIZE] = {0};
	
	reset_integrity_data();

	r = file_integrity_hash_policy_data((char *)(references + 1),data_length,
			&array,&total,&valid);
	if(r){
		httc_util_pr_error("hash data error %d\n",r);
		return r;
	}
	r = tcs_update_file_integrity(references,uid,cert_type,auth_length,auth);
	if( r ){
		if(array){
			file_integrity_delete_from_hashtable_array(array,valid);
			httc_free(array);
		}
		file_integrity_reset();
		httc_util_pr_error("tcs_update_file_integrity error %d\n",r);
		return r;
	}
	if ((r = httc_util_create_path_of_fullpath (FILE_INTEGRITY_PATH))){
		if(array){
			file_integrity_delete_from_hashtable_array(array,valid);
			httc_free(array);
		}
		file_integrity_reset();
		httc_util_pr_error("Create File path failed\n");
		return TCF_ERR_DIR;
	}
	r  =  httc_util_file_write(FILE_INTEGRITY_PATH,(char *)(references + 1),data_length);
	if( r !=  data_length){
		if(array){
			file_integrity_delete_from_hashtable_array(array,valid);
			httc_free(array);
		}
		file_integrity_reset();
		httc_util_pr_error("write file error %d\n",r);
		return TCF_ERR_FILE;
	}
	file_integrity_append_hashed_array(array,total,valid,data_length);
	httc_free(array);

	if( 0 != (r = httc_get_file_digest((const char *) FILE_INTEGRITY_PATH, digest))){
		httc_util_pr_error("httc_get_file_digest error %d\n",r);
		return r;
	}
	if( 0 != (r = tcf_update_file_integrity_digest(digest, DEFAULT_HASH_SIZE))){
		httc_util_pr_error("tcf_update_file_integrity_digest error %d\n",r);
		return r;
	}
	
	if ((r = tsb_reload_file_integrity())){
		if(r == -1){
			httc_util_pr_info ("tsb_reload_file_integrity : %d(0x%x)\n", r, r);
			}
		//return TCF_ERR_TSB;
	}
	
	return 0;
}

				
static int file_integrity_add(
		struct file_integrity_update *references,
		const char *uid,int cert_type,
		int auth_length,unsigned char *auth){
	int r;
	struct file_integrity_item **array = 0;
	unsigned int valid,total;
	unsigned int data_length = 	ntohl(references->be_data_length);
	uint8_t digest[DEFAULT_HASH_SIZE] = {0};
	
	r = build_integrity_data();
	if(r){return r;	}
	r = file_integrity_hash_policy_data((char *)(references + 1),data_length,
			&array,&total,&valid);
	if(r){
		httc_util_pr_error("hash data error %d\n",r);
		return r;
	}

	r = tcs_update_file_integrity(references,uid,cert_type,auth_length,auth);
	if( r ){
		file_integrity_delete_from_hashtable_array(array,valid);
		httc_free(array);
		//file_integrity_clear_list(head);
		httc_util_pr_error("tcs_update_file_integrity error %d\n",r);
		return r;
	}
	unsigned long fsize;
	r =  httc_util_file_size(FILE_INTEGRITY_PATH,&fsize);
	if(r)fsize = 0;
//	if(r){
//		file_integrity_delete_from_hashtable_array(array,valid);
//		httc_free(array);
//		httc_util_pr_error("write file error %d\n",r);
//		return r;
//	}
	int align_fsize =  HTTC_ALIGN_SIZE(fsize,4);
	if(align_fsize > fsize){
		char fill[4] = {0};
		r =  httc_util_file_append(
				FILE_INTEGRITY_PATH,fill,align_fsize - fsize);
		if( r !=  align_fsize - fsize){
			file_integrity_delete_from_hashtable_array(array,valid);
			httc_free(array);
			httc_util_pr_error("write file error %d\n",r);
			return TCF_ERR_FILE;
		}
	}
	r  =  httc_util_file_append(FILE_INTEGRITY_PATH,
			(char *)(references + 1),data_length);
	if( r !=  data_length){
		file_integrity_delete_from_hashtable_array(array,valid);
		httc_free(array);
		httc_util_pr_error("write file error error %d\n",r);
		return TCF_ERR_FILE;
	}
	file_integrity_append_hashed_array(array,total,valid,data_length);
	httc_free(array);

	if( 0 != (r = httc_get_file_digest((const char *) FILE_INTEGRITY_PATH, digest))){
		httc_util_pr_error("httc_get_file_digest error %d\n",r);
		return r;
	}
	if( 0 != (r = tcf_update_file_integrity_digest(digest, DEFAULT_HASH_SIZE))){
		httc_util_pr_error("tcf_update_file_integrity_digest error %d\n",r);
		return r;
	}
	
	if ((r = tsb_add_file_integrity((char *)(references+1),data_length))){
		if(r == -1){
			httc_util_pr_info ("tsb_add_file_integrity: %d(0x%x)\n", r, r);
			}
		//return TCF_ERR_TSB;
	}	
	
	return 0;

}
//struct delete_record{
//	void *pos;
//	int length;
//};
//static int delete_integrity_one(
//		struct file_integrity_item *current, int aligned_item_length,
//		struct delete_record *record,
//		struct delete_item *del_items,int del_num){
//	int i;
//	for(i=0;i<del_num;i++){
//		if(del_items[i].finished)continue;
//		if(	current->be_path_length == del_items[i].item->be_path_length
//				&&!memcmp(current->data,del_items[i].item->data,DEFAULT_HASH_SIZE)){
//			if(del_items[i].path_length == 0
//			|| &&!memcmp(current->data + current->extend_size + DEFAULT_HASH_SIZE,
//					del_items[i].path,del_items[i].path_length
//					)
//			){
//				del_items[i].finished = 1;
//				record->pos = current;
//				record->length = aligned_item_length;
//				memcpy(del_items + i,del_items + del_num -1,sizeof(struct delete_item));
//				return  1;
//			}
//		}
//	}
//	return 0;
//}
static char ZERO_ARRAY[1024];
static int file_integrity_del(
		struct file_integrity_update *references,
		const char *uid,int cert_type,
		int auth_length,unsigned char *auth){
	int r,i;
	unsigned int data_length = 	ntohl(references->be_data_length);
	//struct file_integrity_item *head;
	struct file_integrity_item_info **dellist = 0;
	unsigned int del_num;
	uint8_t digest[DEFAULT_HASH_SIZE] = {0};

	r = build_integrity_data();
	if(r){
		//httc_util_pr_error("parse fail %d\n",r);
		return r;
	}
	r = file_integrity_delete_policy_data_prepare(
			(char *)(references + 1),data_length
			,&dellist,&del_num);
	if( r){
		//httc_util_pr_error("delete data error %d\n",r);
		return -1;
	}
	
	r = tcs_update_file_integrity(references,uid,cert_type,auth_length,auth);
	if( r ){
		if(dellist)httc_free(dellist);
		httc_util_pr_error("tcs_update_file_integrity error %d\n",r);
		return r;
	}

	if(dellist){
		struct file_section *sections = httc_malloc(sizeof(struct file_section ) * del_num);
		if(!sections){
			httc_free(dellist);
			printf("No memory write file\n");
			return TCF_ERR_NOMEM;
		}
		for(i=0;i<del_num;i++){
			printf("del item %p,offset=%d,aligned_size=%d\n",dellist[i],
					dellist[i]->offset,dellist[i]->aligned_size);
			sections[i].buffer = ZERO_ARRAY;
			sections[i].offset = dellist[i]->offset +
					sizeof(struct file_integrity_item);
			sections[i].length = dellist[i]->aligned_size
					- sizeof(struct file_integrity_item);
		}
		r = httc_util_file_write_offset_array(FILE_INTEGRITY_PATH,
				sections,del_num);
		if(r){
			httc_free(sections);
			httc_free(dellist);
			return r;
		}
		r = file_integrity_delete_policy_data(dellist,del_num);
		httc_free(sections);
		httc_free(dellist);
	}

	if( 0 != (r = httc_get_file_digest((const char *) FILE_INTEGRITY_PATH, digest))){
		httc_util_pr_error("httc_get_file_digest error %d\n",r);
		return r;
	}
	if( 0 != (r = tcf_update_file_integrity_digest(digest, DEFAULT_HASH_SIZE))){
		httc_util_pr_error("tcf_update_file_integrity_digest error %d\n",r);
		return r;
	}
	if ((r = tsb_remove_file_integrity((char *)(references+1),data_length))){
		if(r == -1){
			httc_util_pr_info ("tsb_remove_file_integrity: %d(0x%x)\n", r, r);
			}
		//return TCF_ERR_TSB;
	}
	
	return r;
}

static int check_file_integrity_version(uint64_t version,int tag){

	int ret = 0;
	int sub_ver = 0;
	uint64_t major_ver = 0;
	DIR *dir = NULL;
	struct dirent *Dirent = NULL;
	const char cut[2] = "-";
	char *token = NULL;

	if(tag == FILE_INTEGRITY){
		
		if(access((const char *)FILE_INTEGRITY_FILE_PATH,0)!=0){
	//		printf("path:%s\n",FILE_INTEGRITY_VERSION_PATH);
			ret = httc_util_create_path((const char *)FILE_INTEGRITY_FILE_PATH);
			if(ret){
				httc_util_pr_error("create file error %d\n",ret);
				return TCF_ERR_FILE;
			}
		}
		
		if(NULL == (dir = opendir(FILE_INTEGRITY_FILE_PATH))){
			perror("opendir");
			httc_util_pr_error(" Path wrong %s.\n", FILE_INTEGRITY_FILE_PATH);
			return TCF_ERR_PARAMETER;
		}

		sub_ver = get_sub_version(version);
		major_ver = get_major_version(version);
			
		while(1)
		{			
			if(NULL == (Dirent = readdir(dir))) break;
			if (strncmp(Dirent->d_name,".",1)==0) continue;
			if (Dirent->d_type == 8 &&(strncmp(Dirent->d_name + (strlen(Dirent->d_name) - 6),"record",6)==0)){	

				/**Check major version**/
				token = strtok(Dirent->d_name,cut);
				if(!token) {
					httc_util_pr_error("File error! (%s)\n",Dirent->d_name);
					closedir(dir);
					return TCF_ERR_PARAMETER;
				}
				if(major_ver < atol(token)){
					httc_util_pr_error("Version error! old major_ver:0x%016lX, version: 0x%016lX\n",(long unsigned int)atol(token),(long unsigned int)version);
					closedir(dir);
					return TCF_ERR_VERSION;
				}else if(major_ver == atol(token)){
					
					/**Check sub version**/
					token = strtok(NULL,cut);
					if(token){
							if(sub_ver < atoi(token)){
							httc_util_pr_error("Version error! old sub_ver:0x%08X, version: 0x%016lX\n",(unsigned int)atoi(token),(long unsigned int)version);
							closedir(dir);
							return TCF_ERR_VERSION;
						}
					}					
				}
			}
		}
	}
	closedir(dir);
	return TCF_SUCCESS;	
}


static int update_file_integrity_version(uint64_t version, uint32_t action, uint8_t *data, uint32_t length, int tag){

	int ret = 0;
	int sub_ver = 0;
	uint64_t major_ver = 0;
	char filename[256] = {0};

	if(tag == FILE_INTEGRITY){
		if(data == NULL) return TCF_ERR_PARAMETER;
		sub_ver = get_sub_version(version);
		major_ver = get_major_version(version);
		
		if(action == POLICY_ACTION_ADD){
			
			sprintf(filename,"%s%ld-%d-add.record",FILE_INTEGRITY_FILE_PATH,(long int)major_ver,sub_ver);
			ret = httc_util_file_write((const char *)filename, (const char *)data, length);
			if(ret != length){
				httc_util_pr_error("write file error %d\n",ret);
				return TCF_ERR_FILE;
			}
			
		}else if(action == POLICY_ACTION_DELETE){
			
			sprintf(filename,"%s%ld-%d-del.record",FILE_INTEGRITY_FILE_PATH,(long int)major_ver,sub_ver);
			ret = httc_util_file_write((const char *)filename, (const char *)data, length);
			if(ret != length){
				httc_util_pr_error("write file error %d\n",ret);
				return TCF_ERR_FILE;
			}
		}else if(action == POLICY_ACTION_SET){

			ret = httc_util_rm(FILE_INTEGRITY_FILE_PATH"*");
			if(ret){
				httc_util_pr_error("httc_util_rm %s  error\n", FILE_INTEGRITY_FILE_PATH);
				return TCF_ERR_FILE;
			}
			
			sprintf(filename,"%s%ld-%d-set.record",FILE_INTEGRITY_FILE_PATH,(long int)major_ver,sub_ver);
			ret = httc_util_file_write((const char *)filename, (const char *)data, length);
			if(ret != length){
				httc_util_pr_error("write file error %d\n",ret);
				return TCF_ERR_FILE;
			}
		}else{
				httc_util_pr_error("Unsupported action\n");
				return TCF_ERR_PARAMETER;
		}

	}

	return TCF_SUCCESS;	
}

int httc_get_file_integrity_subver(uint64_t version,uint32_t *sub){

	int ret = 0;
	int sub_ver_old = 0;
	int sub_ver_new = 0;
	DIR *dir = NULL;
	struct dirent *Dirent = NULL;
	const char cut[2] = "-";
	char *token = NULL;

	if(access((const char *)FILE_INTEGRITY_FILE_PATH,0)!=0){
//		printf("path:%s\n",FILE_INTEGRITY_VERSION_PATH);
		ret = httc_util_create_path((const char *)FILE_INTEGRITY_FILE_PATH);
		if(ret){
			httc_util_pr_error("create file error %d\n",ret);
			return TCF_ERR_FILE;
		}
	}
	
	if(NULL == (dir = opendir(FILE_INTEGRITY_FILE_PATH))){
		perror("opendir");
		httc_util_pr_error(" Path wrong %s.\n", FILE_INTEGRITY_FILE_PATH);
		return TCF_ERR_PARAMETER;
	}
		
	while(1)
	{			
		if(NULL == (Dirent = readdir(dir))) break;
		if (strncmp(Dirent->d_name,".",1)==0) continue;
		if (Dirent->d_type == 8 &&(strncmp(Dirent->d_name + (strlen(Dirent->d_name) - 6),"record",6)==0)){	

			/**Check major version**/
			token = strtok(Dirent->d_name,cut);
			if(!token) {
				httc_util_pr_error("File error! (%s)\n",Dirent->d_name);
				closedir(dir);
				return TCF_ERR_PARAMETER;
			}
			if(version == atol(token)){					
				/**Check sub version**/
				token = strtok(NULL,cut);
				if(token){
					sub_ver_new = atoi(token);
					if(sub_ver_new > sub_ver_old){
						sub_ver_old = sub_ver_new;
					}
				}else{
					httc_util_pr_error("File error! (%s)\n",Dirent->d_name);
					closedir(dir);
					return TCF_ERR_PARAMETER;
				}					
			}
		}
	}		
	closedir(dir);
	*sub =  sub_ver_old;
	return TCF_SUCCESS;
}

/*
 * 	更新文件完整性基准库
 * 	设置、增加、删除。
 */

int tcf_update_file_integrity(
		struct file_integrity_update *references,
		const char *uid,int cert_type,
		unsigned int auth_length,unsigned char *auth,
		unsigned char *local_ref, unsigned int local_ref_length){

	int ret = 0;
	int number = ntohl(references->be_item_number);
	int action = ntohl(references->be_action);
	unsigned int data_length = ntohl(references->be_data_length);
	uint64_t version = ntohll(references->be_replay_counter);
	
	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_INTEGRITY)))	return ret;
	if((ret = check_file_integrity_version(version,FILE_INTEGRITY))){
		tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
		return ret;
	}
	
	//check hash match
	if(data_length < 0){
		tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
		return TCF_ERR_PARAMETER;
	}
	
	if(action == POLICY_ACTION_SET){
		ret = file_integrity_set(references,uid,cert_type,auth_length,auth);
	}
	else if(action == POLICY_ACTION_ADD){
		if(data_length < 0){
			tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
			return TCF_ERR_PARAMETER;
		}
		ret = file_integrity_add(references,uid,cert_type,auth_length,auth);
	}
	else if((action == POLICY_ACTION_DELETE) && number){
		if(data_length < 0){
			tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
			return TCF_ERR_PARAMETER;
		}
		ret = file_integrity_del(references,uid,cert_type,auth_length,auth);
	}
	else{
		httc_util_pr_error("Unsupported action\n");
		tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
		return TCF_ERR_PARAMETER;
	}
	
	if(!ret){
		if(local_ref_length 
			&& (0 != (ret = update_file_integrity_version(version,action,local_ref,local_ref_length,FILE_INTEGRITY))))
			goto out;
		httc_write_version_notices (ntohll (references->be_replay_counter), POLICY_TYPE_FILE_INTEGRITY);
	}

out:
	tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
	return ret;
}

/*
 *	释放基准库内存
 */
void tcf_free_file_integrity(struct file_integrity_item_user * pp,unsigned int num){
	httc_free_file_integrity_item_user(pp,num);
	//return 0;
}
///*
// * 	通过HASH查找程序基准库
// */
//int tcf_get_file_integrity_by_hash(
//		struct file_integrity_item_user ** pp,int *num,
//		const unsigned char *hash, int hash_length);

///*
// * 	通过名字查找程序基准库
// */
//int tcf_get_file_integrity_by_name(
//		int *num,struct file_integrity_item_user ** pp,
//		const unsigned char *name, int path_length);

///*
// * 	通过路径查找基准库
// */
//int tcf_get_file_integrity_by_path(
//		int *num,struct file_integrity_item_user ** pp,
//		const unsigned char *path, int path_length);


///*
// * 	基准库按名字名匹配
// */
//int tcf_match_file_integrity_by_name(
//		const unsigned char *hash, int hash_length,
//		const unsigned char *name, int name_length);
///*
// * 	基准库按名字和路径匹配
// */
//int tcf_match_file_integrity_by_name_and_path(
//		const unsigned char *hash, int hash_length,
//		const unsigned char *name, int name_length,
//		const unsigned char *path, int path_length);
/*
 *	获取基准库有效条数
 */

int tcf_get_file_integrity_valid_number(uint32_t *num)
{
	int r;
	if ((r = tcf_util_sem_get (TCF_SEM_INDEX_INTEGRITY)))	return r;
	if (!(r = build_integrity_data ())){
		*num = file_integrity_valid ();
	}
	tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
	return r;
	//return tcs_get_file_integrity_valid_number(num);
}//proc 导出
/*
 * 	获取基准库存储条数
 */
int tcf_get_file_integrity_total_number(uint32_t *num)
{
	int r;
	if ((r = tcf_util_sem_get (TCF_SEM_INDEX_INTEGRITY)))	return r;
	if (!(r = build_integrity_data ())){
		*num = file_integrity_total ();
	}
	tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
	return r;
	//return tcs_get_file_integrity_total_number(num);
}//proc 导出

/*
 *	获取基准库可增量修改限制
 */

int tcf_get_file_integrity_modify_number_limit(uint32_t *num)
{
	int r;
	if (is_intercept_measure_supported ()){
		return  tcs_get_file_integrity_modify_number_limit(num);
	}else{
		if ((r = tcf_util_sem_get (TCF_SEM_INDEX_INTEGRITY)))	return r;
		r = build_integrity_data ();
		if (!r){
			*num = file_integrity_modify_limit ();
		}
		tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
		return 0;
	}
	
}//proc 导出

/*
 * 获取文件完整性同步数据
 */
static int get_file_integrity_number(int *number){

	int num = 0;
	DIR *dir = NULL;
	struct dirent *Dirent = NULL;

	if(NULL == (dir = opendir(FILE_INTEGRITY_FILE_PATH))){
//		perror("opendir");
//		httc_util_pr_error(" Path wrong %s.\n", FILE_INTEGRITY_FILE_PATH);
		*number = 0;
		return TCF_SUCCESS;
	}

	while(1)
	{			
		if(NULL == (Dirent = readdir(dir))) break;
		if (strncmp(Dirent->d_name,".",1)==0) continue;
		if (Dirent->d_type == 8 &&(strncmp(Dirent->d_name + (strlen(Dirent->d_name) - 6),"record",6)==0))	num ++;
	}

	closedir(dir);
	*number = num;
	return TCF_SUCCESS;
}

int tcf_get_synchronized_file_integrity (struct sync_version *version, struct file_integrity_sync **file_integrity, int *num){

	
	int n = 0;
	int ret = 0;
	int number = 0;
	int sub_ver = 0;
	uint64_t major_ver = 0;
	uint32_t action = 0;
	DIR *dir = NULL;
	struct dirent *Dirent = NULL;
	char filename[512] = {0};
	unsigned long datalen = 0;
	char str[20] = {0};
	char *s_str = NULL; 
	const char cut[2] = "-";
	char *token = NULL; 
	struct file_integrity_sync *file = NULL;

	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_INTEGRITY))) return ret;
	if(0 != (ret = get_file_integrity_number(&number))) {
		tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
		return ret;
	}
	if(number == 0){
		*num = 0;
		tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
		return TCF_SUCCESS;
	} 
	
	if (NULL == (file = (struct file_integrity_sync *)httc_malloc (number * sizeof(struct file_integrity_sync)))){
		httc_util_pr_error (" Req Alloc error!\n");
		tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
		return TCF_ERR_NOMEM;
	}
	
	if(NULL == (dir = opendir(FILE_INTEGRITY_FILE_PATH))){
		httc_free(file);
		perror("opendir");
		httc_util_pr_error(" Path wrong %s.\n", FILE_INTEGRITY_FILE_PATH);
		tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
		return TCF_ERR_PARAMETER;
	}

		
	while(1)
	{			
		if(NULL == (Dirent = readdir(dir))) break;
		if (strncmp(Dirent->d_name,".",1)==0) continue;
		if (Dirent->d_type == 8 &&(strncmp(Dirent->d_name + (strlen(Dirent->d_name) - 6),"record",6)==0))		 
		{	
			memset(str,0,20);
			memcpy(str,Dirent->d_name,strlen(Dirent->d_name) - 7);
		
			/**Get major version**/
			token = strtok_r(str,cut,&s_str);
			if(!token) continue;
			major_ver = atol(token);
			

			/**Get sub version**/
			token = strtok_r(NULL,cut,&s_str);
			if(!token) continue;  
			sub_ver = atoi(token);

			/**Get action**/
			token = strtok_r(NULL,cut,&s_str);
			if(!token) continue;
			if(token){
				if(!strcmp(token,"add")){
					action = POLICY_ACTION_ADD;
				}else if(!strcmp(token,"del")){
					action = POLICY_ACTION_DELETE;
				}else if(!strcmp(token,"set")){
					action = POLICY_ACTION_SET;
				}
			}
			
			if(major_ver >= version->smajor &&
			  major_ver <= version->emajor){			  

				  file[n].smajor = major_ver;
				  file[n].sminor = sub_ver;
				  file[n].action = action;

				  memset(filename,0,512);
				  sprintf(filename,"%s%s",FILE_INTEGRITY_FILE_PATH,Dirent->d_name);
				  file[n].data = httc_util_file_read_full((const char *)filename, &datalen);
				  if(file[n].data == NULL){
						httc_util_pr_error(" Read file_integrity failed %s.\n", filename);
						file[n].length = 0;
						n++;
						continue;
				  }
				  file[n].length = datalen;
				  n++;
			}			
		}
	}
	*file_integrity = file;
	*num = n;
	closedir(dir);
	tcf_util_sem_release (TCF_SEM_INDEX_INTEGRITY);
	return TCF_SUCCESS;
}



/*
 * 释放文件完整性同步数据
 */
int tcf_free_synchronized_file_integrity (struct file_integrity_sync **file_integrity, int num){

	if(*file_integrity){
		while(num--){
				if((*file_integrity + num)->data) httc_free((*file_integrity + num)->data);		
		}
		httc_free(*file_integrity);
	}
	
	return TCF_SUCCESS;
}

/*
 * 	准备更新关键文件完整性基准库。
 */
int tcf_prepare_update_critical_file_integrity(
		struct file_integrity_item_user *items, unsigned int num,
		unsigned char *tpcm_id, unsigned int tpcm_id_length,
		int action, uint64_t replay_counter,
		struct file_integrity_update **buffer, unsigned int *prepare_size)
{
	if (action != POLICY_ACTION_SET){
		httc_util_pr_error ("Unsupported action: %d\n", action);
		return TCF_ERR_PARAMETER;
	}
	return tcf_prepare_update_file_integrity(
				items, num, tpcm_id, tpcm_id_length, action, replay_counter, buffer, prepare_size);
}

/*
 * 	整体更新关键文件完整性基准库
 */
int tcf_update_critical_file_integrity(
		struct file_integrity_update *references,
		const char *uid, int cert_type,
		unsigned int auth_length, unsigned char *auth)
{
	int r = 0;
	int num = 0;
	if (!references)	return TCF_ERR_PARAMETER;
	if ((r = tcf_util_sem_get (TCF_SEM_INDEX_POLICY)))	return r;
	if ((r = tcs_update_critical_file_integrity (references, uid, cert_type, auth_length, auth))){
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		return r;
	}


	if (httc_util_create_path_of_fullpath (CRITICAL_FILE_INTEGRITY_PATH)){
		httc_util_pr_error ("Create log path error!\n");
		return TCF_ERR_FILE;
	}
	
	num = ntohl (references->be_item_number);
	/** 写入基准值条数 */
	r = httc_util_file_write (CRITICAL_FILE_INTEGRITY_PATH, (const char *)&num, sizeof (num));
	if (r != sizeof (num)){		
		httc_util_pr_error ("httc_util_file_write error: %d != %d\n", r, (int)sizeof (num));
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		return TCF_ERR_FILE;
	}
	/** 整体写入基准库 */
	r = httc_util_file_write_offset (CRITICAL_FILE_INTEGRITY_PATH, (const char *)references->data, sizeof (num), ntohl (references->be_data_length));
	if (r != ntohl (references->be_data_length)){		
		httc_util_pr_error ("httc_util_file_write error: %d != %d\n", r, (int)ntohl (references->be_data_length));
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		return TCF_ERR_FILE;
	}
	tcf_util_sem_release (TCF_SEM_INDEX_POLICY);

	if ((r = tsb_reload_critical_confile_integrity ())){
		if(r == -1){
			httc_util_pr_info ("tsb_reload_critical_confile_integrity: %d(0x%x)\n", r, r);
			}
		//return TCF_ERR_TSB;
	}
	httc_write_version_notices (ntohll (references->be_replay_counter), POLICY_TYPE_CRITICAL_FILE_INTEGRITY);	
	return TCF_SUCCESS;
}

/** 获取关键更新基准库 */
int tcf_get_critical_file_integrity (
		struct file_integrity_item_user **references, unsigned int *num)
{
	int i,r,ops = 0;
	void *data;
	int items_num = 0;
	int items_size = 0;
	void *items = NULL;
	struct file_integrity_item *item = NULL;
	struct file_integrity_item_user *items_user = NULL;
	unsigned long psize;

	*num = 0;
	*references = NULL;

	if ((r = tcf_util_sem_get (TCF_SEM_INDEX_POLICY)))	return r;
	if (access (CRITICAL_FILE_INTEGRITY_PATH, F_OK)){
		*num = 0;
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		return TCF_SUCCESS;
	}
	if (NULL == (data = httc_util_file_read_full (CRITICAL_FILE_INTEGRITY_PATH, &psize))){
		httc_util_pr_error ("httc_util_file_read_full error\n");
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		return TCF_ERR_FILE;
	}
	tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
	
	items_num = *(int*)data;
	httc_util_pr_dev ("critical_file_integrity num: %d\n", items_num);

	if (NULL == (items_user = httc_calloc (items_num, sizeof (struct file_integrity_item_user)))){
		httc_util_pr_error ("No mem for items_user!\n");
		return TCF_ERR_NOMEM;
	}

	items = data + sizeof (items_num);
	items_size = psize - sizeof (items_num);
	for (i = 0; i < items_num; i ++){
		if ((ops + sizeof (struct file_integrity_item)) >= items_size){
			httc_util_pr_error ("Invalid file_integrity_item (%ld < %d)\n", (long int)(ops + sizeof (struct file_integrity_item)), items_size);
			tcf_free_critical_file_integrity (items_user, i);
			httc_free (data);
			return TCF_ERR_PARAMETER;
		}

		item = (struct file_integrity_item*)(items + ops);
		items_user[i].hash_length = DEFAULT_HASH_SIZE;
		items_user[i].path_length = ntohs (item->be_path_length);
		items_user[i].extend_size = item->extend_size;
		if ((ops + sizeof (struct file_integrity_item)
				+ items_user[i].hash_length + items_user[i].path_length + items_user[i].extend_size) > items_size){
			httc_util_pr_error ("Invalid file_integrity_item\n");
			tcf_free_critical_file_integrity (items_user, i);
			httc_free (data);
			return TCF_ERR_PARAMETER;
		}
		items_user[i].hash = httc_malloc (items_user[i].hash_length + items_user[i].path_length + items_user[i].extend_size);
		if (NULL == items_user[i].hash){
			httc_util_pr_error ("No mem for items_user->hash!\n");
			tcf_free_critical_file_integrity (items_user, i);
			httc_free (data);
			return TCF_ERR_NOMEM;
		}
		items_user[i].extend_buffer = items_user[i].hash + items_user[i].hash_length;
		items_user[i].path = items_user[i].hash + items_user[i].hash_length + items_user[i].extend_size;
		memcpy (items_user[i].hash, item->data, items_user[i].hash_length + items_user[i].extend_size + items_user[i].path_length);

		items_user[i].is_enable = item->flags & (1 << FILE_INTEGRITY_FLAG_ENABLE) ? 1 : 0;
		items_user[i].is_control = item->flags & (1 << FILE_INTEGRITY_FLAG_CONTROL) ? 1 : 0;
		items_user[i].is_full_path = item->flags & (1 << FILE_INTEGRITY_FLAG_FULL_PATH) ? 1 :0;	
		ops += HTTC_ALIGN_SIZE (sizeof (struct file_integrity_item)
				+ items_user[i].hash_length + items_user[i].path_length + items_user[i].extend_size, 4);
	}

	*num = items_num;
	*references = items_user;
	httc_free (data);
	return TCF_SUCCESS;
}

/** 释放关键更新基准库内存 */
void tcf_free_critical_file_integrity (
		struct file_integrity_item_user *references, unsigned int num)
{
	int i = 0;
	if (references){
		for (i = 0; i < num; i++){
			if (references[i].hash)	httc_free (references[i].hash);
		}
		httc_free (references);
	}
}

int tcf_update_file_integrity_digest (unsigned char *digest ,unsigned int digest_len){
	return tcs_update_file_integrity_digest(digest, digest_len);
}


int tcf_get_file_integrity_digest (unsigned char *digest ,unsigned int *digest_len){
	return tcs_get_file_integrity_digest(digest, digest_len);
}

/** 获取关键文件完整性基准库摘要值 */
int tcf_get_critical_file_integrity_digest (unsigned char *digest ,unsigned int *digest_len){
	return tcs_get_critical_file_integrity_digest(digest,  digest_len);
}
