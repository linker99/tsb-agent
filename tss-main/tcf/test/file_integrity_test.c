#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <httcutils/debug.h>
#include <httcutils/mem.h>
#include <tcfapi/tcf_file_integrity.h>
#include <tcfapi/tcf_auth.h>
//void httc_util_dump_hex (const char *name, void *p, int bytes);
static int rand_bytes(unsigned char *buffer,int length)
{
	int i;
	      //初始化随机数
    for( i = 0; i < length;i++ )                          //打印出10个随机数
    	buffer[i] = (unsigned char)(rand() & 0xff);
    return 0;
}

static void print_item(const char *name,struct file_integrity_item_user *item){
	printf("%s control=%d,enable=%d,full_path=%d\n",name,
		item->is_control,item->is_enable,item->is_full_path);
	if(item->hash)httc_util_dump_hex("ITEM hash",item->hash,item->hash_length);
	if(item->extend_buffer)httc_util_dump_hex("ITEM extend_buffer",item->extend_buffer,item->extend_size);
	if(item->path){
		if(!item->is_full_path)httc_util_dump_hex("ITEM path",item->path,item->path_length);
		else printf("ITEM path %s\n",item->path);
	}
}
int test_set(void){
	struct file_integrity_update *update;
	unsigned int update_size;
	struct file_integrity_item_user list[5];
	uint64_t replay_counter = 0;
	
	int r,i;
	list[0].extend_buffer = 0;
	list[0].extend_size = 0;
	list[0].hash = httc_malloc(DEFAULT_HASH_SIZE);
	rand_bytes((unsigned char *)list[0].hash,DEFAULT_HASH_SIZE);
	httc_util_dump_hex("list[0].hash",list[0].hash,DEFAULT_HASH_SIZE);
	list[0].hash_length = DEFAULT_HASH_SIZE;
	list[0].is_control = 0;
	list[0].is_enable = 1;
	list[0].is_full_path = 0;
	list[0].path = 0;
	list[0].path_length = 0;


	list[1].extend_buffer = 0;
	list[1].extend_size = 0;
	list[1].hash = httc_malloc(DEFAULT_HASH_SIZE);
	rand_bytes((unsigned char *)list[1].hash,DEFAULT_HASH_SIZE);
	httc_util_dump_hex("list[1].hash",list[1].hash,DEFAULT_HASH_SIZE);
	list[1].hash_length = DEFAULT_HASH_SIZE;
	list[1].is_control = 1;
	list[1].is_enable = 0;
	list[1].is_full_path = 1;
	list[1].path = "/usr/bin/gedit";
	list[1].path_length = strlen(list[1].path) + 1;

	memcpy(list + 4,list +1 ,sizeof(struct file_integrity_item_user));

	list[2].extend_buffer = 0;
	list[2].extend_size = 0;
	list[2].hash = httc_malloc(DEFAULT_HASH_SIZE);
	rand_bytes((unsigned char *)list[2].hash,DEFAULT_HASH_SIZE);
	httc_util_dump_hex("list[2].hash",list[2].hash,DEFAULT_HASH_SIZE);
	list[2].hash_length = DEFAULT_HASH_SIZE;
	list[2].is_control = 1;
	list[2].is_enable = 1;
	list[2].is_full_path = 0;
	list[2].path = httc_malloc(DEFAULT_HASH_SIZE);
	rand_bytes((unsigned char *)list[2].path,DEFAULT_HASH_SIZE);
	list[2].path_length = DEFAULT_HASH_SIZE;


	list[3].extend_buffer = 0;
	list[3].extend_size = 0;
	list[3].hash = httc_malloc(DEFAULT_HASH_SIZE);
	rand_bytes((unsigned char *)list[3].hash,DEFAULT_HASH_SIZE);
	httc_util_dump_hex("list[3].hash",list[3].hash,DEFAULT_HASH_SIZE);
	list[3].hash_length = DEFAULT_HASH_SIZE;
	list[3].is_control = 1;
	list[3].is_enable = 1;
	list[3].is_full_path = 1;
	list[3].path = "/usr/bin/gcc";
	list[3].path_length = strlen(list[3].path) + 1;
	list[3].extend_size = 6;
	list[3].extend_buffer = httc_malloc(list[3].extend_size );
	rand_bytes((unsigned char *)list[3].extend_buffer,list[3].extend_size);
	for(i=0;i<5;i++){
		char name[100];
		sprintf(name,"SET %i :",i);
		print_item(name,list + i);
	}
	//httc_util_dump_hex("list ",list,4 * sizeof(struct file_integrity_item_user));

	replay_counter = time(0);
	replay_counter |= 0x1000000000000000;
	r =  tcf_prepare_update_file_integrity(
			list,5,
			(unsigned char *)"AAAABBBBCCCCDDDD",16,
			POLICY_ACTION_SET,replay_counter,
			&update,&update_size);
	printf("tcf_prepare_update_file_integrity result %d\n",r);
	if(r)return r;
	printf("update_size = %d\n",update_size);
	httc_util_dump_hex("update ",update,update_size);
	r = tcf_update_file_integrity(update,0,CERT_TYPE_PUBLIC_KEY_SM2,
			DEFAULT_SIGNATURE_SIZE,0,NULL,0);
	printf("tcf_update_file_integrity %d\n",r);
	return r;
}

int test_add(void){
	struct file_integrity_update *update;
	unsigned int update_size;
	struct file_integrity_item_user list[5];
	uint64_t replay_counter = 0;
	int r,i;
	
	
	list[0].extend_buffer = 0;
	list[0].extend_size = 0;
	list[0].hash = httc_malloc(DEFAULT_HASH_SIZE);
	rand_bytes((unsigned char *)list[0].hash,DEFAULT_HASH_SIZE);
	httc_util_dump_hex("list[0].hash",list[0].hash,DEFAULT_HASH_SIZE);
	list[0].hash_length = DEFAULT_HASH_SIZE;
	list[0].is_control = 0;
	list[0].is_enable = 1;
	list[0].is_full_path = 0;
	list[0].path = 0;
	list[0].path_length = 0;


	list[1].extend_buffer = 0;
	list[1].extend_size = 0;
	list[1].hash = httc_malloc(DEFAULT_HASH_SIZE);
	rand_bytes((unsigned char *)list[1].hash,DEFAULT_HASH_SIZE);
	httc_util_dump_hex("list[1].hash",list[1].hash,DEFAULT_HASH_SIZE);
	list[1].hash_length = DEFAULT_HASH_SIZE;
	list[1].is_control = 1;
	list[1].is_enable = 0;
	list[1].is_full_path = 1;
	list[1].path = "/usr/bin/gedit";
	list[1].path_length = strlen(list[1].path) + 1;


	list[2].extend_buffer = 0;
	list[2].extend_size = 0;
	list[2].hash = httc_malloc(DEFAULT_HASH_SIZE);
	rand_bytes((unsigned char *)list[2].hash,DEFAULT_HASH_SIZE);
	httc_util_dump_hex("list[2].hash",list[2].hash,DEFAULT_HASH_SIZE);
	list[2].hash_length = DEFAULT_HASH_SIZE;
	list[2].is_control = 1;
	list[2].is_enable = 1;
	list[2].is_full_path = 0;
	list[2].path = httc_malloc(DEFAULT_HASH_SIZE);
	rand_bytes((unsigned char *)list[2].path,DEFAULT_HASH_SIZE);
	list[2].path_length = DEFAULT_HASH_SIZE;


	list[3].extend_buffer = 0;
	list[3].extend_size = 0;
	list[3].hash = httc_malloc(DEFAULT_HASH_SIZE);
	rand_bytes((unsigned char *)list[3].hash,DEFAULT_HASH_SIZE);
	httc_util_dump_hex("list[3].hash",list[3].hash,DEFAULT_HASH_SIZE);
	list[3].hash_length = DEFAULT_HASH_SIZE;
	list[3].is_control = 1;
	list[3].is_enable = 1;
	list[3].is_full_path = 1;
	list[3].path = "/usr/bin/gcc";
	list[3].path_length = strlen(list[3].path) + 1;
	list[3].extend_size = 6;
	list[3].extend_buffer = httc_malloc(list[3].extend_size );
	rand_bytes((unsigned char *)list[3].extend_buffer,list[3].extend_size);
	for(i=0;i<4;i++){
		char name[100];
		sprintf(name,"ADD %i :",i);
		print_item(name,list + i);
	}
	//httc_util_dump_hex("list ",list,4 * sizeof(struct file_integrity_item_user));
	replay_counter = time(0);
	replay_counter |= 0x1000000000000000;
	
	r =  tcf_prepare_update_file_integrity(
			list,4,
			(unsigned char *)"AAAABBBBCCCCDDDD",16,
			POLICY_ACTION_ADD,replay_counter,
			&update,&update_size);
	printf("tcf_prepare_update_file_integrity result %d\n",r);

	if(r)return r;
	printf("update_size = %d\n",update_size);
	httc_util_dump_hex("update ",update,update_size);
	r = tcf_update_file_integrity(update,0,CERT_TYPE_PUBLIC_KEY_SM2,
			DEFAULT_SIGNATURE_SIZE,0,NULL,0);
	printf("1 tcf_update_file_integrity %d\n",r);

	r = tcf_update_file_integrity(update,0,CERT_TYPE_PUBLIC_KEY_SM2,
				DEFAULT_SIGNATURE_SIZE,0,NULL,0);
	printf("2 tcf_update_file_integrity %d\n",r);
	//tcf_free_file_integrity();
	return r;
}

int test_get(void){
	struct file_integrity_item_user *getlist = 0;
	unsigned int get_size = 1000000;
	int i;
	int r = tcf_get_file_integrity(&getlist,0,&get_size);
	printf("tcf_get_file_integrity result %d\n",r);
	if(r)return r;
	for(i=0;i<get_size;i++){
		char name[100];
		sprintf(name,"GET %i :",i);
		print_item(name,getlist + i);
	}
	tcf_free_file_integrity(getlist,get_size);

	get_size = 2;
	tcf_get_file_integrity(&getlist,1,&get_size);
	printf("tcf_get_file_integrity result %d\n",r);
	if(r)return r;
	for(i=0;i<get_size;i++){
		char name[100];
		sprintf(name,"GET %i :",i);
		print_item(name,getlist + i);
	}
	tcf_free_file_integrity(getlist,get_size);
	return 0;
}

int test_del(void){

	struct file_integrity_update *update;
	struct file_integrity_item_user *getlist = 0;
	unsigned int get_size = 1000;
	uint64_t replay_counter = 0;
	int i;
	int r;
	unsigned int update_size;


	r = tcf_get_file_integrity(&getlist,0,&get_size);
	printf("tcf_get_file_integrity result %d\n",r);
	if(r)return r;
	for(i=0;i<get_size;i++){
		char name[100];
		sprintf(name,"GET %i :",i);
		print_item(name,getlist + i);
	}
//	if(get_size < 2 )return 0;
//	r =  tcf_prepare_update_file_integrity(
//			getlist + get_size -2 ,2,
//					(unsigned char *)"AAAABBBBCCCCDDDD",16,
//					POLICY_ACTION_DELETE,time(0),
//					&update,&update_size);

	if(get_size < 3 ){
		tcf_free_file_integrity(getlist,get_size);
		return 0;
	}

	replay_counter = time(0);
	replay_counter |= 0x1000000000000000;
	r =  tcf_prepare_update_file_integrity(
			getlist + 1 ,2,
					(unsigned char *)"AAAABBBBCCCCDDDD",16,
					POLICY_ACTION_DELETE,replay_counter,
					&update,&update_size);
	printf("tcf_prepare_update_file_integrity result %d\n",r);
	if(r){
		tcf_free_file_integrity(getlist,get_size);
		return r;
	}
	r = tcf_update_file_integrity(update,0,CERT_TYPE_PUBLIC_KEY_SM2,
				DEFAULT_SIGNATURE_SIZE,0,NULL,0);
	printf("tcf_update_file_integrity %d\n",r);
	if(r){
		tcf_free_file_integrity(getlist,get_size);
		return r;
	}
	tcf_free_file_integrity(getlist,get_size);
	
	tcf_get_file_integrity(&getlist,0,&get_size);
	printf("after delete tcf_get_file_integrity result %d\n",r);
	if(r)return r;
	for(i=0;i<get_size;i++){
		char name[100];
		sprintf(name,"GET %i :",i);
		print_item(name,getlist + i);
	}
	tcf_free_file_integrity(getlist,get_size);
	return 0;
}
int main(int argc,const char **args){

	int r;
	srand( (unsigned)time( 0 ) );

//	r = test_del();
//	if(r){
//		printf("test del fail %d\n",r);
//		return r;
//	}

//	r = test_set();
//	if(r){
//		printf("test set fail %d\n",r);
//		return r;
//	}
//	r = test_add();
//	if(r){
//		printf("test add fail %d\n",r);
//		return r;
//	}


	r = test_get();
	if(r){
		printf("test get fail\n %d\n",r);
		return r;
	}
	return 0;
}



