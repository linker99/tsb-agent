#include <stdio.h>
#include <sys/stat.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>

#include "httc_dmeasure.h"

static pthread_mutex_t mem_metux = PTHREAD_MUTEX_INITIALIZER;

void *httc_malloc (size_t size){
	pthread_mutex_lock (&mem_metux);
	pthread_mutex_unlock (&mem_metux);
	return malloc(size);
}
void *httc_calloc (size_t nmemb, size_t size){
	pthread_mutex_lock (&mem_metux);
	pthread_mutex_unlock (&mem_metux);
	return calloc(nmemb, size);
}

void httc_free (void *ptr){
	pthread_mutex_lock (&mem_metux);
	pthread_mutex_unlock (&mem_metux);
	free(ptr);
}

void httc_util_dump_hex (const char *name, void *p, int bytes)
{
    int i = 0;
    uint8_t *data = p;
    int hexlen = 0;
    int chrlen = 0;
    uint8_t hexbuf[49] = {0};
    uint8_t chrbuf[17] = {0};
    uint8_t dumpbuf[128] = {0};

    printf ("%s length=%d:\n", name, bytes);

    for (i = 0; i < bytes; i ++){
        hexlen += sprintf ((char *)&hexbuf[hexlen], "%02X ", data[i]);
        chrlen += sprintf ((char *)&chrbuf[chrlen], "%c", ((data[i] >= 33) && (data[i] <= 126)) ? (unsigned char)data[i] : '.');
        if (i % 16 == 15){
            sprintf ((char *)&dumpbuf[0], "%08X: %-49s%-17s", i / 16 * 16, hexbuf, chrbuf);
            printf ("%s\n", dumpbuf);
            hexlen = 0;
            chrlen = 0;
        }
    }

    if (i % 16 != 0){
        sprintf ((char *)&dumpbuf[0], "%08X: %-49s%-17s", i / 16 * 16, hexbuf, chrbuf);
        printf ("%s\n", dumpbuf);
    }
}


static int get_local_adminkey(admin_t *admin)
{
	FILE *fp = NULL;
	char path[512] = {0};
	struct stat st;

	snprintf(path, sizeof(path)-1, "%s/etc/adminkey", HOME_PATH);

	stat(path, &st);
	if ((access(path, F_OK)) != 0 || (st.st_size != sizeof(*admin))){
		printf("file %s not exist or size error\n", path);
		return -1;
	}

	fp = fopen(path, "rb");
	if (!fp) {
		printf("read %s fail\n", path);
		return -2;
	}

	fread((void *)admin, 1, sizeof(*admin), fp);
	fclose(fp);
	return 0;
}

int update_dmeasure_policy(char *name, int dminterval) {
	
	int ret = 0;
	int i = 0;
	int j = 0;
	int find_flag = 0;
	int num = 0;
	admin_t admin = {0};
	uint8_t *sign = NULL;
	uint32_t signlength = 0;
	uint64_t replay_counter = 0;
	int auth_type = CERT_TYPE_PUBLIC_KEY_SM2;
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	uint8_t tpcm_id[MAX_TPCM_ID_SIZE] = {0};
	
	int policy_update_length = 0;
	struct dmeasure_policy_item_user item_user[6] = {0};
	struct dmeasure_policy_update *policy_update = NULL;
	struct dmeasure_policy_item_user *policy = NULL;
	
	ret = get_local_adminkey(&admin);
	if (ret < 0) {
		printf("get_local_adminkey %d fail\n", ret);
		return -1;
	}

	if(httc_get_replay_counter(&replay_counter)) {
		printf("Error httc_get_replay_counter.\n");
		return -2;
	}

	if (0 != (ret = tcf_get_tpcm_id (tpcm_id, &tpcm_id_length))) {
		printf("tcf_get_tpcm_id error: %d(0x%x)\n", ret, ret);
		return -3;
	}
	
	if (0 != (ret = tcf_get_dmeasure_policy (&policy, &num))){
		printf ("tcf_get_dmeasure_policy error: %d(0x%x)\n", ret, ret);
		return ret;
	}
	
	for (i = 0; i < num; i++){
		if(strncmp(name, policy[i].name, strlen(name)) == 0 ) {
			find_flag = 1;
			if((policy[i].interval_milli == dminterval * 1000) && num != 1) {
				continue;
			}
			item_user[j].type = 1;
			item_user[j].interval_milli = dminterval * 1000;
			item_user[j].name = name;
#if 0
			printf ("dm_policy index: %d\n", j);
			printf ("[%d].name: %s\n", j, item_user[j].name);
			printf ("[%d].type: %u\n", j, item_user[j].type);
			printf ("[%d].interval_milli: %u\n", j, item_user[j].interval_milli);
			printf ("\n");
#endif 
			j ++;
		}
		else {
			item_user[j].type = policy[i].type;
			item_user[j].interval_milli = policy[i].interval_milli;
			item_user[j].name = policy[i].name;
#if 0
			printf ("dm_policy index: %d\n", j);
			printf ("[%d].name: %s\n", j, item_user[j].name);
			printf ("[%d].type: %u\n", j, item_user[j].type);
			printf ("[%d].interval_milli: %u\n", j, item_user[j].interval_milli);
			printf ("\n");
			
#endif 
			j ++;
		}
	}

	if(find_flag == 0) {
		item_user[j].type = 1;
		item_user[j].interval_milli = dminterval * 1000;		//interval单位：秒
		item_user[j].name = name;
		j ++;
	}
	
	if (0 != (ret = tcf_prepare_update_dmeasure_policy (item_user, j,
					   tpcm_id, tpcm_id_length, POLICY_ACTION_SET, replay_counter, &policy_update, &policy_update_length))) {
		ret = -4;
		printf("tcf_prepare_update_dmeasure_policy error: %d(0x%x)\n", ret, ret);
		goto out;
	}

	if (0 != (ret = os_sm2_sign((const uint8_t *)policy_update,
				   policy_update_length, admin.prikey, 32, admin.pubkey, 64, &sign ,&signlength))) {
		printf ("Sign for dynamic policy failed!\n");
		goto out;
	}

#if 0	
	printf ("policy_update:%d---len=%d\n", policy_update->be_item_number, policy_update_length);
	if (0 != (ret = os_sm2_verify (
				   (const uint8_t *)policy_update, policy_update_length, admin.pubkey, 64, sign, signlength))) {
		printf ("Verify for dynamic policy failed!\n");
		goto out;
	}
#endif
	if (0 != (ret = tcf_update_dmeasure_policy (policy_update, UID_LOCAL, auth_type, signlength, sign))) {
		printf ("tcf_update_dmeasure_policy error: %d(0x%x)\n", ret, ret);
		ret = -1;
		goto out;
	}


out:
 	if (policy) tcf_free_dmeasure_policy (policy, num);
	if (policy_update) httc_free (policy_update);
	return ret;
}

int update_dmeasure_process_policy(char *object_id, int dminterval, int sub_process_mode, int old_process_mode, int share_lib_mode) {
	int ret = 0;
	int num = 0;
	int number = 1;
	int i = 0;
	int j = 0;
	int id_i = 0;
	uint64_t replay_counter = 0;
	admin_t admin = {0};
	uint8_t *sign = NULL;
	int signlength = 0;
	int auth_type = CERT_TYPE_PUBLIC_KEY_SM2;
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	char tpcm_id[MAX_TPCM_ID_SIZE] = {0};
	int update_len = 0;
	struct dmeasure_process_policy_update *update = NULL;
	struct dmeasure_process_item_user *policy_item = NULL;
	struct dmeasure_process_item_user *policy = NULL;

	ret = get_local_adminkey(&admin);
	if (ret < 0) {
		printf("get_local_adminkey %d fail\n", ret);
		return -1;
	}

	if(httc_get_replay_counter(&replay_counter)){
		printf("Error httc_get_replay_counter.\n");
		return -2;
	}
	
	if (0 != (ret = tcf_get_tpcm_id (tpcm_id, &tpcm_id_length))){
		printf("Get tpcm id error: %d(0x%x)\n", ret, ret);
		return -3;
	}

	if (0 != (ret = tcf_get_dmeasure_process_policy (&policy, &num))) {
		printf ("tcf_get_dmeasure_process_policy error: %d(0x%x)\n", ret, ret);
		goto out;
	}

	for(i = 0; i < num; i++) {
		if(strncmp(object_id, policy[i].object_id, strlen(object_id)) == 0) {
			number = num - 1;
			id_i = i;
		}
		else {
			number = num + 1;
		}
	}
	if(number != 0) {

		if (NULL == (policy_item = (struct dmeasure_process_item_user *)httc_calloc (number, sizeof (struct dmeasure_process_item_user)))){
			printf ("Malloc for reference failure\n");
			return -1;
		}
		
		for (i = 0, j = 0; j < num; j++) {
			if(j == id_i && number < num)
				continue;
			policy_item[i].object_id_type = policy[j].object_id_type;
			policy_item[i].sub_process_mode = policy[j].sub_process_mode;
			policy_item[i].old_process_mode = policy[j].old_process_mode;
			policy_item[i].share_lib_mode = policy[j].share_lib_mode;
			policy_item[i].measure_interval = policy[j].measure_interval;
			policy_item[i].object_id_length = policy[j].object_id_length;
			policy_item[i].object_id = policy[j].object_id;
#if 0			
			printf ("\n");
			printf ("dm_policy index: %d\n", i);
			printf ("[%d].object_id_type: %d\n", i, policy[i].object_id_type);
			printf ("[%d].sub_process_mode: %d\n", i, policy[i].sub_process_mode);
			printf ("[%d].old_process_mode: %d\n", i, policy[i].old_process_mode);
			printf ("[%d].share_lib_mode: %d\n", i, policy[i].share_lib_mode);
			printf ("[%d].measure_interval: %d\n", i, policy[i].measure_interval);
			printf ("[%d].object_id_length: %d\n", i, policy[i].object_id_length);
			printf ("[%d].object_id: %s\n", i, policy[i].object_id);
#endif
			i ++;
		}

		if(number > num) {
			policy_item[number - 1].object_id_type = PROCESS_DMEASURE_OBJECT_ID_FULL_PATH;
			policy_item[number - 1].sub_process_mode = sub_process_mode;
			policy_item[number - 1].old_process_mode = old_process_mode;
			policy_item[number - 1].share_lib_mode = share_lib_mode;
			policy_item[number - 1].measure_interval = dminterval * 1000;
			policy_item[number - 1].object_id_length = strlen(object_id);
			if (NULL == (policy_item[number - 1].object_id = httc_malloc (policy_item[number - 1].object_id_length))) {
				printf ("Malloc for policy_item.object_id failure\n");
				ret = -4;
				goto out;
			}
			memcpy (policy_item[number - 1].object_id, object_id, policy_item[number - 1].object_id_length);
		}
	}

	if (0 != (ret = tcf_prepare_update_dmeasure_process_policy (policy_item,
		 	number, tpcm_id, tpcm_id_length, POLICY_ACTION_SET, replay_counter, &update, &update_len))){
		 printf ("tcf_prepare_update_dmeasure_process_policy id error: %d(0x%x)\n", ret, ret);
		 goto out;
	}

	if (0 != (ret = os_sm2_sign((const uint8_t *)update, update_len, admin.prikey, 32, admin.pubkey, 64, &sign ,&signlength))){
		printf ("Sign for dynamic policy failed!\n");
		goto out;
	}
#if 0
	if (0 != (ret = os_sm2_verify ((const uint8_t *)update, update_len, admin.pubkey, 64, sign, signlength))){
		printf ("Verify for dynamic policy failed!\n");
	}
#endif	
	if (0 != (ret = tcf_update_dmeasure_process_policy (update, UID_LOCAL, auth_type, signlength, sign))){
		printf ("[tcs_update_dmeasure_process_policy] ret: %d(0x%x)\n", ret, ret);
		ret = -5;
	}
	
out:
	if (update) httc_free(update);
	if (policy_item != NULL && policy_item[number - 1].object_id) httc_free(policy_item[number - 1].object_id);
	if (policy) httc_free (policy);
	return ret;
}

int get_dmeasure_policy() {

	int i = 0;
	int ret = 0;
	unsigned int num = 0;
	struct dmeasure_policy_item_user *policy = NULL;
	
	if (0 != (ret = tcf_get_dmeasure_policy (&policy, &num))){
		printf ("tcf_get_dmeasure_policy error: %d(0x%x)\n", ret, ret);
		return ret;
	}
	
	for (i = 0; i < num; i++){
		printf ("\n");
		printf ("dm_policy index: %d\n", i);
		printf ("[%d].name: %s\n", i, policy[i].name);
		printf ("[%d].type: %u\n", i, policy[i].type);
		printf ("[%d].interval_milli: %u\n", i, policy[i].interval_milli);
	}
	printf ("\n");
	
	if (policy)
		tcf_free_dmeasure_policy (policy, num);
	return 0;
}

int get_dmeasure_process_policy() {
	
	int i = 0;
	int ret = 0;
    int num = 0;
	struct dmeasure_process_item_user *policy = NULL;

	if (0 != (ret = tcf_get_dmeasure_process_policy (&policy, &num))) {
	        printf ("tcf_get_dmeasure_process_policy error: %d(0x%x)\n", ret, ret);
	        return ret;
	}

	for (i = 0; i < num; i++) {
	        printf ("\n");
	        printf ("dm_policy index: %d\n", i);
	        printf ("[%d].object_id_type: %d\n", i, policy[i].object_id_type);
	        printf ("[%d].sub_process_mode: %d\n", i, policy[i].sub_process_mode);
	        printf ("[%d].old_process_mode: %d\n", i, policy[i].old_process_mode);
	        printf ("[%d].share_lib_mode: %d\n", i, policy[i].share_lib_mode);
	        printf ("[%d].measure_interval: %d\n", i, policy[i].measure_interval);
	        printf ("[%d].object_id_length: %d\n", i, policy[i].object_id_length);
	        if (PROCESS_DMEASURE_OBJECT_ID_HASH == policy[i].object_id_type) {
	                printf ("[%d].", i); httc_util_dump_hex ("object_id", policy[i].object_id, policy[i].object_id_length);
	        }
			else {
				policy[i].object_id[policy[i].object_id_length] = '\0';
				printf ("[%d].object_id: %s\n", i, policy[i].object_id);
			}
	}
	printf ("\n");

	if (policy)
		tcf_free_dmeasure_process_policy (policy, num);
	return 0;
}

void usage()
{
	printf ("\n"
			" Usage: ]\n"
			" ./ht_dmeasure get_dmeasure_process_policy \n"
			" ./ht_dmeasure get_dmeasure_policy \n"
			" ./ht_dmeasure update_dmeasure_policy name(kernel_section/syscall_table/idt_table) mininterval(600-1728000秒)\n"
			" ./ht_dmeasure update_dmeasure_policy name(module_list/filesystem/network) mininterval(600-1728000秒)\n"
			" ./ht_dmeasure update_dmeasure_process_policy name(全路径) mininterval(600-1728000秒) sub_process_mode(0/1/2) old_process_mode(0/1/2) share_lib_mode(0/1/2)\n"
			"\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	if(argc < 2) {
		usage();
		return -1;
	}
	if(0 == strcmp(argv[1], "get_dmeasure_process_policy")) {
		ret = get_dmeasure_process_policy();	
		if(ret < 0) {
			printf("get_dmeasure_process_policy error ret=%d\n", ret);
			return ret;
		}	
	}
	else if(0 == strcmp(argv[1], "get_dmeasure_policy")) {
		ret = get_dmeasure_policy();	
		if(ret < 0) {
			printf("get_dmeasure_policy error ret=%d\n", ret);
			return ret;
		}
	}
	else if((0 == strcmp(argv[1], "update_dmeasure_policy"))) {
		if(argc != 4) {
			printf("input argc error \n");
			usage();
			return -1;
		}

		if(strncmp(argv[2], "kernel_section", strlen("kernel_section")) != 0 && strncmp(argv[2], "filesystem", strlen("filesystem")) != 0
				&& strncmp(argv[2], "syscall_table", strlen("syscall_table")) != 0 && strncmp(argv[2], "network", strlen("network")) != 0
				&& strncmp(argv[2], "idt_table", strlen("idt_table")) != 0 && strncmp(argv[2], "module_list", strlen("module_list")) != 0) {
			printf("input name error \n");
			usage();
			return -1;
		}
		
		int mininterval = 0;
		mininterval = atoi(argv[3]);
		if (mininterval < 600 || mininterval > 1728000) {
			printf("input mininterval error \n");
			usage();
			return -1;
		}
		
		ret = update_dmeasure_policy(argv[2], mininterval);
		if(ret < 0) {
			printf("add_dmeasure_policy error ret=%d\n", ret);
			return ret;
		}
	}
	else if((0 == strcmp(argv[1], "update_dmeasure_process_policy"))) {
		if(argc > 7 || argc < 4) {
			printf("input error \n");
			usage();
			return -1;
		}
		int mininterval = 0;
		int sub_process_mode = 0;
		int old_process_mode = 0;
		int share_lib_mode = 0;
		
		mininterval = atoi(argv[3]);
		if (mininterval < 600 || mininterval > 1728000) {
			printf("input mininterval error \n");
			usage();
			return -1;
		}
		
		if(argv[4] != NULL) {
			sub_process_mode = atoi(argv[4]);
			if (sub_process_mode < 0 || sub_process_mode > 2) {
				printf("input sub_process_mode error \n");
				usage();
				return -1;
			}
		}
		
		if(argv[5] != NULL) {
			old_process_mode = atoi(argv[5]);
			if (old_process_mode < 0 || old_process_mode > 2) {
				printf("input old_process_mode error \n");
				usage();
				return -1;
			}
		}
		
		if(argv[6] != NULL) {
			share_lib_mode = atoi(argv[6]);
			if (share_lib_mode < 0 || share_lib_mode > 2) {
				printf("input share_lib_mode error \n");
				usage();
				return -1;
			}
		}
				
		ret = update_dmeasure_process_policy(argv[2], mininterval, sub_process_mode, old_process_mode, share_lib_mode);
		if(ret < 0) {
			printf("add_dmeasure_policy error ret=%d\n", ret);
			return ret;
		}
	}
	else {
		usage();
	}
	
	return 0;
}
