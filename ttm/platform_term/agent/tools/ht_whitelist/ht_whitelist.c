#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <uuid/uuid.h>

#define __USE_GNU
#include <sched.h>
#include <pthread.h>

#include "sqlite3.h"
#include "public.h"
#include "scan_path.h"
#include "cJSON.h"

#include "tsbapi/tsb_admin.h"
#include "tcfapi/tcf_auth.h"
#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_policy.h"
#include "tcfapi/tcf_bmeasure.h"
#include "tcfapi/tcf_dmeasure.h"
#include "tcfapi/tcf_file_integrity.h"
#include "tcfapi/tcf_config.h"
#include "tcfapi/tcf_dev_protect.h"
#include "tcfapi/tcf_network_control.h"
#include "tcfapi/tcf_file_protect.h"

#include "ht_def.h"
#include "ht_util.h"


static char *scan_path = NULL;
static char *home_path = NULL;
static char *command = NULL;
static char *program_name = NULL;
static int  scan_deldb_flag = 0; //默认不清理原有数据

struct whitelist g_array[ARRAY_MAX_LEN];
static unsigned int g_array_count = 0;
static unsigned int g_total_count = 0;
pthread_mutex_t g_array_lock;

struct list_head g_task_list;
static int g_task_count = 0;
pthread_mutex_t g_task_lock;

static int g_running_pthreads = 0;
static int g_scan_done = 0;
static int g_time_first = 0;	//默认准确度优先
static int g_unzip_flag = 1;    //0-不处理压缩包 1-扫描压缩包中的ko加白 2-对压缩包中符合白名单条件的文件加白

int usage()
{
	printf("Usage:  ht_whitelist [COMMAND] [PARAMETER 1] [PARAMETER 2]\n\n" );
	printf("COMMAND:\n");
	printf("ht_whitelist -a	 nounzip/unzip_ko/unzip_all						scan whitelist all, and unzip_ko is default policy.\n");
	printf("ht_whitelist -s  scan_dir  nounzip/unzip_ko/unzip_all			scan scan_dir whitelist, and unzip_ko is default policy. \n");
	printf("ht_whitelist -d  scan_dir  nounzip/unzip_ko/unzip_all			delete scan_dir whitelist, and unzip_ko is default policy. \n");
    printf("ht_whitelist -c 												close whitelist\n");
	printf("ht_whitelist -o 												open whitelist\n");
	printf("ht_whitelist -h													print usage help information\n\n\n");

	exit(HT_INIT_HELP);
}

int ht_backup()
{
    printf("ht_backup begin.\n");
    tools_log(HTTC_INFO, "ht_backup begin.!" );

    if(0 != access(BACKUP_PATH, F_OK))
    {
        ht_mkdir(BACKUP_PATH);
    }

    if(0 != access(DB_BACKUP_PATH, F_OK))
    {
        ht_mkdir(DB_BACKUP_PATH);
    }
    if(0 != access(ETC_BACKUP_PATH, F_OK))
    {
        ht_mkdir(ETC_BACKUP_PATH);
    }
    if(0 != access(CONF_BACKUP_PATH, F_OK))
    {
        ht_mkdir(CONF_BACKUP_PATH);
    }

	ht_copy_dir(DB_PATH, DB_BACKUP_PATH);
	ht_copy_dir(ETC_PATH, ETC_BACKUP_PATH);
	ht_copy_dir(CONF_PATH, CONF_BACKUP_PATH);

    printf("ht_backup end.\n");
	tools_log(HTTC_INFO, "ht_backup end.!" );

    return 0;
}

int ht_rollback()
{
	printf("ht_rollback begin.\n");
    tools_log(HTTC_INFO, "ht_rollback begin.!" );

	ht_copy_dir(DB_BACKUP_PATH, DB_PATH);
	ht_copy_dir(ETC_BACKUP_PATH, ETC_PATH);
	ht_copy_dir(CONF_BACKUP_PATH, CONF_PATH);

	printf("ht_rollback end.\n");
    tools_log(HTTC_INFO, "ht_rollback end.!" );

	return 0;
}

int ht_cleanback()
{
	printf("ht_cleanback begin.\n");
    tools_log(HTTC_INFO, "ht_cleanback begin.!" );

	ht_rmdir(DB_BACKUP_PATH);
	ht_rmdir(ETC_BACKUP_PATH);
	ht_rmdir(CONF_BACKUP_PATH);

	printf("ht_cleanback end.\n");
    tools_log(HTTC_INFO, "ht_cleanback end.!" );

	return 0;
}

int ht_init_write_whitelist_db(struct whitelist *array, int count)
{
	int i;
	sqlite3 *db = NULL;
	char db_path[512] = {0};
	int ret = -1;

	sprintf(db_path, "%s/%s/db/%s", home_path, HTTC_PATH, WHITELIST_DB_NAME);

	ret = sqlite3_open(db_path, &db);
	if(ret != 0) 
	{
		printf("sqlite3_open db_path: %s\n", db_path);
		return ret;
	}
	
	sqlite3_exec(db, "begin;", 0, 0, 0);
	sqlite3_stmt *stmt;
	const char *sql = "insert into whitelist values(?,?,?,?)";
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, 0);
	
	for (i=0; i<count; ++i) {
		sqlite3_reset(stmt);
		sqlite3_bind_text(stmt, 1, array[i].guid, -1, SQLITE_STATIC);
		sqlite3_bind_text(stmt, 2, array[i].path, -1, SQLITE_STATIC);
		sqlite3_bind_text(stmt, 3, array[i].hash, -1, SQLITE_STATIC);
		sqlite3_bind_int(stmt, 4, 3);  //采集来源：1-初始采集 2-管理中心下发 3-本地配置
		sqlite3_step(stmt);
	}
	sqlite3_finalize(stmt);
	sqlite3_exec(db, "commit;", 0, 0, 0);
	
	sqlite3_close(db);
	
	return 0;
}

int ht_init_sqlite_exec(char *sql)
{
	sqlite3 *db = NULL;
	char *errMsg = NULL;
	int res;
	char db_path[512] = {0};

	sprintf(db_path, "%s/%s/db/%s", home_path, HTTC_PATH, WHITELIST_DB_NAME);

	res = sqlite3_open(db_path, &db);
	if (res != SQLITE_OK) {
		printf("open %s fail: %s\n", db_path, sqlite3_errmsg(db));
		return -1;
	}

	res = sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if (res != SQLITE_OK) {
		printf("exec [%s] fail: %s\n", sql, errMsg);
		sqlite3_close(db);
		return -1;
	}

	sqlite3_close(db);
	return 0;
}

void *ht_init_worker_thread(void *args)
{
	int index = *(int *)args;
	char hash[SM3_LEN*2 + 1] = {0};
	//char uuid[UUID_LEN] = {0};
	struct list_head *pos, *next, *node_pos, whitelist_tar_list;;
	struct task *t;
	cpu_set_t mask;
	char db_path[512] = {0};
	sqlite3 *db = NULL;
	char sql[1024] = {0};
	char *errmsg = NULL;
	int row;
	int column;
	char **data =NULL;
	whitelist_exec_node_t *exec_node = NULL, *exec_pos;
	uuid_t _uuid;
	int ret = 0, type = 0;
	
	CPU_ZERO(&mask);
	CPU_SET(index, &mask);
	
	if (pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0) {
		printf("pthread_setaffinity_np: fail!\n");
	}

	while (!(g_scan_done && g_task_count <= 0)) {
		
		pthread_mutex_lock(&g_task_lock);
		if(g_task_count <=0) {
			pthread_mutex_unlock(&g_task_lock);
			usleep(20);
			continue;
		}

		list_for_each_safe(pos, next, &g_task_list) {
			t = list_entry(pos, struct task, list);
			list_del(&t->list);
			break;
		}
		g_task_count--;
		pthread_mutex_unlock(&g_task_lock);

		INIT_LIST_HEAD(&whitelist_tar_list);
		ret = is_exec(t->file, g_time_first);
		if( ret == 1) {
			uuid_generate(_uuid);
			if(ttm_sm3_file(t->file, hash)) {
				free(t);
				continue;
			}

			exec_node = (whitelist_exec_node_t *)agent_calloc(sizeof(*exec_node));
			uuid_unparse(_uuid, exec_node->uuid);
			binary_to_str(hash, exec_node->hash_str, HASH_LENGTH * 2);
			strncpy(exec_node->file_path, t->file, sizeof(exec_node->file_path) - 1);

			list_add_tail(&exec_node->tar_list, &whitelist_tar_list);
		}
		else if(ret > 0) {
			if(ret == 2) type = FILE_COMPRESS_ZIP; // zip file
			if(ret == 3) type = FILE_COMPRESS_TAR; // gz file
			if(ret == 4) type = FILE_COMPRESS_XZ; // xz file
			if(g_unzip_flag == 1){ //对压缩包中的ko加白
				if(ht_whitelist_uncompress(t->file, &whitelist_tar_list, type)) {
					free(t);
					continue;
				}
			}else if(g_unzip_flag == 2){ //对压缩包中符合白名单的文件加白
				if(ht_scan_uncompress_all(t->file, &whitelist_tar_list, type)) {
					free(t);
					continue;
				}
			}
		}

		if(scan_deldb_flag == 0){
			//判断去重
			sprintf(db_path, "%s%s/db/%s", home_path, HTTC_PATH, WHITELIST_DB_NAME);
			printf("db_path:%s\n", db_path);
			if (sqlite3_open(db_path, &db) != SQLITE_OK) {
				printf("open db %s fail\n", db_path);
				continue;
			}
			sprintf(sql, "select * from whitelist where path='%s' and hash='%s' ;", t->file, hash);
			printf("sql:%s\n", sql);

			if (sqlite3_get_table(db, sql, &data, &row, &column, &errmsg) != SQLITE_OK) {
				printf("get data fail, errmsg: %s\n", errmsg);
				sqlite3_close(db);
				agent_free(errmsg);
				continue;;
			}

			sqlite3_close(db);
			if(row > 0){
				printf("file %s already in whitelist.\n",  t->file);
				continue;
			}
		}

		//插入链表，到达上限后写入数据库
		pthread_mutex_lock(&g_array_lock);
		list_for_each_safe(node_pos, next, &whitelist_tar_list) {
			exec_pos = list_entry(node_pos, whitelist_exec_node_t, tar_list);

			strncpy(g_array[g_array_count].guid, exec_pos->uuid, UUID_LEN);
			strncpy(g_array[g_array_count].path, exec_pos->file_path, PATH_MAX_LEN);
			strncpy(g_array[g_array_count].hash, exec_pos->hash_str, SM3_LEN * 2);

			list_del(&exec_pos->tar_list);
			agent_free(exec_pos);

			g_array_count++;
			g_total_count++;

			if (g_array_count == ARRAY_MAX_LEN) {
				ht_init_write_whitelist_db(g_array, g_array_count);
				g_array_count = 0;
				memset(g_array, 0, sizeof(g_array));
			}
		}
		pthread_mutex_unlock(&g_array_lock);

		free(t);
	}

	pthread_mutex_lock(&g_task_lock);
	g_running_pthreads--;
	pthread_mutex_unlock(&g_task_lock);

	return NULL;
}

int ht_init_scan_file(const char* file_path)
{
	struct task *t = (struct task *)agent_malloc(sizeof(struct task));
	if(t == NULL) {
        // 内存分配失败，返回错误码或处理错误
        return -1; 
    }
	memset(t, 0, sizeof(*t));
	strncpy(t->file, file_path, sizeof(t->file) - 1);
	t->file[sizeof(t->file) - 1] = '\0'; 

	pthread_mutex_lock(&g_task_lock);
	list_add_tail(&t->list, &g_task_list);
	g_task_count++;
	pthread_mutex_unlock(&g_task_lock);

	return 0;
}

static int ht_init_scan_whitelist()
{
	DIR	*dir;
	struct dirent *entry;
	char file_path[PATH_MAX_LEN] = {0};
	struct stat st;

	stat(scan_path, &st);
	if(!S_ISDIR(st.st_mode)) {
		if(is_skip_file_suffix(scan_path)){
			printf("The file does not comply with whitelist rules: %s\n", scan_path);
			return -1;
		}
		ht_init_scan_file(scan_path);
		return 0;
	}

	if ((dir=opendir(scan_path)) == NULL) {
		printf("open path %s fail\n", scan_path);
		g_scan_done = 1;
		return -1;
	}

	if(scan_deldb_flag == 1){
		if (ht_init_sqlite_exec("delete from whitelist")) {
			printf("clear DB file fail\n");
			g_scan_done = 1;
			return -1;
		}
	}

	while ((entry=readdir(dir)) != NULL) {
		memset(file_path, 0, PATH_MAX_LEN);
		
		if (entry->d_type == DT_DIR) {
			if (is_skip_dirs(entry->d_name))
				continue;
			if( strncmp( (scan_path + (strlen(scan_path)-1)) , "/", 1) == 0 ){
				snprintf(file_path, sizeof(file_path), "%s%s/", scan_path, entry->d_name);
			}else{
				snprintf(file_path, sizeof(file_path), "%s/%s/", scan_path, entry->d_name);
			}
			ht_init_scan_dir(file_path, (scan_file_callback)ht_init_scan_file, NULL);
		}
		else if (entry->d_type == DT_REG) {
			if(is_skip_file_suffix(entry->d_name))
				continue;
			
			if( strncmp( (scan_path + (strlen(scan_path)-1)) , "/", 1) == 0 ){
				snprintf(file_path, sizeof(file_path), "%s%s", scan_path, entry->d_name);
			}else{
				snprintf(file_path, sizeof(file_path), "%s/%s", scan_path, entry->d_name);
			}
			ht_init_scan_file(file_path);
		}
	}

	closedir(dir);

	g_scan_done = 1;
	
	return 0;
}


static int ht_command_scan(void)
{
	int i, worker_num = sysconf(_SC_NPROCESSORS_ONLN) / 2;
	pthread_t *workers;
	struct timeval begin, end;
	
	if (worker_num == 0)
		worker_num = 1;
	g_running_pthreads = worker_num;

	INIT_LIST_HEAD(&g_task_list);
	pthread_mutex_init(&g_task_lock, NULL);
	pthread_mutex_init(&g_array_lock, NULL);
	memset(g_array, 0, sizeof(g_array));

	workers = (pthread_t *)malloc(sizeof(pthread_t) * worker_num);
	for (i = 0; i < worker_num; i++) {
		pthread_create(&workers[i], NULL, ht_init_worker_thread, (void *)&i);
	}
	
	gettimeofday(&begin, NULL);
	
	ht_init_scan_whitelist();

	while (g_running_pthreads)
		usleep(10000);

	if (g_array_count > 0) {
		ht_init_write_whitelist_db(g_array, g_array_count);
	}

	gettimeofday(&end, NULL);

	printf("whitelist count: %u, thread num: %d, used %.2lf sec\n", g_total_count, worker_num,
			(double)(end.tv_sec - begin.tv_sec) + (end.tv_usec - begin.tv_usec)/1000000.00);

	free(workers);
	return HT_INIT_OK;
}

int sdp_get_local_adminkey(admin_t *admin)
{
	FILE *fp = NULL;
	char path[512] = {0};
	struct stat st;

	snprintf(path, sizeof(path)-1, "%s/etc/adminkey", HOME_PATH);

	stat(path, &st);
	if ((access(path, F_OK)) != 0 || (st.st_size != sizeof(*admin))){
		printf("file %s not exist or size error\n", path);
		return HT_INIT_ERR_EXIST;
	}

	fp = fopen(path, "rb");
	if (!fp) {
		printf("read %s fail\n", path);
		return HT_INIT_ERR_FILE;
	}

	fread((void *)admin, 1, sizeof(*admin), fp);
	fclose(fp);
	return HT_INIT_OK;
}

int sdp_whitelist_get_fromDB(int *row, int *column, char ***data)
{
	char db_path[512] = {0};
	sqlite3 *db = NULL;
	char *sql = "select * from whitelist order by hash";
	char *errmsg = NULL;

	snprintf(db_path, sizeof(db_path)-1, "%s/db/whitelist.db", HOME_PATH);

	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		printf("open db %s fail\n", db_path);
		return -1;
	}

	if (sqlite3_get_table(db, sql, data, row, column, &errmsg) != SQLITE_OK) {
		printf("get data fail, errmsg: %s\n", errmsg);
		sqlite3_close(db);
		agent_free(errmsg);
		return -1;
	}

	sqlite3_close(db);
	return 0;
}

char *sdp_format_json(cJSON *array, int action)
{
	cJSON *root = cJSON_CreateObject();
	cJSON *array2 = cJSON_Duplicate(array, 1);
	
	cJSON_AddItemToObject(root, "action", cJSON_CreateNumber(action));
	cJSON_AddItemToObject(root, "policy", array2);

	char *str = cJSON_PrintUnformatted(root);

	cJSON_Delete(root);
	return str;
}

static uint64_t ht_get_replay_counter()
{
	int ret;
	uint64_t counter = 0;

	if ((ret=tcf_get_replay_counter(&counter)) != 0) {
		printf("tcf_get_replay_counter fail! ret: %08X\n", ret);
		return 0;
	}

	return counter + 1;
}

static int ht_sm2_sign(admin_t *admin, const unsigned char *data, int data_len, unsigned char **sig)
{
	unsigned int sig_len;
		
	return os_sm2_sign(data, (unsigned int)data_len, admin->prikey, PRIKEY_LENGTH, 
						admin->pubkey, PUBKEY_LENGTH, sig, &sig_len);
}

int sdp_whitelist_set_sign(admin_t *admin, struct file_integrity_item_user *items,
								int item_count, int action, cJSON *array)
{
	int ret, size, id_len = ID_LENGTH;
	unsigned long long counter;
	char *json_str = NULL;
	unsigned char *sig = NULL;
	char tpcm_id[ID_LENGTH + 1] = {0};
	struct file_integrity_update *references = NULL;

	tcf_get_tpcm_id(tpcm_id, &id_len);
	json_str = sdp_format_json(array, action);
	counter = ht_get_replay_counter();
	
	
	ret = tcf_prepare_update_file_integrity(items, item_count, tpcm_id,	MAX_TPCM_ID_SIZE,
											action, counter, &references, &size);
	if(ret != 0) {
		printf("prepare smeasure policy fail, ret=%08X\n", ret);
		ret = HT_INIT_ERR_TCF;
		goto clean;
	}

	ht_sm2_sign(admin, (unsigned char *)references, size, &sig);
	ret = tcf_update_file_integrity(references, UID_LOCAL, CERT_TYPE_PUBLIC_KEY_SM2, 
						SIG_LENGTH, sig, (unsigned char *)json_str, strlen(json_str) + 1);
	if(ret != 0) {
		printf("update smeasure policy fail, ret=%08X\n", ret);
		ret = HT_INIT_ERR_TCF;
	}

clean:

	agent_free(sig);
	agent_free(json_str);
	agent_free(references);
	return ret;
}

int sdp_whitelist_set_policy(admin_t *admin, int total_count, int column, char **data)
{
	int ret = -1, left_count = total_count;
	int i, j, index = column, action = POLICY_ACTION_SET;
	const char *last_hash = "";
	struct file_integrity_item_user *items = NULL;
	
	items = (struct file_integrity_item_user *)agent_calloc(sizeof(*items) * ONCE_MAX_COUNT);
	if (items == NULL) {
		printf("malloc fail\n");
		return HT_INIT_ERR_MALLOC;
	}
	
	while (left_count > 0) {
		cJSON *json_array;
		int once_count = (left_count > ONCE_MAX_COUNT) ? ONCE_MAX_COUNT : left_count;

		json_array = cJSON_CreateArray();

		for(i = 0, j = 0; i < once_count; i++, index += 4) {
			cJSON *json_one;
			json_one = cJSON_CreateObject();
			cJSON_AddNumberToObject(json_one, "source", atoi(data[index + 3]));
			cJSON_AddStringToObject(json_one, "hash", data[index + 2]);
			cJSON_AddStringToObject(json_one, "path", data[index + 1]);
			cJSON_AddStringToObject(json_one, "guid", data[index]);

			/* 如果与上一个hash不同，才新增items赋值 */
			if (strcmp(data[index + 2], last_hash) != 0) {
				items[j].is_enable = 1;
				items[j].is_control = 1;
				items[j].hash_length = HASH_LENGTH;
				items[j].hash = agent_calloc(HASH_LENGTH);
				str_to_binary(data[index + 2], items[j].hash, HASH_LENGTH);

				j++;
			}
			
			last_hash = data[index + 2];
			cJSON_AddItemToArray(json_array, json_one);
		}

		ret = sdp_whitelist_set_sign(admin, items, j, action, json_array);
		action = POLICY_ACTION_ADD;

		for (i = 0; i < j; i++) {
			agent_free(items[i].hash);
		}
		cJSON_Delete(json_array);

		if (ret != HT_INIT_OK) {
			break;
		}

		left_count -= once_count;
	}
	
	agent_free(items);
	sqlite3_free_table(data);
	return ret;
}


int ht_command_sdp_whitelist()
{
	int row, column, ret = 0;
	char **data = NULL;
	admin_t admin;
	struct timeval begin, end;
	
	printf("ht_command_sdp_whitelist begin!\n");

	CHECK_FAIL(sdp_get_local_adminkey(&admin), );

	if (sdp_whitelist_get_fromDB(&row, &column, &data) < 0) {
		return HT_INIT_ERR_DB;
	}

	gettimeofday(&begin, NULL);

	ret = sdp_whitelist_set_policy(&admin, row, column, data);
	if(ret < 0)
    {
        printf("error wh_sdp_whitelist_set_policy faild\n");
        tools_log(HTTC_ERROR, "error wh_sdp_whitelist_set_policy faild!" );
        return ret;
    }
	gettimeofday(&end, NULL);
	printf("whitelist count: %d, used %.2lf sec\n", row, 
			(double)(end.tv_sec - begin.tv_sec) + (end.tv_usec - begin.tv_usec)/1000000.00);

	printf("ht_command_sdp_whitelist end!\n");

	return HT_INIT_OK;
}

int ht_command_scan_whitelist()
{
	char path[128] = {0};
	
	snprintf(path, sizeof(path)-1, "%s/%s/db/whitelist.db", home_path, HTTC_PATH);
	//printf("whitelist path : %s\n", path);
	tools_log(HTTC_INFO, "whitelist path: %s " , path);

	if (access(path, F_OK) != 0) {
		printf("DB file: [%s] not exist\n", path);
		tools_log(HTTC_ERROR, "DB file: [%s] not exist " , path);
		return HT_INIT_ERR_EXIST;
	}

    tools_log(HTTC_INFO, "begain ht_command_scan ");
	printf("begain ht_command_scan\n");
	ht_command_scan(); //收集白名单数据
	printf("end ht_command_scan\n");
	tools_log(HTTC_INFO, "end ht_command_scan ");

	return HT_INIT_OK;
}

int ht_del_whitelist_db(const struct whitelist *array, int count)
{
	int i;
	sqlite3 *db = NULL;
	char db_path[512] = {0};
	int ret = -1;
	char *errmsg, sql[5120];
	const char *sbuf = "(compressed)";
	size_t sbuf_len = strlen(sbuf);

	sprintf(db_path, "%s/%s/db/%s", home_path, HTTC_PATH, WHITELIST_DB_NAME);

	ret = sqlite3_open(db_path, &db);
	if(ret != 0) 
	{
		printf("sqlite3_open db_path: %s\n", db_path);
		return ret;
	}
	
	sqlite3_exec(db, "begin;", 0, 0, 0);
	
	for (i=0; i<count; ++i) {
		memset(sql, 0, sizeof(sql));
		if(strncmp(array[i].path, sbuf, sbuf_len) == 0)
		{
			const char *sqlbuf = "%(compressed)%";
			snprintf(sql, sizeof(sql) - 1, "delete from whitelist where path like '%s' and hash = '%s'", sqlbuf, array[i].hash);
		}else{
			snprintf(sql, sizeof(sql) - 1, "delete from whitelist where path = '%s' and hash = '%s'", array[i].path, array[i].hash);
		}
		ret = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
		if(ret != SQLITE_OK) {
			tools_log(HTTC_WARN, "exec sql [%s] fail, message :[%s]", sql, errmsg);
			ret = HTTC_ERR_SQLITE;
			return ret;
		}
	}
	sqlite3_exec(db, "commit;", 0, 0, 0);
	
	sqlite3_close(db);
	
	return 0;
}

/* 删除白名单数据及策略 */
/* 最多每800条处理一次 */
int ht_whitelist_del_db_and_policy(void)
{
	int ret=0,i, j;
	const char *last_hash = "";
	cJSON *json_array;
	struct file_integrity_item_user *items = NULL;
	admin_t admin;
	CHECK_FAIL(sdp_get_local_adminkey(&admin), );

	json_array = cJSON_CreateArray();
	items = (struct file_integrity_item_user *)agent_calloc(sizeof(*items) * ONCE_MAX_COUNT);
	if (items == NULL) {
		printf("malloc fail\n");
		g_array_count = 0;
		memset(g_array, 0, sizeof(g_array));
		return HT_INIT_ERR_MALLOC;
	}

	for(i = 0, j = 0; i < g_array_count; i++) {
		cJSON *json_one;
		json_one = cJSON_CreateObject();
		cJSON_AddNumberToObject(json_one, "source", 3);
		cJSON_AddStringToObject(json_one, "hash", g_array[i].hash);
		cJSON_AddStringToObject(json_one, "path", g_array[i].path);
		cJSON_AddStringToObject(json_one, "guid", g_array[i].guid);

		/* 如果与上一个hash不同，才新增items赋值 */
		if (strcmp(g_array[i].hash, last_hash) != 0) {
			items[j].is_enable = 1;
			items[j].is_control = 1;
			items[j].hash_length = HASH_LENGTH;
			items[j].hash = agent_calloc(HASH_LENGTH);
			str_to_binary(g_array[i].hash, items[j].hash, HASH_LENGTH);

			j++;
			cJSON_AddItemToArray(json_array, json_one);
		}
			
		last_hash = g_array[i].hash;
	}

	ret = sdp_whitelist_set_sign(&admin, items, j, POLICY_ACTION_DELETE, json_array);
	if(ret != 0)
	{
		tools_log(HTTC_ERROR,"sdp_whitelist_set_sign err\n");
	}

	ht_del_whitelist_db(g_array, g_array_count);

	g_array_count = 0;
	memset(g_array, 0, sizeof(g_array));

	for (i = 0; i < j; i++) {
		agent_free(items[i].hash);
	}
	cJSON_Delete(json_array);
	agent_free(items);

	return ret;
}

int ht_whitelist_del_whitelist(char *file_path)
{
	int ret = -1;
	whitelist_exec_node_t *exec_pos;

	//过滤指定后缀文件
	if(is_skip_file_suffix(file_path))
	{
		tools_log(HTTC_ERROR, "file:%s  is no need del whitelist", file_path);
		return 1;
	}
	//判断文件是否有可执行权限
	ret = is_exec(file_path, g_time_first);
	if( ret == 1) {
		char hash[SM3_LEN*2 + 1] = {0};
		char uuid[UUID_LEN] = {0};
		uuid_t _uuid;
		unsigned char _hash[HASH_LENGTH];
		if (ttm_sm3_file(file_path, _hash))
			return -1;

		uuid_generate(_uuid);
		uuid_unparse(_uuid, uuid);
		binary_to_str(_hash, hash, HASH_LENGTH * 2);

		strncpy(g_array[g_array_count].guid, uuid, UUID_LEN);
		strncpy(g_array[g_array_count].path, file_path, PATH_MAX_LEN);
		strncpy(g_array[g_array_count].hash, hash, SM3_LEN * 2);

		g_array_count++;
		g_total_count++;
		if(g_array_count == ONCE_MAX_COUNT) { //每800条插入一次白名单
			ht_whitelist_del_db_and_policy();
		}
	}else if(ret > 0) 
	{
		struct list_head *next, *node_pos, whitelist_tar_list;
		int type = 0;
		
		if(ret == 2) type = FILE_COMPRESS_ZIP; // zip file
		if(ret == 3) type = FILE_COMPRESS_TAR; // gz file
		if(ret == 4) type = FILE_COMPRESS_XZ; // xz file
		INIT_LIST_HEAD(&whitelist_tar_list);
		if(g_unzip_flag == 1){ //对压缩包中的ko加白
			if(ht_whitelist_uncompress(file_path, &whitelist_tar_list,type)) {
				tools_log(HTTC_ERROR, "file:%s  ht_whitelist_uncompress fail ", file_path);
			}
		}else if(g_unzip_flag == 2){ //对压缩包中符合白名单的文件加白
			if(ht_scan_uncompress_all(file_path, &whitelist_tar_list,type)) {
				tools_log(HTTC_ERROR, "file:%s  ht_scan_uncompress_all fail ", file_path);
			}
		}

		//读取链表逐个删除
		pthread_mutex_lock(&g_array_lock);
		list_for_each_safe(node_pos, next, &whitelist_tar_list) {
			exec_pos = list_entry(node_pos, whitelist_exec_node_t, tar_list);

			strncpy(g_array[g_array_count].guid, exec_pos->uuid, UUID_LEN);
			strncpy(g_array[g_array_count].path, exec_pos->file_path, PATH_MAX_LEN);
			strncpy(g_array[g_array_count].hash, exec_pos->hash_str, SM3_LEN * 2);

			list_del(&exec_pos->tar_list);
			agent_free(exec_pos);

			g_array_count++;
			g_total_count++;

			if (g_array_count == ONCE_MAX_COUNT) { //每800条删除一次白名单
				ht_whitelist_del_db_and_policy();
			}
		}
		pthread_mutex_unlock(&g_array_lock);
	}

	return ret;
}

int ht_whitelst_del_by_path(char *path)
{
	DIR *dir;
	struct dirent *entry;
	char file_path[PATH_MAX_LEN] = {0};
	int ret = -1;
	struct stat st;

	stat(path, &st);
	if(!S_ISDIR(st.st_mode)) {
		if(is_skip_file_suffix(path)){
			printf("The file does not comply with whitelist rules: %s\n", path);
			return -1;
		}
		ret = ht_whitelist_del_whitelist(path);
		if(ret)
		{
			tools_log(HTTC_WARN, "ht_whitelist_del_whitelist %s err! ", path);
		}
		return 0;
	}

	if ((dir=opendir(path)) == NULL) {
		printf("open path %s\n", path);
		return -1;
	}

	while ((entry=readdir(dir)) != NULL ) {
		if (strcmp(".", entry->d_name) == 0 || strcmp("..", entry->d_name) == 0)
			continue;

		memset(file_path, 0, PATH_MAX_LEN);
		
		if (entry->d_type == DT_DIR) {
			if( strncmp( (path + (strlen(path)-1)) , "/", 1) == 0 ){
				snprintf(file_path, sizeof(file_path), "%s%s/", path, entry->d_name);
			}else{
				snprintf(file_path, sizeof(file_path), "%s/%s/", path, entry->d_name);
			}
			ht_whitelst_del_by_path(file_path);
		}
		else if (entry->d_type == DT_REG) {
			if(is_skip_file_suffix(entry->d_name))
				continue;

			if( strncmp( (path + (strlen(path)-1)) , "/", 1) == 0 ){
				snprintf(file_path, sizeof(file_path), "%s%s", path, entry->d_name);
			}else{
				snprintf(file_path, sizeof(file_path), "%s/%s", path, entry->d_name);
			}
			ret = ht_whitelist_del_whitelist(file_path);
			if(ret)
			{
				tools_log(HTTC_WARN, "ht_whitelist_del_whitelist %s err! ", file_path);
			}
		}
	}
	
	ret = 0;
	closedir(dir);
	return ret;
}

/* 增量添加白名单 */
/* 最多每800条插入一次 */
/* */
int ht_whitelist_s_add_whitelist(void)
{
	int ret=0,i, j;
	const char *last_hash = "";
	cJSON *json_array;
	struct file_integrity_item_user *items = NULL;
	admin_t admin;
	CHECK_FAIL(sdp_get_local_adminkey(&admin), );

	ht_init_write_whitelist_db(g_array, g_array_count);

	json_array = cJSON_CreateArray();
	items = (struct file_integrity_item_user *)agent_calloc(sizeof(*items) * ONCE_MAX_COUNT);
	if (items == NULL) {
		printf("malloc fail\n");
		g_array_count = 0;
		memset(g_array, 0, sizeof(g_array));
		return HT_INIT_ERR_MALLOC;
	}

	for(i = 0, j = 0; i < g_array_count; i++) {
		cJSON *json_one;
		json_one = cJSON_CreateObject();
		cJSON_AddNumberToObject(json_one, "source", 3);
		cJSON_AddStringToObject(json_one, "hash", g_array[i].hash);
		cJSON_AddStringToObject(json_one, "path", g_array[i].path);
		cJSON_AddStringToObject(json_one, "guid", g_array[i].guid);

		/* 如果与上一个hash不同，才新增items赋值 */
		if (strcmp(g_array[i].hash, last_hash) != 0) {
			items[j].is_enable = 1;
			items[j].is_control = 1;
			items[j].hash_length = HASH_LENGTH;
			items[j].hash = agent_calloc(HASH_LENGTH);
			str_to_binary(g_array[i].hash, items[j].hash, HASH_LENGTH);

			j++;
			cJSON_AddItemToArray(json_array, json_one);
		}
			
		last_hash = g_array[i].hash;
	}

	ret = sdp_whitelist_set_sign(&admin, items, j, POLICY_ACTION_ADD, json_array);
	if(ret != 0)
	{
		printf("sdp_whitelist_set_sign err\n");
	}

	g_array_count = 0;
	memset(g_array, 0, sizeof(g_array));

	for (i = 0; i < j; i++) {
		agent_free(items[i].hash);
	}
	cJSON_Delete(json_array);
	agent_free(items);

	return ret;
}

/* 添加白名单 */
/* 1 该文件/目录 不需要添加白名单 */
/* -1 添加白名单失败 */
/* 0  添加白名单成功 */
int ht_whitelist_add_whitelist(char *file)
{
	int ret = -1;
	//过滤指定后缀文件
	if(is_skip_file_suffix(file))
	{
		//printf("file:%s  is no need add whitelist\n", file);
		tools_log(HTTC_ERROR, "file:%s  is no need add whitelist ", file);
		return 1;
	}
	//判断文件是否有可执行权限
	ret = is_exec(file, g_time_first);
	if( ret == 1) {
		char hash[SM3_LEN*2 + 1] = {0};
		char uuid[UUID_LEN] = {0};
		uuid_t _uuid;
		unsigned char _hash[HASH_LENGTH];
		if (ttm_sm3_file(file, _hash))
			return -1;

		uuid_generate(_uuid);
		uuid_unparse(_uuid, uuid);
		binary_to_str(_hash, hash, HASH_LENGTH * 2);

	
		strncpy(g_array[g_array_count].guid, uuid, UUID_LEN);
		strncpy(g_array[g_array_count].path, file, PATH_MAX_LEN);
		strncpy(g_array[g_array_count].hash, hash, SM3_LEN * 2);

		g_array_count++;
		g_total_count++;

		if(g_array_count == ONCE_MAX_COUNT) { //每800条插入一次白名单
			ht_whitelist_s_add_whitelist();
		}
	}else if(ret > 0) 
	{
		int type = 0;
		struct list_head *next, *node_pos, whitelist_tar_list;

		if(ret == 2) type = FILE_COMPRESS_ZIP; // zip file
		if(ret == 3) type = FILE_COMPRESS_TAR; // gz file
		if(ret == 4) type = FILE_COMPRESS_XZ; // xz file
		INIT_LIST_HEAD(&whitelist_tar_list);
		if(g_unzip_flag == 1){ //对压缩包中的ko加白
			if(ht_whitelist_uncompress(file, &whitelist_tar_list,type)) {
				tools_log(HTTC_ERROR, "file:%s  ht_whitelist_uncompress fail ", file);
			}
		}else if(g_unzip_flag == 2){ //对压缩包中符合白名单的文件加白
			if(ht_scan_uncompress_all(file, &whitelist_tar_list,type)) {
				tools_log(HTTC_ERROR, "file:%s  ht_scan_uncompress_all fail ", file);
			}
		}

		//插入链表，到达上限后写入数据库
		pthread_mutex_lock(&g_array_lock);
		list_for_each_safe(node_pos, next, &whitelist_tar_list) {
			whitelist_exec_node_t *exec_pos;
			exec_pos = list_entry(node_pos, whitelist_exec_node_t, tar_list);

			strncpy(g_array[g_array_count].guid, exec_pos->uuid, UUID_LEN);
			strncpy(g_array[g_array_count].path, exec_pos->file_path, PATH_MAX_LEN);
			strncpy(g_array[g_array_count].hash, exec_pos->hash_str, SM3_LEN * 2);

			list_del(&exec_pos->tar_list);
			agent_free(exec_pos);

			g_array_count++;
			g_total_count++;

			if (g_array_count == ONCE_MAX_COUNT) { //每800条插入一次白名单
				ht_whitelist_s_add_whitelist();
			}
		}
		pthread_mutex_unlock(&g_array_lock);
	}

	return ret;
}

int ht_whitelist_scan_dir(char *path)
{
	DIR *dir;
	struct dirent *entry;
	char file_path[PATH_MAX_LEN] = {0};
	int ret = -1;
	struct stat st;

	stat(path, &st);
	if(!S_ISDIR(st.st_mode)) {
		if(is_skip_file_suffix(path)){
			printf("The file does not comply with whitelist rules: %s\n", path);
			return -1;
		}
		ret = ht_whitelist_add_whitelist(path);
		if(ret)
		{
			tools_log(HTTC_WARN, "ht_whitelist_add_whitelist %s err! ", path);
		}
		return 0;
	}

	if ((dir=opendir(path)) == NULL) {
		printf("open path %s\n", path);
		return -1;
	}

	while ((entry=readdir(dir)) != NULL ) {
		if (strcmp(".", entry->d_name) == 0 || strcmp("..", entry->d_name) == 0)
			continue;

		memset(file_path, 0, PATH_MAX_LEN);
		
		if (entry->d_type == DT_DIR) {
			if( strncmp( (path + (strlen(path)-1)) , "/", 1) == 0 ){
				snprintf(file_path, sizeof(file_path), "%s%s/", path, entry->d_name);
			}else{
				snprintf(file_path, sizeof(file_path), "%s/%s/", path, entry->d_name);
			}
			ht_whitelist_scan_dir(file_path);
		}
		else if (entry->d_type == DT_REG) {
			if(is_skip_file_suffix(entry->d_name))
				continue;

			if( strncmp( (path + (strlen(path)-1)) , "/", 1) == 0 ){
				snprintf(file_path, sizeof(file_path), "%s%s", path, entry->d_name);
			}else{
				snprintf(file_path, sizeof(file_path), "%s/%s", path, entry->d_name);
			}
			ret = ht_whitelist_add_whitelist(file_path);
			if(ret)
			{
				tools_log(HTTC_WARN, "ht_whitelist_add_whitelist %s err! ", file_path);
			}
		}
	}
	
	ret = 0;
	closedir(dir);
	return ret;
}

void sighandler(int signum)
{
	printf("白名单工具扫描过程中不能强制退出 请耐心等待......\n");
}

int main(int argc, char *argv[])
{
	struct timeval begin, end;
	int ret = HT_INIT_HELP;

	program_name = argv[0]; 
	if (argc < 2) {//入参检查
		usage();
		printf("invalid parameters specified\n");
		exit(1);
	}
	command = argv[1];

	tools_log_init();
	
	signal(SIGINT, sighandler);

	if (strcmp(command, "-a") == 0) { //扫描全部的白名单
		scan_path = SCAN_DEFAULT_PATH;
		home_path = HOME_DEFAULT_PATH;
		scan_deldb_flag = 1; //清理原先数据

		if(argc == 3)
		{
			if( strcmp(argv[2], "nounzip") == 0 )
				g_unzip_flag = 0;
			else if( strcmp(argv[2], "unzip_ko") == 0 )
				g_unzip_flag = 1;
			else if( strcmp(argv[2], "unzip_all") == 0 )
				g_unzip_flag = 2;
			else
				return usage();
		}
		//backup httcfile
		ht_backup(); //先备份一下

		ret = ht_command_scan_whitelist(); //收集白名单数据到数据库中
		if(ret != 0){
			ht_rollback();
			ht_cleanback();
			printf("ht_command_scan_whitelist error %d !\n", ret);
			tools_log_destroy();
			exit(1);
		}
		
		ret = ht_command_sdp_whitelist();//设置白名单策略
		if(ret != 0){
			ht_rollback();
			ht_cleanback();
			printf("ht_command_sdp_whitelist error %d !\n", ret);
			tools_log_destroy();
			exit(1);
		}

		ht_cleanback();
	} else if (strcmp(command, "-s") == 0) {//扫描指定路径的白名单
		scan_path = argv[2];//指定路径
		home_path = HOME_DEFAULT_PATH;//安装路径
		if(!scan_path) {//入参检查
			usage();
			printf("no scan path is load, exit!\n");
			tools_log_destroy();
			exit(1);
		}

		if(argc == 4)
		{
			if( strcmp(argv[3], "nounzip") == 0 )
				g_unzip_flag = 0;
			else if( strcmp(argv[3], "unzip_ko") == 0 )
				g_unzip_flag = 1;
			else if( strcmp(argv[3], "unzip_all") == 0 )
				g_unzip_flag = 2;
			else
				return usage();
		}

		gettimeofday(&begin, NULL);

		ht_backup(); //备份一下		

		ret = ht_whitelist_scan_dir(scan_path);
		if(ret != 0){
			ht_rollback();
			ht_cleanback();
			printf("ht_whitelist_scan_dir error %d !\n", ret);
			tools_log_destroy();
			exit(1);
		}

		if(g_array_count > 0)
		{
			ht_whitelist_s_add_whitelist();
		}

		ht_cleanback();
		gettimeofday(&end, NULL);
		printf("path: %s scan whitelist count: %u, used %.2lf sec\n", scan_path, g_total_count,
			(double)(end.tv_sec - begin.tv_sec) + (end.tv_usec - begin.tv_usec)/1000000.00);

	} else if (strcmp(command, "-c") == 0) {
		ret = ht_set_switch_whitelist(0);
	} else if (strcmp(command, "-o") == 0) {
		ret = ht_set_switch_whitelist(1);
	} else if (strcmp(command, "-d") == 0) { //删除指定文件或目录的白名单策略
		home_path = HOME_DEFAULT_PATH;
		if(argc == 4)
		{
			if( strcmp(argv[3], "nounzip") == 0 )
				g_unzip_flag = 0;
			else if( strcmp(argv[3], "unzip_ko") == 0 )
				g_unzip_flag = 1;
			else if( strcmp(argv[3], "unzip_all") == 0 )
				g_unzip_flag = 2;
			else
				return usage();
		}
		gettimeofday(&begin, NULL);

		ht_backup(); //备份一下
		
		ret = ht_whitelst_del_by_path(argv[2]);

		if(ret != 0){
			ht_rollback();
			ht_cleanback();
			printf("ht_whitelst_del_by_path error %d !\n", ret);
			tools_log_destroy();
			exit(1);
		}

		if(g_array_count > 0)
		{
			ht_whitelist_del_db_and_policy();
		}

		ht_cleanback();

		gettimeofday(&end, NULL);
		printf("path: %s del whitelist count: %u, used %.2lf sec\n", argv[2], g_total_count,
			(double)(end.tv_sec - begin.tv_sec) + (end.tv_usec - begin.tv_usec)/1000000.00);
	}

	tools_log_destroy();
	return ret == HT_INIT_HELP ? usage() : ret;
}
