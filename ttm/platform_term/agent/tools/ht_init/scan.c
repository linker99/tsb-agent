#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <uuid/uuid.h>
#include <sys/types.h>
#include <sys/stat.h>

#define __USE_GNU
#include <sched.h>
#include <pthread.h>

#include "sqlite3.h"
#include "public.h"
#include "scan.h"

struct whitelist g_array[ARRAY_MAX_LEN];
static unsigned int g_array_count = 0;
static unsigned int g_total_count = 0;
pthread_mutex_t g_array_lock;

struct list_head g_task_list;
static int g_task_count = 0;
pthread_mutex_t g_task_lock;

static int g_running_pthreads = 0;
static int g_scan_done = 0;
static int g_time_first = 1;	//默认时间优先
static int g_unzip_flag = 1;    //0-不处理压缩包 1-扫描压缩包中的ko加白 2-对压缩包中符合白名单条件的文件加白

int ht_init_write_whitelist_db(struct whitelist *array, int count)
{
	int i;
	sqlite3 *db = NULL;
	char db_path[512] = {0};

	sprintf(db_path, "%s/db/%s", HOME_PATH, WHITELIST_DB_NAME);

	sqlite3_open(db_path, &db);
	//sqlite3_exec(db,"PRAGMA synchronous = OFF; ",0,0,0);  //关闭写同步

	sqlite3_exec(db, "begin;", 0, 0, 0);
	sqlite3_stmt *stmt;
	const char *sql = "insert into whitelist values(?,?,?,?)";
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, 0);

	for (i=0; i<count; ++i) {
		sqlite3_reset(stmt);
		sqlite3_bind_text(stmt, 1, g_array[i].guid, -1, SQLITE_STATIC);
		sqlite3_bind_text(stmt, 2, g_array[i].path, -1, SQLITE_STATIC);
		sqlite3_bind_text(stmt, 3, g_array[i].hash, -1, SQLITE_STATIC);
		sqlite3_bind_int(stmt, 4, 1);
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

	sprintf(db_path, "%s/db/%s", HOME_PATH, WHITELIST_DB_NAME);

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

int ht_init_scan_file(const char* file_path, void *args)
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

void *ht_init_worker_thread(void *args)
{
	uuid_t _uuid;
	cpu_set_t mask;
	struct task *t;
	char hash[HASH_LENGTH];
	int index = *(int *)args;
	whitelist_exec_node_t *exec_node = NULL, *exec_pos;
	struct list_head *pos, *next, *node_pos, whitelist_tar_list;
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

static int ht_init_scan_whitelist()
{
	DIR	*dir;
	struct dirent *entry;
	char file_path[PATH_MAX_LEN] = {0};

	if ((dir=opendir(SCAN_DEFAULT_PATH)) == NULL) {
		printf("open path %s fail\n", SCAN_DEFAULT_PATH);
		g_scan_done = 1;
		return -1;
	}

	if (ht_init_sqlite_exec("delete from whitelist")) {
		printf("clear DB file fail\n");
		g_scan_done = 1;
		return -1;
	}

	while ((entry=readdir(dir)) != NULL) {
		memset(file_path, 0, PATH_MAX_LEN);

		if (entry->d_type == DT_DIR) {
			if (is_skip_dirs(entry->d_name))
				continue;

			snprintf(file_path, sizeof(file_path), "%s%s/", SCAN_DEFAULT_PATH, entry->d_name);
			ht_init_scan_dir(file_path, (scan_file_callback)ht_init_scan_file, NULL);
		}
		else if (entry->d_type == DT_REG) {
			if(is_skip_file_suffix(entry->d_name))
				continue;

			snprintf(file_path, sizeof(file_path), "%s%s", SCAN_DEFAULT_PATH, entry->d_name);
			ht_init_scan_file(file_path, NULL);
		}
	}

	closedir(dir);

	g_scan_done = 1;

	return 0;
}

int ht_init_command_scan(int argc, char **argv)
{
	int i, worker_num = sysconf(_SC_NPROCESSORS_ONLN) / 2;
	pthread_t *workers;
	char path[128] = {0};
	struct timeval begin, end;

	//如果设置了accuracy_first参数，则改为准确度优先
	if (argc > 0 && strcmp(argv[0], "accuracy_first") == 0)
		g_time_first = 0;

	//如果设置了nounzip 则不处理压缩包 unzip_all 处理压缩包中符合白名单的文件 默认unzip_ko处理压缩包中的ko文件 
	if ( argc > 1 )
	{
		if( strcmp(argv[1], "nounzip") == 0 )
			g_unzip_flag = 0;
		else if( strcmp(argv[1], "unzip_ko") == 0 )
			g_unzip_flag = 1;
		else if( strcmp(argv[1], "unzip_all") == 0 )
			g_unzip_flag = 2;
		else
			return HT_INIT_HELP;
	}


	snprintf(path, sizeof(path)-1, "%s/db/whitelist.db", HOME_PATH);

	if (access(path, F_OK) != 0) {
		printf("DB file: [%s] not exist\n", path);
		return HT_INIT_ERR_EXIST;
	}

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
