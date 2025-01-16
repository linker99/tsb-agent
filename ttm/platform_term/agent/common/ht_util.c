#include "ht_util.h"
#include "ht_crypt.h"
#include "ht_def.h"
#include "list.h"
#include <pthread.h>

#define _GNU_SOURCE

pthread_mutex_t g_uncompress_log_lock = PTHREAD_MUTEX_INITIALIZER;

char *g_skip_dirs[] = {".", "..", "proc", "lost+found", "sys", "dev", NULL};
static char *g_skip_suffix[] = {".txt", ".png", ".js", ".css", ".sta",
	".lni", "dis", ".cad", ".o", ".a", ".log",
	".xml", ".lock", ".mo", ".idx",
	".deny", ".LOCK", ".cache",
	".h", ".c",  ".html", ".deb", ".rpm",
	".gif", ".old", ".hpp", ".tcc", ".var",
	".jpg", ".ini", ".xpt", "tcl", ".am", "omf",
	".defs", ".ttf", ".pcf", ".afm", ".pfb", ".gsf",
	".pfa", ".xsl", ".kbd", ".svg", ".icon",
	".idl", ".swg", ".i", ".vim", ".awk",
	".pm", ".pod", ".ipp", ".rdf", ".rws",
	".amf", ".cmap", ".alias", ".multi",
	".cset", ".desktop", ".dsl", ".elc",
	".pbm", ".pdf", ".htm", ".in", ".m4", ".x",
	".tcl", ".al", ".omf", ".xpm", ".xinf",
	".eps", ".if", ".tmpl", ".glade", ".cfg", ".hhp",
	".cpp", ".meta", ".LIB", ".directory", ".lang", ".svn-base",
	".XML", ".iso",  ".json", ".avi", ".swf", ".mp4",
	"JPG", NULL
};

static char *g_scan_suffix[] = {".ko", ".sh", ".py", ".so", NULL};

decompression_func_t decompression_func[3] = {
	{
		.type = FILE_COMPRESS_TAR,
		.decomression = tar_file_decompression,
	},
	{
		.type = FILE_COMPRESS_ZIP,
		.decomression = zip_file_decompression,
	},
	{
		.type = FILE_COMPRESS_XZ,
		.decomression = xz_file_decompression,
	}
};

int is_folder_empty(const char *path) {
    DIR *dir = opendir(path);
    
    if (dir == NULL) {
        return -2; 
    }

    const struct dirent *entry;
    int isEmpty = 0; 
    
    while ((entry = readdir(dir)) != NULL) {
        if ((entry->d_type == DT_REG || entry->d_type == DT_DIR) && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            isEmpty = -1; 
            break;
        }
    }
    closedir(dir);

    return isEmpty; 
}

int tar_file_decompression(const char *tar_path, const char *temp_path)
{
	char buffer[1024];
	snprintf(buffer, sizeof(buffer), "tar -xf '%s' -C '%s' > /dev/null 2>&1", tar_path, temp_path);
	if(system(buffer)) {
		return -1;
	}
	return 0;
}

int zip_file_decompression(const char *tar_path, const char *temp_path)
{
	char buffer[1024];
	snprintf(buffer, sizeof(buffer), "unzip -P123 -q '%s' -d '%s' > /dev/null 2>&1", tar_path, temp_path);
	if(system(buffer)) {
		return -1;
	}
	return 0;
}

int xz_file_decompression(const char *tar_path, const char *temp_path)
{
	char buffer[1024];
	snprintf(buffer, sizeof(buffer), "tar -xf '%s' -C '%s' > /dev/null 2>&1", tar_path, temp_path);
	if(system(buffer)){
		char *xz_name;
		xz_name = strrchr(tar_path, '/');
		xz_name = xz_name + 1;
		
		char ln_cmd[1024];
		snprintf(ln_cmd, sizeof(ln_cmd), "ln -s '%s' '%s/%s'", tar_path, temp_path, xz_name);
		if(system(ln_cmd)){
			return -1;
		}
		

		snprintf(buffer, sizeof(buffer), "xz -dkf '%s/%s' > /dev/null 2>&1", temp_path, xz_name);
		if(system(buffer)){
			return -1;
		}
		return 0;
	}

	if(is_folder_empty(temp_path) == 0){
        char *xz_name;
		xz_name = strrchr(tar_path, '/');
		xz_name = xz_name + 1;

		char ln_cmd[1024];
		snprintf(ln_cmd, sizeof(ln_cmd), "ln -s '%s' '%s/%s'", tar_path, temp_path, xz_name);
		if(system(ln_cmd)){
			return -1;
		}


		snprintf(buffer, sizeof(buffer), "xz -dkf '%s/%s' > /dev/null 2>&1", temp_path, xz_name);
		if(system(buffer)){
			return -1;
		}
		return 0;
    }else{
        return 0;
    }
}

int is_skip_dirs(const char *dir_name)
{
	int i;

	//过滤指定目录
	for (i=0; g_skip_dirs[i]; i++) {
		if (strcmp(dir_name, g_skip_dirs[i]) == 0)
			return 1;
	}

	return 0;
}

int is_skip_file_suffix(char *file_path)
{
	int i;
	char *p;

	char *pos = file_path;
	pos += strlen(file_path);
	while(pos > file_path && *(pos - 1) != '/') pos--;

	//过滤指定文件后缀名
	for (i=0; g_skip_suffix[i]; i++) {
		if (strlen(pos) < strlen(g_skip_suffix[i]))
			continue;

		p = pos;
		p = p + strlen(pos) - strlen(g_skip_suffix[i]);
		if (strcmp(p, g_skip_suffix[i])==0)
			return 1;
	}

	return 0;
}

int is_scan_file_suffix(char *file_path)
{
	int i;
	char *p;

	//需要扫描的文件后缀名
	for (i=0; g_scan_suffix[i]; i++) {
		if (strlen(file_path) < strlen(g_scan_suffix[i]))
			continue;

		p = file_path;
		p = p + strlen(file_path) - strlen(g_scan_suffix[i]);
		if (strcmp(p, g_scan_suffix[i])==0)
			return 1;
	}

	return 0;
}


unsigned long long ht_getmill_time()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (unsigned long long)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

void ht_getformat_time(char *cur_time)
{
	if(!cur_time)
		return;

	char Year[6] = {0};
	char Month[4] = {0};
	char Day[4] = {0};
	char Hour[4] = {0};
	char Min[4] = {0};
	char Sec[4] = {0};

	time_t current_time;
	const struct tm* now_time;
	time(&current_time);
	now_time = localtime(&current_time);

	strftime(Year, sizeof(Year), "%Y-", now_time);
	strftime(Month, sizeof(Month), "%m-", now_time);
	strftime(Day, sizeof(Day), "%d ", now_time);
	strftime(Hour, sizeof(Hour), "%H:", now_time);
	strftime(Min, sizeof(Min), "%M:", now_time);
	strftime(Sec, sizeof(Sec), "%S", now_time);

	strncat(cur_time, Year, 5);
	strncat(cur_time, Month, 3);
	strncat(cur_time, Day, 3);
	strncat(cur_time, Hour, 3);
	strncat(cur_time, Min, 3);
	strncat(cur_time, Sec, 3);

}

/*
 *	1、时间优先: 所有路径下的文件，有执行权限就会采集，没有执行权限再去判断后缀名和文件头
 *	2、准确度优先: 只有包含bin或者sbin关键字路径下的文件，有执行权限就会采集，其余路径的文件直接判断后缀名和文件头
 *	2、修改准确度优先： 只有/bin/或者/sbin/关键字路径下的文件，有执行权限就会采集，其余路径的文件直接判断后缀名和文件头
 */
// 1-true 2-zip file  3-gzip file 4-xz file

int is_exec(char *file_path, int g_time_first)
{
	unsigned char buf[512] = {0};
	struct stat statbuf;

	if (g_time_first)
		goto time_first_label;

	if ((strncmp(file_path, "/bin/", 5) == 0) || (strncmp(file_path, "/sbin/", 6) == 0)) {
time_first_label:
		stat(file_path, &statbuf);

		//有些系统文件大小为空，fread时会阻塞，应该过滤掉
		if (statbuf.st_size == 0)
			return 0;

		//具有可执行权限的文件
		if (access(file_path, X_OK) == 0)
			return 1;
	}

	//若文件为指定后缀，则直接判断为可执行文件
	if (is_scan_file_suffix(file_path))
		return 1;

	FILE *fp = fopen(file_path, "rb");
	if (!fp)
		return 0;

	fread(buf, 1, sizeof(buf), fp);
	fclose(fp);

	//二进制程序
	if (strncmp(buf, ELFMAG, SELFMAG) == 0) {
		return 1;
	}

	//shell脚本
	if (strncmp(buf, "#!", 2) == 0)
		return 1;
	//if (buf[0] == 0x50 && buf[1] == 0x4B && buf[2] == 0x03 && buf[3] == 0x04){
	if ( buf[0] == 0x50 && buf[1] == 0x4B ){
		return 2; // ZIP 文件
	}
	if ( buf[4] == 0x50 && buf[5] == 0x4B ){
		return 2; // ZIP 文件
	}
	if (buf[0] == 0x1F && buf[1] == 0x8B ){
        	return 3; // Gzip 文件
	}
	if (buf[0] == 0x1F && buf[4] == 0x8B ){
        	return 3; // Gzip 文件
	}
	if ( memcmp(buf + 257, "ustar", 5) == 0 ){
        	return 3; // Gzip 文件
	}
	
	if (buf[0] == 0xFD && buf[1] == 0x37 && buf[2] == 0x7A && buf[3] == 0x58){
        	return 4; // XZ 文件
	}

	return 0;
}

int ht_init_scan_dir(char *path, scan_file_callback scan_file_handle, void *args)
{
	DIR *dir;
	struct dirent *entry;
	char file_path[PATH_MAX_LEN] = {0};

	if ((dir=opendir(path)) == NULL) {
		//printf("open path %s\n", path);
		return -1;
	}

	while ((entry=readdir(dir)) != NULL ) {
		if (strcmp(".", entry->d_name) == 0 || strcmp("..", entry->d_name) == 0)
			continue;

		memset(file_path, 0, PATH_MAX_LEN);

		if (entry->d_type == DT_DIR) {
			snprintf(file_path, sizeof(file_path), "%s%s/", path, entry->d_name);
			ht_init_scan_dir(file_path, scan_file_handle, args);
		}
		else if (entry->d_type == DT_REG) {
			if(is_skip_file_suffix(entry->d_name))
				continue;

			snprintf(file_path, sizeof(file_path), "%s%s", path, entry->d_name);
			scan_file_handle(file_path, args);
		}
	}

	closedir(dir);
	return 0;
}

int ht_init_getfile_hash(char *file_path, char *hash, char *uuid)
{
	uuid_t _uuid;
	unsigned char _hash[HASH_LENGTH];

	if (!is_exec(file_path, 0))
		return -1;

	if (ttm_sm3_file(file_path, _hash))
		return -1;

	uuid_generate(_uuid);
	uuid_unparse(_uuid, uuid);
	binary_to_str(_hash, hash, HASH_LENGTH * 2);

	return 0;
}

//把文件 hash 路径 uuid 加入 list_head 链表中
int ht_init_scan_file_package(char *file_path, struct list_head *g_tar_list)
{
	char tar_hash[HASH_LENGTH * 2 + 1] = {0};
	char tar_uuid[UUID_LEN] = {0};

    //判断头
    FILE* file = fopen(file_path, "rb");
    if (file == NULL) {
        return 0;  // 文件打开失败，不是.ko文件
    }
    char buf[SELFMAG];
    if (fread(buf, 1, SELFMAG, file) != SELFMAG) {
        fclose(file);
        return 0;  // 读取文件失败，不是.ko文件
    }
    fclose(file);
    if (strncmp(buf, ELFMAG, SELFMAG) != 0) {
        return 0;  // 前SELFMAG个字节与ELFMAG不匹配，不是.ko文件
    }

    //判断尾
    const char *filename = strrchr(file_path, '/');

    if (filename == NULL) {
        filename = file_path;
    } else {
        filename++; 
    }
        //判断文件名是否以 ".ko" 结尾
    const char *tail = strrchr(filename, '.');
    if (tail == NULL || tail == filename || strcmp(tail, ".ko") != 0) {
        return 0;
    }

	int ret = ht_init_getfile_hash(file_path, tar_hash, tar_uuid);
	if(ret == -1){
		return 0;
	}


	whitelist_exec_node_t *t = (whitelist_exec_node_t *)agent_malloc(sizeof(whitelist_exec_node_t));



	char end_path[PATH_MAX_LEN] = {0};
	sprintf(end_path, "(compressed)%s", file_path);
	strcpy(t->file_path, end_path);



	strcpy(t->hash_str, tar_hash);
	strcpy(t->uuid, tar_uuid);


	list_add_tail(&t->tar_list, g_tar_list);

	return 0;
}

//把文件 hash 路径 uuid 加入 list_head 链表中
int ht_scan_all_file_package(char *file_path, struct list_head *g_tar_list)
{
	char tar_hash[HASH_LENGTH * 2 + 1] = {0};
	char tar_uuid[UUID_LEN] = {0};

	int ret = ht_init_getfile_hash(file_path, tar_hash, tar_uuid);
	if(ret == -1){
		return 0;
	}

	whitelist_exec_node_t *t = (whitelist_exec_node_t *)agent_malloc(sizeof(whitelist_exec_node_t));

	char end_path[PATH_MAX_LEN] = {0};
	sprintf(end_path, "(compressed)%s", file_path);
	strcpy(t->file_path, end_path);
	strcpy(t->hash_str, tar_hash);
	strcpy(t->uuid, tar_uuid);
	list_add_tail(&t->tar_list, g_tar_list);

	return 0;
}

/*
   功能：
   传进一个tar包路径 把tar.gz包内 可加白的ko 写到list_head链表中 并出参返回
   参数：
tar_path:tar.gz包路径指针
list：链表头节点
返回值：
0：正常退出
-1：错误退出
 */
int ht_whitelist_uncompress(const char *tar_path, struct list_head *g_tar_list, int type){

	pthread_t tid = pthread_self();
	DIR	*dir = NULL;
	struct dirent *entry;
	int ret = HTTC_OK;
	char buffer[2048] = {0};
	int i = 0;

	//创建临时目录 带tid号
	char temp_cmd[1000];
	snprintf(temp_cmd, sizeof(temp_cmd), "%s/%lu", TMP_COMPRESS_DIR, (unsigned long)tid);

	char mkdir_cmd[1024] = {0};
	snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", temp_cmd);
	system(mkdir_cmd);
	

//遍历结构体数组 找到对应的type和方法
	if(type == 0){
		goto clean;
	}

	for (i = 0; i < (sizeof(decompression_func) / sizeof(decompression_func[0])); i++) {
   		if (decompression_func[i].type == type) {
			
			int decompression_ret = decompression_func[i].decomression((char *)tar_path, (char *)temp_cmd);
			
			if(decompression_ret != 0){
				//写入文件
				pthread_mutex_lock(&g_uncompress_log_lock);
                FILE *file = fopen("/usr/local/httcsec/ttm/var/log/pack.txt", "a+");
                if(file){
                	fprintf(file ,"\n%s", tar_path);
					fclose(file);
				}
				pthread_mutex_unlock(&g_uncompress_log_lock);
				goto clean;
			}

			break; 
		}
	}

	//打开临时文件夹
	dir = opendir(temp_cmd);
	//读取目录
	while ((entry=readdir(dir)) != NULL){
		if (entry->d_type == DT_DIR){
			if (is_skip_dirs(entry->d_name)) // 过滤指定目录
				continue;

			snprintf(buffer, sizeof(buffer), "%s/%s/", temp_cmd, entry->d_name); 
			ht_init_scan_dir(buffer, (scan_file_callback)ht_init_scan_file_package, g_tar_list);
		}
		else if (entry->d_type == DT_REG){
			if(is_skip_file_suffix(entry->d_name))  //过滤指定文件后缀名
				continue;

			snprintf(buffer, sizeof(buffer), "%s/%s", temp_cmd, entry->d_name);
			ht_init_scan_file_package(buffer, g_tar_list);//扫描文件 hash 路径 加到list_head
		}
	}

clean:
	if(dir)
		closedir(dir);
	//删除临时文件夹
	char rm_cmd[1024] = {0};
	snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s", temp_cmd);
	system(rm_cmd);

	return ret;
}

/*
   功能：
   传进一个tar包路径 把tar.gz包内 符合白名单的文件 写到list_head链表中 并出参返回
   参数：
tar_path:tar.gz包路径指针
list：链表头节点
返回值：
0：正常退出
-1：错误退出
 */
int ht_scan_uncompress_all(const char *tar_path, struct list_head *g_tar_list, int type){

	pthread_t tid = pthread_self();
	DIR	*dir = NULL;
	struct dirent *entry;
	int ret = HTTC_OK;
	//int type = 0;
	char buffer[2048] = {0};
	int i = 0;

	//创建临时目录 带tid号
	char temp_cmd[1000];
	snprintf(temp_cmd, sizeof(temp_cmd), "%s/%lu", TMP_COMPRESS_DIR, (unsigned long)tid);

	char mkdir_cmd[1024] = {0};
	snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", temp_cmd);
	system(mkdir_cmd);
	

	//遍历结构体数组 找到对应的type和方法
	if(type == 0){
		goto clean;
	}

	for (i = 0; i < (sizeof(decompression_func) / sizeof(decompression_func[0])); i++) {
   		if (decompression_func[i].type == type) {
			
			int decompression_ret = decompression_func[i].decomression((char *)tar_path, (char *)temp_cmd);
			
			if(decompression_ret != 0){
				//写入文件
				pthread_mutex_lock(&g_uncompress_log_lock);
                FILE *file = fopen("/usr/local/httcsec/ttm/var/log/pack.txt", "a+");
                if(file){
                	fprintf(file ,"\n%s", tar_path);
					fclose(file);
				}
				pthread_mutex_unlock(&g_uncompress_log_lock);
				goto clean;
			}

			break; 
		}
	}

	//打开临时文件夹
	dir = opendir(temp_cmd);
	//读取目录
	while ((entry=readdir(dir)) != NULL){
		if (entry->d_type == DT_DIR){
			if (is_skip_dirs(entry->d_name)) // 过滤指定目录
				continue;

			snprintf(buffer, sizeof(buffer), "%s/%s/", temp_cmd, entry->d_name); 
			ht_init_scan_dir(buffer, (scan_file_callback)ht_scan_all_file_package, g_tar_list);
		}
		else if (entry->d_type == DT_REG){
			if(is_skip_file_suffix(entry->d_name))  //过滤指定文件后缀名
				continue;

			snprintf(buffer, sizeof(buffer), "%s/%s", temp_cmd, entry->d_name);
			ht_scan_all_file_package(buffer, g_tar_list);//扫描文件 hash 路径 加到list_head
		}
	}

clean:
	if(dir)
		closedir(dir);
	//删除临时文件夹
	char rm_cmd[1024] = {0};
	snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s", temp_cmd);
	system(rm_cmd);

	return ret;
}
