#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>

#include "public.h"
#include "scan_path.h"

#define BUF_LEN 1024

int ht_copy_file(char *srcfile, char *desfile)
{
    int frd, fwd; //读写文件描述符
    struct stat src_st;
    char buf[BUF_LEN];
    int rv1, count=0;

    frd = open(srcfile,O_RDONLY);
    if (frd == -1) {
        printf("open srcfile %s err.", srcfile);
        tools_log(HTTC_ERROR, "open srcfile %s fail!", srcfile);
        goto cleanup;
    }

    //获取源文件权限
    if (fstat(frd,&src_st) == -1) {
        printf("fstat file %s err.", srcfile);
        tools_log(HTTC_ERROR, "fstat file %s fail!", srcfile);
        goto cleanup;
    }

    /* 打开目标文件， 使权限与源文件相同*/
    fwd = open(desfile,O_WRONLY | O_CREAT | O_TRUNC,src_st.st_mode);
    if (fwd == -1) {
        printf("open desfile %s err.", desfile);
        tools_log(HTTC_ERROR, "open desfile %s fail!", desfile);
        goto cleanup;
    }

    //从源文件中读数据到buf，再将buf的数据写到目标文件中
	while ((rv1 = read(frd, buf, sizeof(buf))) != 0)
	{
		if ((write(fwd, buf, rv1)) < 0)
		{
			printf("Count[%d] Write failure\n", count);
		}
		count++;
	}
cleanup:
	if (frd > 0)
		close(frd);
	if (fwd > 0)
		close(fwd);

    return 0;
}

int ht_mkdir(char *file_dir)
{
    int ret = 0;
    ret = mkdir(file_dir, 0755);
    if(ret != 0){
        printf("mkdir %s error\n", file_dir);
        tools_log(HTTC_ERROR, "mkdir %s fail!", file_dir);
    }

    return ret;
}

int ht_rm_file(char *file)
{
    int ret = 0;

    ret = unlink(file);
    if(ret != 0){
        printf("unlink %s error\n", file);
        tools_log(HTTC_ERROR, "unlink %s fail!", file);
    }
    return ret;
}

int ht_rmdir(char *file_dir)
{
    DIR *dir;
	const struct dirent *entry;
	char file_path[PATH_MAX_LEN] = {0};

    if ((dir=opendir(file_dir)) == NULL) {
		printf("open path %s error\n", file_dir);
        tools_log(HTTC_ERROR, "open path %s fail!", file_dir);
		return -1;
	}
    
    while ((entry=readdir(dir)) != NULL ) {
		if (strcmp(".", entry->d_name) == 0 || strcmp("..", entry->d_name) == 0)
			continue;

		memset(file_path, 0, PATH_MAX_LEN);

		if (entry->d_type == DT_DIR) {
			snprintf(file_path, sizeof(file_path), "%s%s/", file_dir, entry->d_name);
            
			ht_rmdir(file_path);
		}
		else if (entry->d_type == DT_REG) {
            snprintf(file_path, sizeof(file_path), "%s%s", file_dir, entry->d_name);
			ht_rm_file(file_path);
		}
	}
	
	closedir(dir);
    rmdir(file_dir);

    return 0;
}

int ht_copy_dir(char *srcpath, const char *dstpath)
{
    DIR *dir;
	const struct dirent *entry;
	char file_path[PATH_MAX_LEN] = {0};
    char dst_file_path[PATH_MAX_LEN] = {0};
    int  ret = 0;


    if ((dir=opendir(srcpath)) == NULL) {
		printf("open path %s error\n", srcpath);
        tools_log(HTTC_ERROR, "open path %s fail!", srcpath);
		return -1;
	}
    
    while ((entry=readdir(dir)) != NULL ) {
		if (strcmp(".", entry->d_name) == 0 || strcmp("..", entry->d_name) == 0)
			continue;

		memset(file_path, 0, PATH_MAX_LEN);
        memset(dst_file_path, 0, PATH_MAX_LEN);
		
		if (entry->d_type == DT_DIR) {
			snprintf(file_path, sizeof(file_path), "%s%s/", srcpath, entry->d_name);
            snprintf(dst_file_path, sizeof(dst_file_path), "%s%s/", dstpath, entry->d_name);
            if(0 != access(dst_file_path, F_OK))
            {
                ret = ht_mkdir(dst_file_path);
                if(ret != 0)
                {
                    printf("ht_mkdir %s error\n", dst_file_path);
                    tools_log(HTTC_ERROR, "ht_mkdir %s fail!", dst_file_path);
                }
            }
			ht_copy_dir(file_path, dst_file_path);
		}
		else if (entry->d_type == DT_REG) {
            snprintf(file_path, sizeof(file_path), "%s%s", srcpath, entry->d_name);
            snprintf(dst_file_path, sizeof(dst_file_path), "%s%s", dstpath, entry->d_name);
			ht_copy_file(file_path, dst_file_path);
		}
	}
	
	closedir(dir);

    return 0;
}