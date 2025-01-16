#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <httcutils/sys.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/time.h>

#define  TYPE_FILE 1
#define  TYPE_DIR 2

int httc_util_system (const char *cmdstring)
{
	int status;
	if(cmdstring == NULL)	return -1;
	pid_t pid = fork();
	if(pid < 0){	
		return -1;
	}else if(pid == 0){
		prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
		execl("/bin/sh", "sh", "-c", cmdstring, (char *)0);
		return 127;
	}else{
		waitpid(pid, &status, 0);
		return status;
	}
}

void httc_util_time_print (const char *format, uint64_t time)
{
	char uatime[128] = {0};
	struct tm *p = localtime ((time_t*)&time);
	if (p)
		snprintf (uatime, sizeof (uatime), "%04d-%02d-%02d %02d:%02d:%02d",
			(1900 + p->tm_year), ( 1 + p->tm_mon), p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec);
	printf (format, uatime);
	return ;
}

void httc_util_rand_bytes (unsigned char *buffer, int size)
{
	int i;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	srand(tv.tv_usec);
    for(i = 0; i < size; i++)
    	buffer[i] = (unsigned char)(rand() & 0xff);
}

//remove 函数
static int check_file(const char *path)
{
	struct stat stats;
	if (lstat(path, &stats) != 0)
	        return -1;
	if (S_ISREG(stats.st_mode))
	        return TYPE_FILE;
	if (S_ISDIR(stats.st_mode))
	        return TYPE_DIR;
	return 0;
}

static int remove_file(const char *filename)
{
	int ret = 0;
	ret = remove(filename);
	if(ret == -1){
		printf("remove error : %s\n", strerror(errno));
	   	return -1;
   	}
	return ret;
}

static int remove_dir(const char *dirname)
{
	int ret = 0;
	DIR *dir = NULL;
	struct dirent *wlDirent = NULL;
	char filename[1024] = {0};
	char subdirfile[1024] = {0};

	if (NULL == (dir = opendir (dirname))) return -1;
	while(1)
	{
	    if (NULL == (wlDirent = readdir(dir))) break;
	    if (strncmp(wlDirent->d_name,".",1)==0) continue;
	    if (wlDirent->d_type == 8){
			sprintf(filename,"%s/%s",  dirname, wlDirent->d_name);
			ret = remove_file(filename);
			if(ret != 0){
				closedir (dir);
				return ret;
			}
			continue;
	    }else if (wlDirent->d_type == 4){
			sprintf(subdirfile, "%s/%s", dirname, wlDirent->d_name);
			ret = remove_dir(subdirfile);
			if(ret != 0){
				closedir (dir);
				return ret;
			}
			ret = remove_file(subdirfile);
			if(ret != 0){
				closedir (dir);
				return ret;
			}
	    }
	}
	closedir (dir);
	return ret;	
}

int httc_util_rm_exec(char *args, ...)  
{ 
	int ret;
	va_list argp;
	char *para = args;
	char * path = NULL;
	
	va_start(argp, args);
	do{
		//printf("Parameter is: %s\n", para);
		if(para == NULL){
			printf("param is null\n");
			va_end(argp);
		   	return -1;
		}

		if (strstr ((const char *)para, "*")){
			path = strndup ((const char *)para, strlen ((const char *)para) - 1);
		}else{
			path = strdup ((const char *)para);
		}
		if (access((const char *)path, 0) != 0){
			if (path) {free (path); path = NULL;}
			continue;
		}
		ret = check_file(path);
		if(ret == TYPE_FILE){
			ret = remove_file(path);
			if(ret != 0){
				if (path) {free (path); path = NULL;}
				va_end(argp);
				return ret;
			}
		}else if(ret == TYPE_DIR){
			ret = remove_dir(path);
			if(ret != 0){
				if (path) {free (path); path = NULL;}
				va_end(argp);
				return ret;
			}
			if (!strstr ((const char *)para, "*")){
				ret = remove_file(path);
				if(ret != 0){
					if (path) {free (path); path = NULL;}
					va_end(argp);
					return ret;
				}
			}
		}else{
			if (path) {free (path); path = NULL;}
			va_end(argp);
			return -1;
		}
	}while((para = va_arg(argp, char*)) != NULL);
	va_end(argp);

	if (path) {free (path); path = NULL;}
	return 0;
}

int httc_util_chmod_exec(mode_t mode, char *args, ...)  
{ 
	int ret = 0;
	va_list argp;
	char *para = args;

	va_start(argp, args);
	do{
		//printf("Parameter is: %s\n", para);
		if(para == NULL){
			printf("param is null\n");
			va_end(argp);
		   	return -1;
	    }
		ret = check_file(para);
		//printf("ret = %d\n", ret);
		if(ret == 1)
		{
			ret = chmod(para, mode);
			if((ret == -1)&&(errno != 2)){
				printf("chmod error : %s\n", strerror(errno));
				va_end(argp);
				return -1;
			}
		}else if(ret == 2){
			printf("%s IS DIR\n", para);
		}
		else{
			printf("%s NO EXIST\n", para);
		}
	}while((para = va_arg(argp, char*)) != NULL);
	va_end(argp);

	return 0;
}


//mkdir 函数
int httc_util_mkdir_exec(mode_t mode, char *args, ...)  
{ 
   int ret = 0;
   va_list argp;
   char *para = args;

	va_start(argp, args);
	do{
		//printf("Parameter is: %s\n", para);
		if(para == NULL){
			printf("param is null\n");
			va_end(argp);
		   	return -1;
	    }
		ret = access(para , F_OK);
		if(ret != 0){
			ret = mkdir(para, mode);
			if((ret == -1)&&(errno != 2)){
				printf("mkdir error : %s, %s\n", strerror(errno), para);
				
				return -1;
			}
		}
	}while((para = va_arg(argp, char*)) != NULL);
	va_end(argp);

	return 0;
}

