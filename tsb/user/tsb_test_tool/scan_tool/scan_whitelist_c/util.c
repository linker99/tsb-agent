#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <wait.h>
#include <string.h>
#include "util.h"

void daemonize()
{
	int pid;

	if ((pid=fork()) < 0) {
		printf("fork failed\n");
		exit(1);
	}

	if (pid > 0) {
		exit(0);
	}

	setsid();
	chdir("/");
	umask(0);

	if ((pid=fork()) < 0) {
		printf("fork [2] failed\n");
		exit(1);
	}

	if (pid > 0) {
		exit(0);
	}
}

int	KeepAlive()
{
	int	pid,status;

	//for(int i=0;i<20;i++)	signal(i,SIG_IGN);

	pid=fork();
	if (pid<0)
	{
		printf("KeepAlive : can not fork new process,errno=%d\n",errno);
		return -1;
	}
	if (pid==0)	return 0;

	while(1)
	{
		pid_t pchild;
		pchild=wait(&status);
		if(WIFEXITED(status))
		{
			printf("The child process[%d] exit normally. The WEXITSTATUS return code is:%d ", pchild, WEXITSTATUS(status));
			//exit(EXIT_SUCCESS);
		}
		else
		{
			printf( "The child process[%d] exit abnormally. Status is:%d", pchild, status);
		}

		sleep(1);

		pid=fork();
		if (pid<0)
		{
			printf("KeepAlive: can not fork new process,errno=%d\n",errno);
			return -1;
		}
		if (pid==0)	return	0;
	}
}

int getPidByName(char* task_name)
{
	DIR *dir;
	struct dirent *ptr;
	FILE *fp;
	char filepath[50];
	char cur_task_name[50];
	char buf[1024];
	int pid = -1;

	dir = opendir("/proc"); //打开路径
	if (NULL != dir)
	{
		while ((ptr = readdir(dir)) != NULL) //循环读取路径下的每一个文件/文件夹
		{
			//如果读取到的是"."或者".."则跳过，读取到的不是文件夹名字也跳过
			if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0))
				continue;
			if (DT_DIR != ptr->d_type)
				continue;

			sprintf(filepath, "/proc/%s/status", ptr->d_name);//生成要读取的文件的路径
			fp = fopen(filepath, "r");//打开文件
			if (NULL != fp)
			{
				if( fgets(buf, 1024-1, fp)== NULL )
				{
					fclose(fp);
					continue;
				}
				sscanf(buf, "%*s %s", cur_task_name);

				//如果文件内容满足要求则打印路径的名字（即进程的PID）
				if (!strcmp(task_name, cur_task_name))
				{
					//printf("PID:  %s\n", ptr->d_name);
					pid = atoi(ptr->d_name);
				}
				fclose(fp);
			}
		}
		closedir(dir);//关闭路径
	}

	return pid;
}

int RunCmdGetResult(char* cmd, char* buf, int len)
{
	if(!cmd)
		return -1;

	FILE *fp = popen(cmd,"r");
	fread(buf,len,1,fp);
	pclose(fp);

	return 0;
}

//过滤换行符
int filterLF(char* buf)
{
	if(!buf)
		return -1;

	char *tmp = NULL;
	if ((tmp = strstr(buf, "\n")))
	{
		*tmp = '\0';
	}

	return 0;
}

int GetLinuxModuleFileName(char* szFileName, int iLen)
{
	char sLine[1024] = { 0 };
	void* pSymbol = (void*)"";

	FILE *fp = fopen ("/proc/self/maps", "r");
	if ( fp == NULL )
		return -1;

	while (!feof (fp))
	{
		unsigned long start, end;

		if ( !fgets (sLine, sizeof (sLine), fp))
			continue;

		if ( !strstr (sLine, " r-xp ") || !strchr (sLine, '/'))
			continue;

		sscanf (sLine, "%lx-%lx ", &start, &end);
		if (pSymbol >= (void *)start && pSymbol < (void *)end)
		{
			// Extract the filename; it is always an absolute path 
			char *pPath = strchr (sLine, '/');

			// Get rid of the newline 
			char *tmp = strrchr (pPath, '\n');
			if (tmp)
				*tmp = 0;

			/* Get rid of "(deleted)" */
			//size_t len = strlen (pPath);
			//if (len > 10 && strcmp (pPath + len - 10, " (deleted)") == 0)
			//{
			//    tmp = pPath + len - 10;
			//    *tmp = 0;
			//}

			strncpy(szFileName, pPath, iLen-1);
		}
	}

	fclose (fp);
	return 0;
}