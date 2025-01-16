#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include "sm3.h"
//#include "sqlite.h"
#include "util.h"

char szPath[256] = {0};
static char *escape_dirs[] = {"proc", "lost+found", "sys", "dev", NULL};

static char *escape_extension[] = {".txt", ".png", ".js", ".css", ".sta",
	".lni", "dis", ".cad", ".o", ".a", ".log",
	".xml", ".lock", ".mo", ".idx",
	".local", ".deny", ".LOCK", ".cache",
	".h", ".c", ".tar", ".gz", ".html",
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
	".XML", ".iso", ".zip", ".json", ".avi", ".swf", ".mp4",
	"JPG", NULL};

FILE* fp = NULL;

int check_isexec(char* file_path)
{
	//过滤指定文件
	int i;
	for (i=0; escape_extension[i]; i++)
	{
		if (strlen(file_path)<strlen(escape_extension[i]))
			continue;

		char *p = file_path;
		p = p+strlen(file_path)-strlen(escape_extension[i]);
		if (strcmp(p, escape_extension[i])==0)
		{
			//pLog(DEBUG, "%s is not whitelist file, skip", file_path);
			return 0;
		}
	}

	//具有可执行权限的文件
	if(access(file_path, X_OK)==0)
		return 1;

	//有些系统文件大小为空，fread时会阻塞，应该过滤掉
	struct stat statbuf;
	stat(file_path, &statbuf);
	if (statbuf.st_size == 0)
	{
		printf("%s size is 0, skip\n", file_path);
		return -1;
	}

	char buf[4] = {0};
	FILE *fp = fopen(file_path, "rb");
	if (!fp)
	{
		return -1;
	}
	fread(buf, 1, sizeof(buf), fp);
	fclose(fp);

	//二进制程序
	if(strncmp(buf, "\177ELF", 4) == 0)
	{
		//pLog(DEBUG, "%s is exe", file_path);
		return 1;
	}

	//shell脚本
	if(strncmp(buf, "#!", 2) == 0)
	{
		//pLog(DEBUG, "%s is shell", file_path);
		return 1;
	}

	return 0;
}

int scan_file(char* file_name)
{
	char hash[128] = {0};
	char sql[1024] = {0};
	char buf[1024] = {0};
	
	if (check_isexec(file_name) <= 0)
		return -1;

	if (sm3_file(file_name, hash) != 0)
		return -1;
	//printf("%s hash is [%s]\n", file_name, hash);
	//sprintf(sql, "insert into whitelist values(\"\", \"%s\", \"%s\")", file_name, hash);
	//dbExec(sql);
	sprintf(buf, "%s %s\n", file_name, hash);
	fputs(buf, fp);

	return 0;
}

int scan_dir(char *dir)
{
	DIR		*dp;
	struct	dirent	*entry;
	struct	stat	statbuf;
	
	if ((dp = opendir(dir)) == NULL) 
	{
		fprintf(stderr, "cannot open directory: %s\n", dir);
		return -1;
	}

	//过滤指定目录
	int i;
	for (i=0; escape_dirs[i]; i++)
	{
		if (strlen(dir)<strlen(escape_dirs[i]))
			continue;

		char *p = dir;
		p = p+strlen(dir)-strlen(escape_dirs[i]);
		if (strcmp(p, escape_dirs[i])==0)
		{
			printf("%s is not whitelist dir\n", dir);
			return 0;
		}
	}

	chdir(dir);				//system call
	while ((entry = readdir(dp)) != NULL ) 
	{
		char file_name[256]={0};
		lstat(entry->d_name, &statbuf);
		if (S_ISDIR(statbuf.st_mode)) 
		{
			if (strcmp(".", entry->d_name)==0 || strcmp("..", entry->d_name)==0) 
					continue;

			//printf("d_name: %s/\n", entry->d_name);

			snprintf(file_name, sizeof(file_name), "%s/%s", dir, entry->d_name);
			scan_dir(file_name);
		}
		else
		{
			snprintf(file_name, sizeof(file_name), "%s/%s", dir, entry->d_name);
			//printf("file_name: %s\n", file_name);
			scan_file(file_name);
		}

	}
	chdir("..");
	closedir(dp);

	return 0;
}

int scan_whitelist(char* path)
{
	int ret = 0;
	struct stat statbuf;
	stat(path, &statbuf);

	if(S_ISDIR(statbuf.st_mode))
	{	
		printf("dir path[%s]\n", path);
		ret = scan_dir(path);
	}
	else if(S_ISREG(statbuf.st_mode))
	{
		printf("file path[%s]\n", path);
		scan_file(path);
	}
	else
	{	
		printf("error path[%s]\n", path);
		ret = -1;
	}

	return ret;
}

int main(int argc, char* argv[])
{
	//取扫描路径，如不指定路径，从根目录开始扫描
	char scan_path[256] = {0};
	if((argc>1) && (0==strcmp("-p", argv[1])))
	{
		strncpy(scan_path, argv[2], 255);
	}
	else
	{
		strcpy(scan_path, "/");
	}

	//得到程序全路径
	GetLinuxModuleFileName(szPath, 256);
	printf("%s\n", szPath);
	char *p = strrchr (szPath, '/');
	*(p+1) = '\0';
	printf("szPath: %s\n", szPath);

	////清空白名单表
	//char sql[1024] = {0};
	//sprintf(sql, "delete from whitelist");
	//dbExec(sql);

	fp = fopen("whitelist_str", "w");

	//开始扫描
	scan_whitelist(scan_path);
	printf("done.\n");

	fclose(fp);

	exit(0);
}
