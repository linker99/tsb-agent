#include "agt_log.h"
#include "agt_config.h"
#include "ht_def.h"
#include "ht_util.h"
#include <stdarg.h>
#include <syslog.h>
#include "tcsapi/tcs_constant.h"

#ifndef IN_DIRENT 
#define IN_DIRENT
	#include "dirent.h"
	#include<pthread.h>
	#include<sys/prctl.h>
#endif
int log_file_count = 0;	
#define BUFFER_SIZE 4096

extern agent_t *g_master;

pthread_mutex_t log_lock;
config_log_t *g_log_master = NULL;

int agent_log_init(agent_t *agent)
{
	if(!agent) return -1;

	if(!agent->foreground) {
		config_log_t *log = &agent->config.common.log;
		log->fp = fopen(log->path, "a+");
		if(!log->fp) {
			return -1;
		}

		log->size *= 1024 * 1024;
		g_log_master = log;
	}

	agt_config_print(agent);

	return 0;
}

/*ɾ������������ʱ�����ϵ��ļ�
  filepath:�ļ�����Ŀ¼
  file_name:�ļ������й����ַ���
  ����ֵ:0ɾ���ɹ���-1ɾ��ʧ��
*/
int remove_file_by_count_time(char* filepath, const char* file_name)
{
	struct dirent **namelist;
	int allfile_count = 0;
	allfile_count = scandir(filepath, &namelist, 0, alphasort);
	if(allfile_count > 0)
	{
		int file_index = 0;
		int remove_flag = 0;
		while(file_index < allfile_count)
		{
			if(strstr(namelist[file_index]->d_name, file_name) && remove_flag == 0)
			{
				int ret = 0;
				char remove_file[BUFFER_SIZE];
				snprintf(remove_file, sizeof(remove_file), "%s/%s", filepath, (const char *)namelist[file_index]->d_name);
				ret = remove(remove_file);
				if(ret == -1)
				{
					printf("remove error %s\n", strerror(errno));
					return ret;
				}
				remove_flag = 1;
			}
			free(namelist[file_index]);
			file_index++;
		}
		free(namelist);
	}
	return 0;
}

/*�����ļ����ݵ����ļ������ļ��������
  fp:FILE *fp
  newfile:���ļ�����
  ����ֵ:0ɾ���ɹ���-1ɾ��ʧ��
*/
int copy_stream_to_new_file(FILE *fp, const char* newfile)
{
	char buffer[BUFFER_SIZE];
	FILE *fout;
	int rszie = 0;
	int fd = 0;
	if((fout=fopen(newfile, "a+")) == NULL) 
	{
		return -1;
	}
	// ��fp�ļ�ָ���ƶ������ֽ�  
	rewind(fp);
	while( (rszie = fread (buffer,1,BUFFER_SIZE,fp)) > 0)
	{
		if(fwrite(buffer, 1, rszie, fout) != rszie)
		{
			break;
		}
	}
	fclose(fout);
	fd = fileno(fp);
	ftruncate(fd,0);
	return 0;
} 

void agent_log_real(int level, const char *filename, int line, const char *format, ...)
{
	char _time[TIME_STR] = {0};
	ht_getformat_time(_time);
	struct stat st;
	char buffer[256] = {0};

	FILE *fp = stderr;
	if(g_log_master) {
		fp = g_log_master->fp;
		if(stat(g_log_master->path, &st)<0)
			return;
		if(st.st_size > g_log_master->size )
		{
			pthread_mutex_lock(&log_lock);
			if(stat(g_log_master->path, &st)<0)
			{
				pthread_mutex_unlock(&log_lock);
				return;
			}
			if(st.st_size > g_log_master->size )
			{
	    		char logfile_bak[1024] = {0}; 
				char strtime[TIME_STR] = {0};
				memcpy(strtime, _time, TIME_STR);
			    for(int i = 0; i < strlen(strtime); i++)
			    {
			        if(strtime[i] == ' ' || strtime[i] == ':')
			        {
			            strtime[i] = '-';
			        }
			    }
				sprintf(logfile_bak, "%s.bak_%s",g_log_master->path, strtime);

				//�����ļ����ݵ�fout
				int ret = 0;
				ret = copy_stream_to_new_file(fp, logfile_bak);
				if(ret == -1)
				{
					printf("copy error\n");
				}
				pthread_mutex_unlock(&log_lock);
				log_file_count++;
				
				//������־�ļ�����
				if(log_file_count > LOG_FILE_MAX_COUNT)
				{
					ret = remove_file_by_count_time("/usr/local/httcsec/ttm/var/log/", "ht_agent.log.bak_");
					if(ret == -1){
						printf("remove error\n");
					}
					else
					{
						log_file_count--;
					}
				}
			}
			else
			{
				pthread_mutex_unlock(&log_lock);
			}
		}
	}

	if (level < g_master->config.common.log.level) {
		return;
	}

	switch(level) {
		case HTTC_ABORT:
			sprintf(buffer, "\033[31m[ABORT] %s %s %04d: ", _time, filename, line);
			exit(-1);
			break;
		case HTTC_ERROR:
			sprintf(buffer, "\033[31m[ERROR] %s %s %04d: ", _time, filename, line);
			break;
		case HTTC_WARN:
			sprintf(buffer, "\033[33m[WARN] %s %s %04d: ", _time, filename, line);
			break;
		case HTTC_INFO:
			sprintf(buffer, "\033[36;1m[INFO] %s %s %04d: ", _time, filename, line);
			break;
		case HTTC_DEBUG:
			sprintf(buffer, "\033[35;1m[DEBUG] %s %s %04d: ", _time, filename, line);
			break;
		default:
			break;
	}

	va_list  argptr;
	pthread_mutex_lock(&log_lock);
	va_start(argptr, format);

	fprintf(fp, "%s", buffer);
	vfprintf(fp, format, argptr);
	fprintf(fp, "\033[0m\n");

	va_end(argptr);

	fflush(fp);
	pthread_mutex_unlock(&log_lock);
}

int agent_log_destroy(int foreground, config_log_t *log)
{
	if(!log) return -1;

	if(!foreground) {
		if(log->fp) {
			fclose(log->fp);
			log->fp = NULL;
		}

		g_log_master = NULL;
	}

	return 0;
}

