#include "tools_log.h"

#define TIME_STR	21

pthread_mutex_t log_lock;
config_log_t *g_log_master = NULL;
config_log_t g_log;

int tools_log_init()
{
	sprintf(g_log.path, "%s", HTTC_NORM_LOGPATH);
	g_log.fp = fopen(g_log.path, "a+");
	if(!g_log.fp) {
		return -1;
	}

	g_log.level = HTTC_LOG_LEVEL;
	g_log.size = 256 * 1024 * 1024; //256M
	g_log_master = &g_log;

	return 0;
}

void tools_log_real(int level, const char *filename, int line, const char *format, ...)
{
	char _time[TIME_STR] = {0};
	ht_getformat_time(_time);
	
	struct stat st;
	char buffer[256] = {0};

	FILE *fp = stderr;
	if(g_log_master) {
		if(stat(g_log_master->path, &st)<0)
		{
			printf("g_log_master->path: %s\n", g_log_master->path);
			return;
		}

		if(st.st_size > g_log_master->size) {
			printf("st.st_size %ld\n", st.st_size);
			return;
		}

		fp = g_log_master->fp;
	}

	if (level < g_log_master->level) {
		printf("g_log_master->level = %d\n", g_log_master->level);
		return;
	}


	switch(level) {
		case HTTC_ABORT:
			sprintf(buffer, "\033[31m[ABORT] %s %s %04d: ", _time, filename, line);
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

int tools_log_destroy()
{
	if(!g_log_master) return -1;

	if(g_log_master->fp) {
		fclose(g_log_master->fp);
		g_log_master->fp = NULL;
	}

	g_log_master = NULL;

	return 0;
}

