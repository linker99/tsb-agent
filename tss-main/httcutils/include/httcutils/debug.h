#ifndef DEBUG_H_
#define DEBUG_H_
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pthread.h>

#define MAX_SUBJECT 32
#define MAX_FILENAME 4095
#define MAX_LOG_SIZE 256
#define MIN_LOG_SIZE 1
#define MAX_LOG_ENTRY_SIZE 1024

#define DEFAULT_LOG_FILE "/var/log/tss.log"
#define DEFAULT_DEBUG_LOG_FILE "/var/log/tss-debug.log"
#define DEFAULT_LOG_SUBJECT "tss"

enum LogLevel
{
	HTTC_UTIL_LOG_LEVEL_NONE = -1,
	HTTC_UTIL_LOG_LEVEL_ERROR = 0,
	HTTC_UTIL_LOG_LEVEL_INFO,
	HTTC_UTIL_LOG_LEVEL_DEBUG,
	HTTC_UTIL_LOG_LEVEL_MAX

};

enum OutPut
{
	TO_FILE,
	TO_CONSOLE,
	TO_CALLBACK
};

enum LogErrNum{
	LOG_OK,
	LOG_CONFIG_NULL,
	LOG_CONFIG_OUTPUT_INVALID,
	LOG_CONFIG_LEVEL_INVALID,
	LOG_CONFIG_SUBJECT_NULL,
	LOG_CONFIG_SUBJECT_TOO_LONG,
	LOG_CONFIG_FILENAME_NULL,
	LOG_CONFIG_FILENAME_TOO_LONG,
	LOG_CONFIG_MAX_SIZE_INVALID,
	LOG_CONFIG_CALLBACK_NULL,
	LOG_LOG_FILE_OPEN_FAILED,
	LOG_CONFIG_CALLOC_ERR,
	LOG_CONFIG_UNSET
};

extern char *g_cb_buff;
extern pthread_mutex_t g_log_mutex;
extern char *log_label[HTTC_UTIL_LOG_LEVEL_MAX];

typedef void(httc_util_log_callback_t)(int level, const char *message);
typedef struct httc_util_log_config
{
	char subject[MAX_SUBJECT];			// 日志主体（ttm,tsb等）
	char filename[MAX_FILENAME];		// 日志文件名
	httc_util_log_callback_t *callback; // 日志数据输出回调函数
	int max_size;						// 日志文件最大大小（单           位：M）
	enum OutPut output;			// 输出标志，0 filename 1 控制台 2 回调 3 关闭
	enum LogLevel level;		// 日志等级
} httc_util_log_config_t;

extern httc_util_log_config_t *gp_config;

extern FILE *gp_log_file;

void httc_util_log_init(void);
int httc_util_log_set(const struct httc_util_log_config *config);
int httc_util_log_get(struct httc_util_log_config *config);
int httc_util_log_close(void);
int httc_util_log_reset(void);

static inline void util_log_update(void)
{
    int log_filename_len = strlen(gp_config->filename);
    if (log_filename_len)
    {
        // 获取log 大小，如果超过 maxsize，将当前文件重命名，更新 gp_log_file
        if (ftell(gp_log_file) > gp_config->max_size * 1024 * 1024)
        {
            //关闭 gp_log_file
            if (gp_log_file)
            {
                fclose(gp_log_file);
                gp_log_file = NULL;
            }
            // 构造新名字
            char *tmp = calloc(log_filename_len + 5, 1);
            if (!tmp)
            {
                fprintf(stderr, "calloc error");
            }
            strncpy(tmp, gp_config->filename,log_filename_len);
            strcat(tmp, ".old");
            rename(gp_config->filename, tmp);

            free(tmp);
            tmp = NULL;
            //更新 gp_log_file
            gp_log_file = fopen(gp_config->filename, "a+");
        }
    }
}

#define httc_util_pr_out(func,outio, level, fmt, arg...)                   \
	{struct timespec ts;   \
    clock_gettime(CLOCK_REALTIME, &ts);   \
    struct tm *tm_info;   \
    char timestr[80];   \
    tm_info = localtime(&ts.tv_sec);   \
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", tm_info);\
	if(!strcmp(func,"snprintf"))                                              \
	{\
		snprintf((char*)outio, MAX_LOG_ENTRY_SIZE, "[%s:%s]%s:%s:%s:%d:" fmt, gp_config->subject, timestr, level, __FILE__, __func__, __LINE__, ##arg);}\
	else{\
		fprintf((FILE *)outio, "[%s:%s]%s:%s:%s:%d:" fmt, gp_config->subject, timestr, level, __FILE__, __func__, __LINE__, ##arg);	\
	}\
	}\


#define httc_util_print(printlevel,fmt,arg...)                             \
	do{                                                                    \
	if (gp_config && gp_config->level >= printlevel)                       \
	{                                                                      \
		pthread_mutex_lock(&g_log_mutex);                                  \
		switch (gp_config->output)                                         \
		{                                                                  \
		case TO_FILE:                                                      \
			if (gp_log_file)                                               \
			{                                                              \
				util_log_update();                                         \
			}                                                              \
			else                                                           \
			{                                                              \
				gp_log_file = fopen(gp_config->filename, "a+");            \
			}                                                              \
			if(gp_log_file)                                                \
			{httc_util_pr_out("fprintf", gp_log_file, log_label[printlevel], fmt, ##arg);                                         \
				fflush(gp_log_file); }                                     \
			else{                                                          \
				printf("open log file %s failed\n",gp_config->filename);   \
			}                                                              \
			break;                                                         \
		case TO_CONSOLE:;                                                  \
			httc_util_pr_out("fprintf",stderr, log_label[printlevel], fmt, ##arg);\
			fflush(stderr);                                                \
			break;                                                         \
		case TO_CALLBACK:                                                  \
			if (gp_config->callback)                                       \
			{                                                              \
				if(!g_cb_buff){ g_cb_buff = malloc(MAX_LOG_ENTRY_SIZE);}   \
				if(!g_cb_buff){ gp_config->callback(printlevel,"malloc err\n");break;}                                                    \
				httc_util_pr_out("snprintf", g_cb_buff, log_label[printlevel], fmt, ##arg);                                               \
				gp_config->callback(printlevel, g_cb_buff);                \
			}else{ printf("callbak func not set\n");}                      \
			break;                                                         \
		default:                                                           \
			break;                                                         \
		}                                                                  \
		pthread_mutex_unlock(&g_log_mutex);                                \
	}}while(0);

#define httc_util_pr_dev(fmt, arg...) \
	httc_util_print(HTTC_UTIL_LOG_LEVEL_DEBUG, fmt, ##arg);

#define httc_util_pr_error(fmt, arg...)                                    \
	httc_util_print(HTTC_UTIL_LOG_LEVEL_ERROR, fmt, ##arg);

#define httc_util_pr_info(fmt, arg...)                                     \
	httc_util_print(HTTC_UTIL_LOG_LEVEL_INFO, fmt, ##arg);

void httc_util_dump_hex(const char *name, void *p, int bytes);

#endif /* DEBUG_H_ */
