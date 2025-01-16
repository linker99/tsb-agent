#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "httcutils/debug.h"

void httc_util_log_callback(int level, const char *message)
{
	printf("callback level %d\n loginfo %s\n", level, message);
}

#define NUM_THREADS 5

httc_util_log_config_t testconfig = {
	.callback = httc_util_log_callback,
	.filename = "testlog",
	.level = HTTC_UTIL_LOG_LEVEL_DEBUG,
	.max_size = 1,
	.output = TO_FILE,
	.subject = "test"};

void print_config(httc_util_log_config_t *c)
{
	printf("config info:=========================HEAD\n"
		   "\tcallback: %p\n"
		   "\tfilename: %s\n"
		   "\tlevel: %d\n"
		   "\tmax_size: %d\n"
		   "\toutput: %d\n"
		   "\tsubject: %s\n"
		   "config info:=========================TAIL\n",
		   c->callback, c->filename, c->level, c->max_size, c->output, c->subject);
}

void *print_error_message(void *thread_id)
{
	char *loginfo = "error thread\n";
	long tid;
	tid = (long)thread_id;
	while (1)
	{
		httc_util_pr_error("Thread %ld: %s \n", tid, loginfo);
		sleep(0.7);
	}
}
void *print_info_message(void *thread_id)
{
	char *loginfo = "info thread\n";
	long tid;
	tid = (long)thread_id;
	while (1)
	{
		httc_util_pr_info("Thread %ld: %s \n", tid, loginfo);
		sleep(0.5);
	}
}
void *print_debug_message(void *thread_id)
{
	char *loginfo = "debug thread\n";
	long tid;
	tid = (long)thread_id;
	while (1)
	{
		httc_util_pr_dev("Thread %ld: %s \n", tid, loginfo);
		sleep(0.6);
	}
}

int mt_test(void)
{
	pthread_t threads[NUM_THREADS];
	int rc;
	long t;


	httc_util_log_init();
	testconfig.output = TO_FILE;
	testconfig.level = HTTC_UTIL_LOG_LEVEL_DEBUG;
	httc_util_log_set(&testconfig);

	for (t = 0; t < NUM_THREADS; t++)
	{
		printf("Creating thread 0%ld\n", t);
		rc = pthread_create(&threads[t], NULL, print_error_message, (void *)t);
		if (rc)
		{
			printf("ERROR: return code from pthread_create is %d\n", rc);
			exit(-1);
		}

		printf("Creating thread 1%ld\n", t);
		rc = pthread_create(&threads[t], NULL, print_info_message, (void *)t);
		if (rc)
		{
			printf("ERROR: return code from pthread_create is %d\n", rc);
			exit(-1);
		}

		printf("Creating thread 2%ld\n", t);
		rc = pthread_create(&threads[t], NULL, print_debug_message, (void *)t);
		if (rc)
		{
			printf("ERROR: return code from pthread_create is %d\n", rc);
			exit(-1);
		}
	}
	printf("check testlog to see loginfo\n");
	printf("可按 ctrl-c 结束测试程序\n");
	sleep(10);
	return LOG_OK;
}

int set_test(void)
{
	httc_util_log_config_t configback = {};
	// file
	int set = httc_util_log_set(&testconfig);
	httc_util_log_get(&configback);
	print_config(&configback);
	printf("log set return %d\n", set);
	if (set)
	{
		printf("set error\n");
		return -1;
	}
	else
	{
		printf("check testlog file to see loginfo\n");
	}

	httc_util_pr_dev("debug debug\n");
	httc_util_pr_info("info info\n");
	httc_util_pr_error("error error\n");
	sleep(10);
	// callback
	testconfig.output = TO_CALLBACK;
	set = httc_util_log_set(&testconfig);
	httc_util_log_get(&configback);
	print_config(&configback);
	printf("log set return %d\n", set);
	if (set)
	{
		printf("set error\n");
		return -1;
	}
	else
	{
		printf("check callback to see loginfo\n");
	}

	httc_util_pr_dev("debug debug\n");
	httc_util_pr_info("info info\n");
	httc_util_pr_error("error error\n");


	// console
	testconfig.output = TO_CONSOLE;
	set = httc_util_log_set(&testconfig);
	httc_util_log_get(&configback);
	print_config(&configback);
	printf("log set return %d\n", set);
	if (set)
	{
		printf("set error\n");
		return -1;
	}
	else
	{
		printf("check console to see loginfo\n");
	}

	httc_util_pr_dev("debug debug\n");
	httc_util_pr_info("info info\n");
	httc_util_pr_error("error error\n");

	httc_util_log_reset();
	httc_util_log_close();
	httc_util_log_get(&configback);
	printf("after close\n");
	print_config(&configback);
	return 0;
}
void level_test(void)
{	
	printf("未配置 log,开始打印 log\n");
	httc_util_pr_dev("debug debug\n");
	httc_util_pr_info("info info\n");
	httc_util_pr_error("error error\n");
	printf("结束打印 log \n");
	printf("你不应该看到任何 log 信息输出\n");
	
	// console
	testconfig.output = TO_CONSOLE;
	testconfig.level = HTTC_UTIL_LOG_LEVEL_DEBUG;
	httc_util_log_set(&testconfig);

	printf("配置 level =HTTC_UTIL_LOG_LEVEL_DEBUG,开始打印 log\n");
	httc_util_pr_dev("debug debug\n");
	httc_util_pr_info("info info\n");
	httc_util_pr_error("error error\n");
	printf("结束打印 log \n");
	printf("你应该看到debug ,info,error 3 条 log 信息输出\n");

	// console
	testconfig.output = TO_CONSOLE;
	testconfig.level = HTTC_UTIL_LOG_LEVEL_INFO;
	httc_util_log_set(&testconfig);

	printf("配置 level =HTTC_UTIL_LOG_LEVEL_INFO,开始打印 log\n");
	httc_util_pr_dev("debug debug\n");
	httc_util_pr_info("info info\n");
	httc_util_pr_error("error error\n");
	printf("结束打印 log \n");
	printf("你应该看到 info,error 2 条 log 信息输出\n");

	testconfig.output = TO_CONSOLE;
	testconfig.level = HTTC_UTIL_LOG_LEVEL_ERROR;
	httc_util_log_set(&testconfig);
	
	printf("配置 level = HTTC_UTIL_LOG_LEVEL_ERROR,开始打印 log\n");
	httc_util_pr_dev("debug debug\n");
	httc_util_pr_info("info info\n");
	httc_util_pr_error("error error\n");
	printf("结束打印 log \n");
	printf("你应该看到 error 1 条 log 信息输出\n");

	testconfig.output = TO_CONSOLE;
	testconfig.level = HTTC_UTIL_LOG_LEVEL_NONE;
	httc_util_log_set(&testconfig);
	
	printf("配置 level = HTTC_UTIL_LOG_LEVEL_NONE,开始打印 log\n");
	httc_util_pr_dev("debug debug\n");
	httc_util_pr_info("info info\n");
	httc_util_pr_error("error error\n");
	printf("结束打印 log \n");
	printf("你应该看到 0 条 log 信息输出\n");

}

int main(int argc, char **argv)
{
	set_test();
	level_test();
	mt_test();
}
