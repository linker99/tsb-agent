#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include <httcutils/convert.h>
#include <httcutils/debug.h>
#include <httcutils/sys.h>
#include "tcsapi/tcs_error.h"
#include "tcfapi/tcf_log_notice.h"

#define DELETE_NUM  -1

static void usage ()
{
	printf ("\n"
			" Usage: ./log_read_block -r <> -d<>  \n"
			"    eg. ./log_read_block -r 10\n"
			"        ./log_read_block -r 10 -d 2 \n");
}

void log_dump (struct log **logs, int num)
{
	int i = 0;
	struct log *log = NULL;

	for (i = 0; i < num; i++){
		log = logs[i];
		if (!log)	return ;
		printf ("\n");
		printf ("log index: %d\n", i);
		printf ("  [%d].type: %d\n", i, log->type);
		printf ("  [%d].operate: %d\n", i, log->operate);
		printf ("  [%d].result: %d\n", i, log->result);
		printf ("  [%d].userid: %d\n", i, log->userid);
		printf ("  [%d].pid: %d\n", i, log->pid);
		printf ("  [%d].repeat_num: %d\n", i, log->repeat_num);
		printf ("  [%d].", i); httc_util_time_print ("time: %s\n", log->time);
		printf ("  [%d].total_len: %d\n", i, log->total_len);
		printf ("  [%d].len_subject: %d\n", i, log->len_subject);
		printf ("  [%d].len_object: %d\n", i, log->len_object);
		printf ("  [%d].", i); httc_util_dump_hex ("sub_hash", log->sub_hash, DEFAULT_HASH_SIZE);
		printf ("  [%d].subject: %s\n", i, log->data);
		printf ("  [%d].object: %s\n", i, log->data + log->len_subject);
	}
	printf ("\n");
}


int read_logs_noblock (int read_num, int delete_num)
{
	int ret = 0;
	int index = 0;
	struct log **logs = NULL;
	
	if (0 != (ret = tcf_read_logs_noblock (&logs, &read_num))){
		httc_util_pr_error ("tcf_read_logs error: %d(0x%x)\n", ret, ret);
		return ret;
	}
	log_dump (logs, read_num);
	
	if(delete_num  > read_num){
		delete_num = read_num;
	}
	if(delete_num == DELETE_NUM)
		index = read_num - 1;
	else if(delete_num == 0){
		if (0 != (ret = tcf_free_logs (read_num, logs)))
			httc_util_pr_error ("tcf_free_logs error: %d(0x%x)\n", ret, ret);
		return ret;
	}
	else{
		index = delete_num - 1;
	}
	
	if (read_num){
		if (0 != (ret = tcf_remove_logs (logs[index]))){
			httc_util_pr_error ("tcf_remove_logs error: %d(0x%x)\n", ret, ret);
			//return ret;
		}
		if (0 != (ret = tcf_free_logs (read_num, logs))){
			httc_util_pr_error ("tcf_free_logs error: %d(0x%x)\n", ret, ret);
			return ret;
		}
	}


	return ret;
}

int main (int argc, char *argv[])
{
	int read_logs_num =  10;
	int delete_logs_num = DELETE_NUM;
	int ch = 0;
	while ((ch = getopt(argc, argv, "r:d:h")) != -1)
	{
		switch (ch)
		{
			case 'r':
				read_logs_num = atoi (optarg);
				break;
			case 'd':
				delete_logs_num = atoi (optarg);
				break;
			case 'h':
				usage ();
				return 0;	
		}
	}
	
	read_logs_noblock (read_logs_num, delete_logs_num);
		
	return 0;
}
