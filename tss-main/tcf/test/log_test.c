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
		printf ("  [%d].object: %s\n", i, log->data);
		printf ("  [%d].subject: %s\n", i, log->data + log->len_object);
	}
	printf ("\n");
}

int test_read_logs (void)
{
	int ret = 0;
	int num_inout = 10;
	unsigned timeout = 10;
	struct log **logs = NULL;
	
	if (0 != (ret = tcf_read_logs (&logs, &num_inout, timeout))){
		httc_util_pr_error ("tcf_read_logs error: %d(0x%x)\n", ret, ret);
		return ret;
	}
	log_dump (logs, num_inout);
	
	if (num_inout){
		if (0 != (ret = tcf_remove_logs (logs[num_inout - 1]))){
			httc_util_pr_error ("tcf_remove_logs error: %d(0x%x)\n", ret, ret);
			//return ret;
		}

		if (0 != (ret = tcf_free_logs (num_inout, logs))){
			httc_util_pr_error ("tcf_free_logs error: %d(0x%x)\n", ret, ret);
			return ret;
		}
	}
	return ret;
}

int test_read_logs_noblock (void)
{
	int ret = 0;
	int num_inout = 1000;
	struct log **logs = NULL;
	
	if (0 != (ret = tcf_read_logs_noblock (&logs, &num_inout))){
		httc_util_pr_error ("tcf_read_logs error: %d(0x%x)\n", ret, ret);
		return ret;
	}
	//log_dump (logs, num_inout);
		
	if (num_inout){
		if (0 != (ret = tcf_remove_logs (logs[num_inout - 1]))){
			httc_util_pr_error ("tcf_remove_logs error: %d(0x%x)\n", ret, ret);
			//return ret;
		}
		if (0 != (ret = tcf_free_logs (num_inout, logs))){
			httc_util_pr_error ("tcf_free_logs error: %d(0x%x)\n", ret, ret);
			return ret;
		}
	}

	return ret;
}

int main ()
{
	//test_read_logs ();
	test_read_logs_noblock ();
	return 0;
}

