#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <httcutils/debug.h>
#include "tcfapi/tcf_log_notice.h"


int main ()
{
	int ret;
	char buf[128] = {0};
	int length = sizeof (struct log_n) + sizeof (struct tnc_log);

	struct log_n *log = (struct log_n *)buf;
	struct tnc_log *tnclog = (struct tnc_log *)log->data;

	log->len = sizeof (struct tnc_log);
	log->category = LOG_CATEGRORY_TNC;
	log->type = 0;
	//log->repeat_num = 
	//log->time = 
	tnclog->action = LOG_TNC_NEGOTIATION_FAIL;
	tnclog->peer_addr = 0x0100007F;
	tnclog->local_session_id = 123;
	tnclog->peer_session_id = 456;
	tnclog->expire_time = 789;
	tnclog->is_bi_direction = 1;
	tnclog->error_code = 0xA;
	
	if ((ret = tcf_write_logs (buf, length))){
		httc_util_pr_error ("tcf_write_logs error: %d(0x%x) \n",ret, ret);
	}
	httc_util_pr_dev ("tcf_write_logs: %d(0x%x) \n",ret, ret);

	return 0;
}