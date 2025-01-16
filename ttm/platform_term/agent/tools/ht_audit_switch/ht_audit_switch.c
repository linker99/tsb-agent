#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "public.h"

#include "tcfapi/tcf_config.h"
#include "tsbapi/tsb_admin.h"
#include "tcfapi/tcf_attest.h"

static char *program_name = NULL;
static char *command = NULL;
static char *switch_flag = NULL;

int usage()
{
	printf("Usage:  %s [COMMAND] [switch_flag]\n\n", program_name );
	printf("COMMAND:\n");
	printf("%s show								get audit switch policy.\n", program_name );
	printf("%s dmeasure  success/fail/no/all	set dmeasure audit switch.\n", program_name );
	printf("%s smeasure  success/fail/no/all	set smeasure audit switch.\n", program_name );

	printf("%s -h									print usage help information\n\n\n", program_name );

	exit(HT_HELP);
}

uint64_t httc_next_version(int index)
{
	/* 获取版本号 */
	struct policy_version_user version;
	version.type = index;

	int ret = tcf_get_one_policy_version(&version);
	if(ret) {
		syslog(LOG_ERR, "get policy version fail! ret :%08X", ret);
		return -1;
	}

	return version.major + 1;
}


int ht_set_dmeasure_audit_switch( int switch_flag )
{
	int ret;
	struct log_config config;

	ret = tcf_get_log_config(&config);
	if(ret) {
		printf("tcf_get_log_config fail! ret :%08X\n", ret);
		return ret;
	}

	config.dmeasure_log_level = switch_flag;
	ret = tcf_set_log_config(&config, httc_next_version(POLICY_TYPE_LOG));
	if(ret) {
		printf( "tcf_set_log_config fail! ret :%08X\n", ret);
		return ret;
	}

	printf("set dmeasure audit switch success!\n");

	return ret;
}

int ht_set_smeasure_audit_switch( int switch_flag )
{
	int ret;
	struct log_config config;

	ret = tcf_get_log_config(&config);
	if(ret) {
		printf("tcf_get_log_config fail! ret :%08X\n", ret);
		return ret;
	}

	config.program_log_level = switch_flag;
	ret = tcf_set_log_config(&config, httc_next_version(POLICY_TYPE_LOG));
	if(ret) {
		printf( "tcf_set_log_config fail! ret :%08X\n", ret);
		return ret;
	}

	printf("set smeasure audit switch success!\n");

	return ret;
}

int ht_show_audit_switch()
{
	int ret = 0;
	struct log_config config;
	char messages[512] = {0};

	ret = tcf_get_log_config(&config); 
	if (ret != 0) {
		printf("tcf_get_log_config failed, ret=%08X.\n", ret);
		return ret;
	}

	switch(config.program_log_level)
	{
		case RECORD_SUCCESS:
			strcpy(messages, "成功审计");
			break;
		case RECORD_FAIL:
			strcpy(messages, "失败审计");
			break;
		case RECORD_NO:
			strcpy(messages, "不审计");
			break;
		case RECORD_ALL:
			strcpy(messages, "全审计");
			break;
		default:
			strcpy(messages, "未知审计");
			break;
	}

	printf("smeausre audit swtich: %s\n",  messages);

	memset(messages, 0, sizeof(messages));
	switch(config.dmeasure_log_level)
	{
		case RECORD_SUCCESS:
			strcpy(messages, "成功审计");
			break;
		case RECORD_FAIL:
			strcpy(messages, "失败审计");
			break;
		case RECORD_NO:
			strcpy(messages, "不审计");
			break;
		case RECORD_ALL:
			strcpy(messages, "全审计");
			break;
		default:
			strcpy(messages, "未知审计");
			break;
	}

	printf("dmeasure switch: %s\n", messages );

	return ret;
}

int main(int argc, char *argv[])
{
	int ret = HT_HELP;
	program_name = argv[0]; 
	if (argc < 2 ) {//入参检查
		usage();
		printf("invalid parameters specified\n");
		exit(1);
	}
	command = argv[1];
	if(strcmp(command, "show") == 0) {
		ret = ht_show_audit_switch();
	}else if(strcmp(command, "dmeasure") == 0) { //动态度量
		if(!argv[2])
		{
			return usage();
		}
		switch_flag = argv[2];
		if(strcmp(switch_flag, "success") == 0)
		{
			ret = ht_set_dmeasure_audit_switch(RECORD_SUCCESS);
		}else if(strcmp(switch_flag, "fail") == 0)
		{
			ret = ht_set_dmeasure_audit_switch(RECORD_FAIL);
		}else if(strcmp(switch_flag, "no") == 0)
		{
			ret = ht_set_dmeasure_audit_switch(RECORD_NO);
		}else if(strcmp(switch_flag, "all") == 0)
		{
			ret = ht_set_dmeasure_audit_switch(RECORD_ALL);
		}
		
	} else if(strcmp(command, "smeasure") == 0) { //静态度量
		if(!argv[2])
		{
			return usage();
		}
		switch_flag = argv[2];
		if(strcmp(switch_flag, "success") == 0)
		{
			ret = ht_set_smeasure_audit_switch(RECORD_SUCCESS);
		}else if(strcmp(switch_flag, "fail") == 0)
		{
			ret = ht_set_smeasure_audit_switch(RECORD_FAIL);
		}else if(strcmp(switch_flag, "no") == 0)
		{
			ret = ht_set_smeasure_audit_switch(RECORD_NO);
		}else if(strcmp(switch_flag, "all") == 0)
		{
			ret = ht_set_smeasure_audit_switch(RECORD_ALL);
		}
	}

	return ret == HT_HELP ? usage() : ret;
}