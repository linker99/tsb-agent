#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include "tutils.h"
#include "tsbapi/tsb_admin.h"
#include "tcsapi/tcs_constant.h"
#include "tcsapi/tcs_attest.h"
#include "tcsapi/tcs_notice.h"
#include "tcsapi/tcs_attest_def.h"
#include "tcfapi/tcf_log_notice.h"
#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_error.h"

#include "httcutils/convert.h"
#include "httcutils/debug.h"
#include "httcutils/file.h"
#include "httcutils/mem.h"

#include "crypto/sm/sm2_if.h"
#include "crypto/sm/sm3.h"

int httc_get_replay_counter(uint64_t *replay_counter)
{
	int ret = 0;

	ret =  tcf_get_replay_counter(replay_counter);
	if(ret) return ret;

	*replay_counter += 1;
	return ret;
}

/** 发送策略版本通知 */
int httc_write_version_notices (uint64_t version, int type)
{
	struct policy_version_user ver;
	ver.major = htonll (version << 8 >> 8);
	ver.minor = htonl (version >> 56);
	ver.type = htonl (type);
	httc_util_pr_dev ("Version notice >>> major: 0x%lx, minor: 0x%x, type: 0x%x\n", (long unsigned int)ver.major, ver.minor, ver.type);
	tcf_write_notices ((unsigned char*)&ver, sizeof (ver), NOTICE_POLICIES_VERSION_UPDATED);

	return TCF_SUCCESS;
}

/** 发送策略来源通知 */
int httc_write_source_notices (uint32_t source, int type)
{
	int ret = 0;
	struct policy_source_user src;
	src.source = htonl (source);
	src.type = htonl (type);
	httc_util_pr_dev ("Source notice >>> source: 0x%x, type: 0x%x\n", src.source, src.type);

	if (0 != (ret = tcf_write_notices ((unsigned char*)&src, sizeof (src), NOTICE_POLICIES_SOURCE_UPDATED))){
		if(ret == -1){
			httc_util_pr_info ("tcf_write_notices : %d(0x%x)\n", ret, ret);
			}
	}
	return TCF_SUCCESS;
}

int httc_get_version(uint64_t *version,int flag)
{
	unsigned long datalen = 0;
	const char *file = NULL;
	uint64_t *old_version = NULL;

	if(flag == LOG_VERSION){
		file = HTTC_TSS_CONFIG_PATH"log.version";
	}else if(flag == NOTICE_VERSION){
		file = HTTC_TSS_CONFIG_PATH"notice.version";
	}

	old_version = httc_util_file_read_full(file, &datalen);
	if(old_version == NULL){
		*version = 1;
	}else{
		*version = *old_version + 1;
	}

	if(old_version) httc_free(old_version);
	return 0;
}

int httc_get_file_digest (const char *file, unsigned char *digest){

	uint8_t hash[DEFAULT_HASH_SIZE] = {0};
	uint8_t *data = NULL;
	unsigned long datalen = 0;

	if(file == NULL || digest == NULL) return TCF_ERR_PARAMETER;

	data = httc_util_file_read_full(file, &datalen);
	if(data == NULL){
		httc_util_pr_error("file error %s",file);
		return TCF_ERR_PARAMETER;
	}

	sm3(data,datalen,hash);
	memcpy(digest,hash,DEFAULT_HASH_SIZE);

	if(data) httc_free(data);
	return 0;
}



