#include "agt_util.h"
#include "tcfapi/tcf_attest.h"
#include "tcsapi/tcs_notice.h"

int notice_upload_all_versions(agent_t *agent);
int notice_upload_update_version(agent_t *agent, struct policy_version_user *ver);
int notice_upload_update_source(agent_t *agent, struct policy_source_user *source);
int notice_upload_untrusted(agent_t *agent);
int notice_upload_session_info(agent_t *agent, int type, void *buf);

void *notice_run(void *args);

