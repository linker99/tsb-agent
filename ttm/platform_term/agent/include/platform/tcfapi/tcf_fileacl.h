
#ifndef TRUNK_INCLUDE_TCFAPI_TCF_FILEACL_H_
#define TRUNK_INCLUDE_TCFAPI_TCF_FILEACL_H_
#include "../tcsapi/tcs_constant.h"
struct tcf_file_protect{
	int length;//pattern length
	char *pattern;
};
struct tcf_privilege_process{
	int length;//pattern length
	char hash[DEFAULT_HASH_SIZE];
	char *pattern;
};

int tcf_set_file_protect_policy(struct tcf_file_protect *ppolicy,int num);
int tcf_set_privilege_process_policy(struct tcf_privilege_process *ppolicy,int num);

#endif /* TRUNK_INCLUDE_TCFAPI_TCF_FILEACL_H_ */
