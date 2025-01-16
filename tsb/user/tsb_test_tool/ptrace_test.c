#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "../tsbapi/tsb_admin.h"
#include "../tcsapi/tcs_protect_def.h"

#define BYTE4_ALIGNMENT(len) if((len%4) != 0) len += 4-len%4

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		printf("param error!\n");
		return 0;
	}

	char buf[1024] = {0};
	struct ptrace_protect *p = (struct ptrace_protect *)buf;
	p->be_ptrace_protect = htonl(1);
	p->be_ptracer_number = htonl(1);
	p->be_non_tracee_number = htonl(1);


	char *tracer_name = "helloa";
	int len = sizeof(struct process_name) + strlen(tracer_name) + 1;
	BYTE4_ALIGNMENT(len);
	struct process_name *p_process_name = malloc(len);
	p_process_name->be_name_length = htonl(strlen(tracer_name) + 1);
	strcpy(p_process_name->prcess_names, tracer_name);

	memcpy(p->process_names, p_process_name, len);
	free(p_process_name);


	char *non_tracer_name = "printname";
	int len1 = sizeof(struct process_name) + strlen(non_tracer_name) + 1;
	BYTE4_ALIGNMENT(len1);
	p_process_name = malloc(len1);
	p_process_name->be_name_length = htonl(strlen(non_tracer_name) + 1);
	strcpy(p_process_name->prcess_names, non_tracer_name);

	memcpy(p->process_names+len, p_process_name, len1);
	free(p_process_name);


	p->be_total_length = htonl(sizeof(struct ptrace_protect)+len+len1);

	if (strcmp(argv[1], "1") == 0)
		tsb_set_ptrace_process_policy((const char *)buf, sizeof(struct ptrace_protect)+len+len1);
	else if (strcmp(argv[1], "3") == 0)
		tsb_reload_ptrace_process_policy();
	else
		printf("param argv error!\n");
	
	return 0;
}