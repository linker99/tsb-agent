#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "../tsbapi/tsb_admin.h"
#include "../tcsapi/tcs_policy.h"

//struct log_n{
//	uint16_t len;
//	uint16_t category;
//	uint16_t type;
//	uint16_t repeat_num;//
//	uint64_t time;//
//	char data[0];
//};

int main(int argc, char **argv)
{
	struct log_n log={0};
	log.len = 0;
	log.category = LOG_CATEGRORY_TNC;
	log.type = 1;

	write_user_log((unsigned char *)&log, sizeof(log));

	return 0;
}
