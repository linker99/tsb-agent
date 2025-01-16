#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "../tsbapi/tsb_admin.h"

int main(int argc, char **argv)
{
	write_user_info_log("hello word", 11);

	return 0;
}
