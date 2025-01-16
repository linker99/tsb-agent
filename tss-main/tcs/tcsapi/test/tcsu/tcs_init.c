#include <stdio.h>
#include "tcs_maintain.h"

static void usage ()
{
	printf ("\n"
			" Usage: ./tcs_init <pwd>\n"
			"        -pwd           - The password string\n"
			"        eg. ./tcs_init httc@123\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	
	if (argc != 2){
		usage ();
		return -1;
	}

	if (0 != (ret = tcs_init ((unsigned char *)argv[1]))){
		printf ("[tcs_init] ret = %d(0x%x)\n", ret, ret);
		return ret;
	}
	
	return 0;
}

