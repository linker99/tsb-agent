#include <stdio.h>
#include "tcs_maintain.h"

static void usage ()
{
	printf ("\n"
			" Usage: ./tcs_init <oldpwd> <newpwd>\n"
			"        -oldpwd           - The old password string\n"
			"        -newpwd           - The new password string\n"
			"        eg. ./configure httc@123\n");		
}

int main (int argc, char **argv)
{
	int ret = 0;
	
	if (argc != 3){
		usage ();
		return -1;
	}

	if (0 != (ret = tcs_change_tcm_owner_auth ((unsigned char *)argv[1], (unsigned char *)argv[2]))){
		printf ("[tcs_change_tcm_owner_auth] ret = %d(0x%x)\n", ret, ret);
		return ret;
	}
	
	return 0;
}




