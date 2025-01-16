#include <stdio.h>
#include <stdint.h>

#include "tcfapi/tcf_file_integrity.h"

static void usage ()
{
	printf ("\n"
			" Usage: ./get_file_integrity_modify_number_limit\n"
			"\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	uint32_t num = 0;

	ret = tcf_get_file_integrity_modify_number_limit (&num);
	if (ret){
		printf ("[tcf_get_file_integrity_modify_number_limit] ret: %d(0x%x)\n", ret, ret);
		return -1;
	}

	printf ("file integrity modify number limit: %u\n", num);
		
	return 0;
}

