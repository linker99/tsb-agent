#include <stdio.h>
#include <stdint.h>

#include "tcs_file_integrity.h"

static void usage ()
{
	printf ("\n"
			" Usage: ./get_file_integrity_total_number\n"
			"\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	uint32_t num = 0;

	ret = tcs_get_file_integrity_total_number (&num);
	if (ret){
		printf ("[tcs_get_file_integrity_total_number] ret: %d(0x%x)\n", ret, ret);
		return -1;
	}

	printf ("file integrity total number: %u\n", num);
		
	return 0;
}


