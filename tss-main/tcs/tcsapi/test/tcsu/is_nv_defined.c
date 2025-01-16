#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include "file.h"
#include "debug.h"
#include "tcs_store.h"


int main(int argc, char **argv){

	int ret = 0;

	uint32_t index = 0;
	index = atoi(argv[1]);
	ret = tcs_is_nv_index_defined(index);
	if(ret){
		printf("tcs_is_nv_defined fail! ret:0x%08X!\n",ret);
		return -1;
	}
	return 0;
}




