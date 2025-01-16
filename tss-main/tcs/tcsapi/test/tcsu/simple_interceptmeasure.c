#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#include "mem.h"
#include "debug.h"
#include "tcs_tpcm.h"
    
static void usage ()
{
	printf ("\n"
			" Usage: ./simple_interceptmeasure -n <name> -t <type>\n"
			"        -n <name>               - Intercept measure filename\n"
			"        -t <type>               - Intercept measure type\n"
			"    eg. ./simple_interceptmeasure -n /usr/bin/gdb -t 1\n\n");
}


int main (int argc, char **argv){
	int ret = 0;
	int ch = 0;
	uint32_t tpcmRes = 0;
	
	uint8_t mresult[32];
	uint32_t mrLen = 32;
	uint8_t *imname = NULL;
	unsigned int imtype = 0;
	uint8_t *imData = NULL;
	uint32_t dataLen = 0;
	uint32_t imKeyLen = 0;
	uint8_t *imKey = NULL;
	
	struct stat imfileStat;	
	FILE *fp = NULL;
	unsigned int imfileSize = 0;

	if(argc < 5){
		usage ();
		return -1;
	}

	while ((ch = getopt(argc, argv, "n:t:")) != -1){
		switch (ch)
			{
				case 'n':
					imname = optarg;
					imKeyLen = strlen(imname);
						if(NULL == (imKey = (uint8_t *)httc_malloc(imKeyLen))){
							printf ("[%s:%d] Malloc imKey error\n", __func__, __LINE__);
							return -1;
						}
					memcpy(imKey,imname,imKeyLen);
					break;
				case 't':
					imtype = atoi(optarg);
					break;				
			}
	}
	if (NULL == (fp = fopen (imname, "rb")))
	{
		perror ("Open message file faliure");
		if(imKey) httc_free(imKey);
		return -1;
		
	}
	stat (imname, &imfileStat);
	dataLen = (int)imfileStat.st_size;
	if (NULL == (imData = httc_malloc (dataLen))){
		fclose (fp);
		if(imKey) httc_free(imKey);
		return -1;
	}
	if (dataLen != fread (imData, 1, dataLen, fp))
	{
		perror ("Read data from file failure");
		fclose (fp);
		if(imKey) httc_free(imKey);
		if(imData) httc_free(imData);
		return -1;
	}

	ret = tcsk_integrity_measure_easy (imKey,imKeyLen,imtype,imData,dataLen,&tpcmRes,&mrLen,mresult);
	if(!ret && mrLen != 0){
		httc_util_dump_hex("mresult",mresult,mrLen);
	}
	if (ret || tpcmRes){
		printf ("[tcsk_integrity_measure_easy]ret: 0x%08x, tpcmRes: 0x%08x\n", ret, tpcmRes);
		ret = -1;
	}

	fclose (fp);
	if(imKey) httc_free(imKey);
	if(imData) httc_free(imData);

	return ret;	
}


