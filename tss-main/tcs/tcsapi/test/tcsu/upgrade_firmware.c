#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "tcs_maintain.h"


int main (int argc, char **argv)
{
	int ret = 0;
	
	FILE *fp = NULL;
  	struct stat fileStat;
  	uint32_t statLen = 0;
  	uint8_t *fwFilename = NULL;
  	uint8_t *fwbuf = NULL;
 
	if (argc != 2){
		printf ("\n");
		printf (" Usage: ./upgrade_firmware FILENAME\n");
		printf ("\n");
		printf ("\n");
		return -EINVAL;
	}

	fwFilename = argv[1];
	if (NULL == (fp = fopen (fwFilename, "rb"))){
		perror ("Open firmware file faliure");
		return -1;
	}
	stat (fwFilename, &fileStat);
	statLen = (uint32_t)fileStat.st_size;

	if (NULL == (fwbuf = malloc (statLen)))	{
		fclose (fp);
		return -1;
	}

	if (statLen != fread (fwbuf, 1, statLen, fp))
	{
		perror ("Read firmware filefailure");
		fclose (fp);
		free (fwbuf);
		return -1;
	}

	ret = tcs_upgrade (fwbuf, statLen);
	printf ("[%s:%d]ret: 0x%08x, tpcmRes: 0x%08x\n", __func__, __LINE__, ret, ret);
	if (ret)	ret = -1;
	fclose(fp);
	if(fwbuf) free(fwbuf);
	return ret;
}

