#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>

#include "sys.h"
#include "tcs_tpcm.h"

int main (int argc, char **argv)
{
	int ret = 0;
	uint32_t tpcmRes = 0;
	struct timeval tv;
	struct timezone tz;
	uint64_t addtime = 0;

	if (0 != (ret = gettimeofday (&tv, &tz))){
		printf ("Get time failed!\n");
		return ret;
	}
	if(argc == 2) addtime = atoi(argv[1]);
	tv.tv_sec += addtime;
	ret = tcs_set_system_time (tv.tv_sec, &tpcmRes);
	if (ret || tpcmRes){
		printf ("[tcs_set_system_time]ret: 0x%08x, tpcmRes: 0x%08x\n", ret, tpcmRes);
		return -1;
	}
	httc_util_time_print ("[tcs_set_system_time]tv_sec: %s\n", tv.tv_sec);
	return 0;
}

