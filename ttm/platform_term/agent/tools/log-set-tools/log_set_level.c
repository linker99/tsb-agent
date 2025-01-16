
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>


#include "tsb_admin.h"


#define HTTC_TSB_INFO	        0x1	/* normal 消息 */
#define HTTC_TPCM_DEBUG       0x2	/* TPCM 调试信息 */
#define HTTC_TSB_DEBUG        0x4	/* TSB 调试信息 */

void usage()
{
	printf ("\n"
			" Usage: ./log_set [options]\n"
			" options:\n"
        "NO_INFO   0x00 no info \n"
	"TSB_INFO  0x1 normal \n"
	"TPCM_DEBUG 0x02TPCM \n"
        "TSB_DEBUG  0x04TSB  \n"
        "GET_LOG_LEVEL :get current kernel log level!\n"
        "eg. ./log_set NO_INFO\n"
			"\n");
}



int main(int argc, char **argv){

	int ret = 0;

	int log_level =0;


	if (argc != 2){
		usage ();
		return -1;
	}
	
if (strcmp(argv[1], "NO_INFO") == 0)
       log_level=0x00; 
else if(strcmp(argv[1], "TSB_INFO") == 0) 
    {
      log_level=0x01;
}else if(strcmp(argv[1], "TPCM_DEBUG") == 0)
    {
      log_level=0x02;
}else if(strcmp(argv[1], "TSB_DEBUG") == 0)
{
      log_level=0x04;
}
else if (strcmp(argv[1], "GET_LOG_LEVEL") == 0)
{
    //get current log level
    log_level = tsb_get_log_mode();
    printf("current log_level:[%d]\n", log_level);
    return 0;

}
 else 
 {
  usage();
  return 0;
 }

    printf ("user input log_level: [%d]\n", log_level);
    tsb_set_log_mode(log_level);
    log_level=tsb_get_log_mode();
    printf("log_level:[%d]\r\n",log_level);
 	return ret;	
}
