#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>
#include "message.h"
#include <comm_driver.h>
#include <string.h>
#include "tpcm_sys.h"
//#include "tpcm_encrypt_store.h"

#define F	"/home/aaa"

int flash_init(void);
int comm_init(void);
#define FLASH_AREA 0x3100000
void mark_start_time();
int system_init();

void func1(int sig)
{
//	char cmd[1024] = {0};
	if(sig != 17){
		printf("Catch a signal,it is NO.%d signal!\n",sig);
	}

//	snprintf(cmd,1024,"echo %d >> /home/z",sig);
//	system(cmd);
}

void cap_signal(void (*func)(int))
{
        struct sigaction sa = { 0 };
        sigemptyset(&sa.sa_mask);//清空信号集合
        sigfillset(&sa.sa_mask);//将所有信号添加进集合

        sa.sa_handler = func;
        for(int i = 1; i < 32; i++)
        {
		if(i != 15 && i!= 13){
                	sigaction(i, &sa, NULL);//注册一个信号的捕捉函数
		}
        }
}

void handle_unexpected(int sig) {
	if(sig == 13){
		exit(0);
	}
}

 //wanans 2022-1012_001
int main(int argc,char **argv){
	unsigned char cmd[1024] = {0};
#if 0
	FILE *fp = NULL;
	fp = fopen(F,"w");
	if(fp){
		printf("1TPCM proxy not null\n");
		fprintf(fp,"TPCM proxy not null\n");
	}else{
		printf("TPCM proxy  null\n");
	}

	if(fp)
		fclose(fp);
	fp = NULL;

#endif

	cap_signal(func1);
	//signal(13, SIG_IGN);
	struct sigaction sa;	
	memset(&sa, 0, sizeof(sa));
	//sa.sa_handler = SIG_IGN;
	sa.sa_handler = handle_unexpected;
	sigaction(SIGPIPE, &sa, NULL);

	srand( (unsigned)time( 0 ) );
	system_init();
	//if(fp)
	//	fprintf(fp,"test1111\n");

	comm_init();
	
	//if(fp)
	//	fprintf(fp,"test22222\n");
	mark_start_time();
	printf("TPCM proxy starting\n");
	


#if 0
	while(1){
		printf("start open usb\n");
		sleep(1);
		main_loop();
	}
#endif
	main_loop();
	
	return 0;
}

