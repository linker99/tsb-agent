#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

#include "sys.h"
#include "convert.h"
#include "tcs_attest.h"
#include "tcs_attest_def.h"

#pragma pack(push, 1)

typedef struct{
	uint32_t uiType;
	uint32_t uiLength;
	uint32_t uiRelativeSec;
	uint32_t uiRelativeMsec;
	uint8_t log[0];
}log_st;

#pragma pack(pop)


#define httc_align_size(len,align) ((len)%(align) == 0 ? (len) : (len) + (align) - (len)%(align))

static int get_log_real_time(struct timeval *res ,uint32_t Sec, uint32_t Msec)
{
	long a = 0;
	struct timeval now;
	
	gettimeofday(&now,NULL);
	a = now.tv_usec - (Msec * 1000);
	
	if(a < 0){
		res->tv_sec = now.tv_sec - Sec - 1;
		res->tv_usec = 1000000 + now.tv_usec - (Msec * 1000);
		return 0;		
	}
	res->tv_sec = now.tv_sec - Sec;
	res->tv_usec = a;
	return 0;	
}

static inline char itoc (int n)
{
	char c = 0;
	if ((n >= 0) && (n <= 9)){
		c = n + '0';
	}
	else if ((n >= 0xA) && (n <= 0xF)){
		c = n - 10 + 'A';
	}
	return c;
}
static inline void Str_hex2Char (uint8_t *output, uint8_t *input, uint32_t insize)
{
	uint32_t i = 0;    
	while (i < insize) {
		output[i*2] = itoc ((input[i] & 0xF0) >> 4);
		output[i*2+1] = itoc (input[i] & 0x0F);
		i++;
	}
}

void tpcm_log_parse(struct tpcm_log *log)
{
	uint32_t uiType;
	uint32_t uiLength;
	uint32_t uiRelativeSec;
	uint32_t uiRelativeMsec;
	
	bmlog_st *bmLog = NULL;
	dmlog_st *dmLog = NULL;

	uint8_t digest[128] = {0};
	printf("getTpcmlog recive log type:%d\n", log->type);

	uiType = log->type;
	uiLength = log->length;
	uiRelativeSec = log->time.tv_sec;
	uiRelativeMsec = log->time.tv_usec;

	printf ("  |Type: %s\n", (LT_BOOT_MEASURE == uiType) ? "Boot Measure" : "Dynamic Measure");
	printf ("  |  |Length: %d(0x%x)\n", uiLength , uiLength);
	printf ("  |  |RelativeTime: %d.%d\n", uiRelativeSec, uiRelativeMsec);

	if (LT_DYNAMIC_MEASURE == uiType){
		dmLog = (dmlog_st *)(log->log);
		dmLog->aucName[31] = 0;
		printf ("  |  |Name: %s\n", dmLog->aucName);
		printf ("  |  |  |Result: %s(%d)\n", 
					(htonl(dmLog->uiResult) == 0)
						? "success"
						: ((htonl(dmLog->uiResult) == 0x80)
							? "failure"
							: ((htonl(dmLog->uiResult) == 2) ? "unknown" : "error")),
					htonl(dmLog->uiResult));
		Str_hex2Char (digest, dmLog->aucDigest, 32);
		printf ("  |  |  |Digest: %s\n", digest);
	}
	else if (LT_BOOT_MEASURE == uiType){
		bmLog = (bmlog_st*)(log->log);	
		printf ("  |  |Stage: %d\n", htonl(bmLog->uiStage));
		printf ("  |  |  |Result: %s(%d)\n",
					(htonl(bmLog->uiResult) == 0)
						? "success"
						: ((htonl(bmLog->uiResult) == 1)
							? "failure"
							: ((htonl(bmLog->uiResult) == 2) ? "unknown" : "error")),
					htonl(bmLog->uiResult));
		Str_hex2Char (digest, bmLog->aucDigest, 32);
		printf ("  |  |  |Digest: %s\n", digest);
		printf ("  |  |  |Name Length: %d\n", htonl(bmLog->uiNameLength));
		printf ("  |  |  |Name: %s\n", bmLog->aucName);
	}
	else{
		printf ("[%s:%d] Invalid Log Type: %d\n", __func__, __LINE__, uiType);
	}
}


int main(){
	int ret = 0;
	unsigned char log[4096]={0};
	int length = 4096;
	uint32_t offLog = 0;
	struct tpcm_log real_log;
	log_st *cur_log;
	

	do{
		offLog = 0;
		ret = tcs_get_tpcm_log (&length, log);
		if(ret){
			printf("tcs_get_tpcm_log fail ret:0x%x\n",ret);
			return -1;
		}
#ifdef DEBUG
		httc_util_dump_hex ("tpcm_log_parse dump", log, length);
#endif

		while (offLog + sizeof(log_st) < length) {
			cur_log = (log_st *)(log + offLog);
			get_log_real_time (&real_log.time, ntohl(cur_log->uiRelativeSec), ntohl(cur_log->uiRelativeMsec));
			real_log.type = ntohl(cur_log->uiType);
			real_log.length = ntohl(cur_log->uiLength);
			real_log.log = (char *)cur_log;

			if (offLog + real_log.length > length){
				printf ("[%s:%d] log length is too large (%d > %d)\n", __func__, __LINE__, offLog + real_log.length, length);
				break;
			}

#ifdef DEBUG
			httc_util_dump_hex ("real_log dump", real_log.log, real_log.length);
#endif
			if(real_log.length > 0)tpcm_log_parse(&real_log);
			offLog += httc_align_size (real_log.length, 4);
		}		
	}while (length);
		
}

