#include <linux/kernel.h>
#include <linux/module.h>

#include "tdd.h"
#include "tcs_tpcm.h"
#include "tcs_kernel.h"
#include "tcs_attest_def.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("TPCM_SetDynamicMeasurePolicy test");

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
	printk("getTpcmlog recive log type:%d\n", log->type);

	uiType = log->type;
	uiLength = log->length;
	uiRelativeSec = log->time.tv_sec;
	uiRelativeMsec = log->time.tv_usec;

	printk ("  |Type: %s\n", (LT_BOOT_MEASURE == uiType) ? "Boot Measure" : "Dynamic Measure");
	printk ("  |  |Length: %d(0x%x)\n", uiLength , uiLength);
	printk ("  |  |RelativeTime: %d.%d\n", uiRelativeSec, uiRelativeMsec);

	if (LT_DYNAMIC_MEASURE == uiType){
		dmLog = (dmlog_st *)(log->log);
		dmLog->aucName[31] = 0;
		printk ("  |  |Name: %s\n", dmLog->aucName);
		printk ("  |  |  |Result: %s(%d)\n", 
					(htonl(dmLog->uiResult) == 0)
						? "success"
						: ((htonl(dmLog->uiResult) == 0x80)
							? "failure"
							: ((htonl(dmLog->uiResult) == 2) ? "unknown" : "error")),
					htonl(dmLog->uiResult));
		Str_hex2Char (digest, dmLog->aucDigest, 32);
		printk ("  |  |  |Digest: %s\n", digest);
	}
	else if (LT_BOOT_MEASURE == uiType){
		bmLog = (bmlog_st*)(log->log);	
		printk ("  |  |Stage: %d\n", htonl(bmLog->uiStage));
		printk ("  |  |  |Result: %s(%d)\n",
					(htonl(bmLog->uiResult) == 0)
						? "success"
						: ((htonl(bmLog->uiResult) == 1)
							? "failure"
							: ((htonl(bmLog->uiResult) == 2) ? "unknown" : "error")),
					htonl(bmLog->uiResult));
		Str_hex2Char (digest, bmLog->aucDigest, 32);
		printk ("  |  |  |Digest: %s\n", digest);
		printk ("  |  |  |Name Length: %d\n", htonl(bmLog->uiNameLength));
		printk ("  |  |  |Name: %s\n", bmLog->aucName);
	}
	else{
		printk ("[%s:%d] Invalid Log Type: %d\n", __func__, __LINE__, uiType);
	}
}

int get_tpcmlog_init(void)
{
	int r;
	printk("[%s:%d] success!\n", __func__, __LINE__);
	r = tcsk_register_log_callback(tpcm_log_parse);
	if(r){
		printk("tpcm_register_log_callback fail\n");
		return -EINVAL;
	}

	return 0;
}

void get_tpcmlog_exit(void)
{
	tcsk_unregister_log_callback(tpcm_log_parse);
	printk("[%s:%d] success!\n", __func__, __LINE__);
}

module_init(get_tpcmlog_init);
module_exit(get_tpcmlog_exit);

