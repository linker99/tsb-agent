#ifndef __HTTC_MOD_PROTECT_H__
#define __HTTC_MOD_PROTECT_H__

#define PLATFORM_MOD_NAME   "platform"
#define SMEASURE_MOD_NAME   "httcsmeasure"
#define DMEASURE_MOD_NAME   "httcdmeasure"
#define FAC_MOD_NAME   "httcfac"
#define NET_MOD_NAME   "httcnet"
#define UDISK_MOD_NAME   "httcudisk"

enum {
	PLATFORM_MOD = 0,
	SMEASURE_MOD,
	DMEASURE_MOD,
	FAC_MOD,
	NET_MOD,
	UDISK_MOD,
	PROTECTION_MAX,
};

int httc_module_protect_init(void);
void httc_module_protect_exit(void);
int check_module_protect_status(char *name);
int httc_protect_module_on(char *name);
#endif
