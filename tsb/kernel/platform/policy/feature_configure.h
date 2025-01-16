#ifndef __FEATURE_CONFIGURE_H__
#define __FEATURE_CONFIGURE_H__

#include "../tpcm/tpcmif.h"




#define PARENT_PATH    "/usr/bin"

enum {
	FEATURE_WHITELIST = 1,
	FEATURE_DMEASURE,
	FEATURE_PROCESS_IDENTITY,
	FEATURE_ANTI_TRACING,
	FEATURE_PROTECTION,
	FEATURE_FAC,
	FEATURE_MAX,
};

/*ͨ�ô�����*/
enum {
    FILE_READ_ERR=-1,
};



int get_global_feature_conf(struct global_control_policy* p_global_policy, uint32_t* p_tpcm_feature, int* p_valid_license);
int path_mkdir(const char *parentpath,const char *childpath, umode_t mode);

int register_feature_conf_notify(int type, void *func);
int unregister_feature_conf_notify(int type, void *func);

int policy_linkage_init(void);
void policy_linkage_exit(void);

#endif	/* __FEATURE_CONFIGURE_H__ */
