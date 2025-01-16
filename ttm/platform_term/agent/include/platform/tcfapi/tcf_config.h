#ifndef TCFAPI_TCF_CONFIG_H_
#define TCFAPI_TCF_CONFIG_H_

#include <stdint.h>
#include "tcf_config_def.h"

/*
 * 	������־����
 */
int tcf_set_log_config(const struct log_config *config, uint64_t version);//��proc���ƣ��鿴
/*
 * 	��ȡ��־����
 */
int tcf_get_log_config(struct log_config *config);//��proc���ƣ��鿴

/*
 * ����֪ͨ��������(ȡֵ1000-2000)
 */
int tcf_set_notice_cache_number(int num, uint64_t version);

/*
 * 	��ȡ֪ͨ��������
 */
int tcf_get_notice_cache_number(int *num);
#endif /* TCFAPI_TCF_CONFIG_H_ */
