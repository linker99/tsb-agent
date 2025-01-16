/*
 * tdd.h
 *
 *  Created on: 2019年2月20日
 *      Author: wangtao
 */

#ifndef TDD_H_
#define TDD_H_

enum{
	TDD_CMD_CATEGORY_INIT =0,
	TDD_CMD_CATEGORY_MANAGE,
	TDD_CMD_CATEGORY_TCM,
	TDD_CMD_CATEGORY_TPCM,
	TDD_CMD_CATEGORY_RESERVED_4,
	TDD_CMD_CATEGORY_RESERVED_5,
	TDD_CMD_CATEGORY_RESERVED_6,
	TDD_CMD_CATEGORY_UNSET_REG_ADDR,
	TDD_CMD_CATEGORY_INIT_ASYNC = 8,
	TDD_CMD_CATEGORY_MANAGE_ASYNC,
	TDD_CMD_CATEGORY_TCM_ASYNC,
	TDD_CMD_CATEGORY_TPCM_ASYNC,
	TDD_CMD_CATEGORY_RESERVED_12,
	TDD_CMD_CATEGORY_RESERVED_13,
	TDD_CMD_CATEGORY_RESERVED_14,
	TDD_CMD_CATEGORY_IMAGE_VERIFY=15,
	TDD_CMD_CATEGORY_MAX = 16
};

#define TDD_CMD_CATEGORY_ASYNC_START 0X8

enum{
	TPCM_NOTIFY_TYPE_LOG = (1<<1),
	TPCM_NOTIFY_TYPE_TRUSTED_STATUS = (1<<2),
	TPCM_NOTIFY_TYPE_LICENSE = (1<<3),
	TPCM_NOTIFY_TYPE_POLICIES_VERSION = (1<<4),
};

enum{
	TPCM_ERROR_TIMEOUT = 512,
	TPCM_ERROR_CATEGORY_MISMATCH,
	TPCM_ERROR_NOMEM,
	TPCM_ERROR_SEND_FAIL,
	TPCM_ERROR_EXCEED,
};

extern int httcsec_messsage_prot;

typedef void (* notifiy_func)(unsigned int notify_type,unsigned long param);

int tdd_send_command(unsigned int cmd_category,void *buffer,
		int length,void *outbuffer,int *pout_length);
int tdd_register_notifiy_handler(notifiy_func func);
int tdd_unregister_notifiy_handler(notifiy_func func);

void *tdd_alloc_data_buffer(unsigned int size);
int tdd_free_data_buffer(void *buffer);
unsigned long tdd_get_phys_addr(void *buffer);
//void  *get_begin_addr(void);

void *tdd_alloc_data_buffer_api(unsigned int size);

enum{
        PROXY_START_CHECK = 100,
        PROXY_RUNNING_CHECK = 101,
};
int compare_proxy(unsigned long pid,int flag);
unsigned long get_proxy_pid(void);


#endif /* TDD_H_ */
