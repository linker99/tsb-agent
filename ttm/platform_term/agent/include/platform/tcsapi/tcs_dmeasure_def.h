

#ifndef TCSAPI_TCS_DMEASURE_DEF_H_
#define TCSAPI_TCS_DMEASURE_DEF_H_
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#include "tcs_constant.h"
#define MAX_DMEASURE_HASH_VERSION_NUMBER 8
#define TPCM_DMEASURE_OBJECT_SIZE	32
#pragma pack(push, 1)

struct dmeasure_policy_item{
	uint32_t be_type;
	uint32_t be_interval_milli;
	unsigned char object[TPCM_DMEASURE_OBJECT_SIZE];//name
};

struct dmeasure_process_item{
	uint8_t object_id_type;//�����ʶ����ȫ·������������HASH
	uint8_t sub_process_mode;//�ӽ��̣���������������Ĭ�ϣ���ȫ�ֲ��Կ��ƣ�
	uint8_t old_process_mode;//������Чǰ�������Ľ��̣���������������Ĭ�ϣ���ȫ�ֲ��Կ��ƣ�
	uint8_t share_lib_mode;;//�����⣬��������������Ĭ�ϣ���ȫ�ֲ��Կ��ƣ�
	uint32_t be_measure_interval;//����������룬0ΪĬ�ϣ���ȫ�ֲ��Կ��ƣ�
	uint16_t be_object_id_length; //���峤��
	unsigned char object_id[0];//�����ʶ��ȫ·������������HASH��
};

#pragma pack(pop)

#endif /* TCSAPI_TCS_DMEASURE_DEF_H_ */
