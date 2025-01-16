
#ifndef TSBAPI_TSB_ADMIN_H_
#define TSBAPI_TSB_ADMIN_H_

#include <stdint.h>
#include "../tcfapi/tcf_config_def.h"
#include "tsb_udisk.h"
#include "tsb_net.h"

#define TSB_USERPASS   "httc@123456"
//operate
enum {
	WHITELIST_OPERATE_EXEC = 0x1,
	CRITICAL_FILE_OPEN = 0x2,
};

enum {
	DMEASURE_OPERATE_PERIODICITY = 0x1,
	DMEASURE_TRIGGER = 0x2,
};

enum {
	LOG_CATEGRORY_WHITELIST = 0x1,
	LOG_CATEGRORY_DMEASURE = 0x2,
	LOG_CATEGRORY_WARNING = 0x3,
	LOG_CATEGRORY_AUDIT_SUM,
};
/*
//CATEGORTY
enum {
	LOG_CATEGRORY_BMEASURE = 0x1,
	LOG_CATEGRORY_WHITELIST = 0x2,
	LOG_CATEGRORY_DMEASURE = 0x3,
	LOG_CATEGRORY_TNC = 0x4,
	LOG_CATEGRORY_WARNING = 0x5,
	LOG_CATEGRORY_ACCESS = 0x6,
	LOG_CATEGRORY_UDISK = 0x7,
	LOG_CATEGRORY_NET = 0x8,
	LOG_CATEGRORY_USER_INFO = 0x9,
	LOG_CATEGRORY_AUDIT_SUM,
};
*/
/* udisk operate  */
enum 
{
	UDISK_PLUG   = 0x1,
	UDISK_UNPLUG = 0x2,
	UDISK_SCAN = 0x3,
};

enum{
	LOG_TYPE_INFO= 0,//һ����Ϣ
	LOG_TYPE_PASS, //ͨ��
	LOG_TYPE_ERROR//ʧ��
};

//������־����
enum {
	WARNING_LOG_WHITELIST = 0x1,
	WARNING_LOG_CRITICAL_CONFILE = 0x2,
};

/*�����*/
#ifdef XW_BLACK

enum {
   PARAM_ERR=0x1,
   COPY_ERR,
   USERPASS_ERR,
   OPEN_ERR,
};
#endif
    
struct tsb_user_license
{
	int *puiDataLen;
	char *pcData;
};

struct tsb_write_nv_parameter
{
    uint32_t index; 
    int length;
    unsigned char *data;
};

struct tsb_read_nv_parameter
{
    uint32_t index; 
    int length;
    unsigned char *data;
};

struct tsb_license_st
{
    int datalen;
    char data[0];
};

#ifdef XW_BLACK

typedef struct _common_header 
{
      int length;
      const char* data;
}common_header;


#endif

//result
#define		RESULT_SUCCESS        1
#define		RESULT_FAIL           2
#define		RESULT_BYPASS         3
#define		RESULT_UNMEASURED     4

#define     	RESULT_UNMARK          5   /* udisk unmark */
#define     	RESULT_MARK_INVISIBLE  6   /* udisk marked but not visible */
#define     	RESULT_MARK_READ       7   /* udisk marked can read only */
#define     	RESULT_MARK_WRITE      8   /* udisk marked can read and write */

enum {
	RECORD_SUCCESS = 1,
	RECORD_FAIL = 2,
	RECORD_NO = 4,
	RECORD_ALL = 8,
};

#define MAX_NOTICE_SIZE 48 

#pragma pack(push, 1)
struct log_n{
	uint16_t len;
	uint16_t category; //��־����
	uint16_t type;     //�������
	uint16_t repeat_num;
	uint64_t time;
	char data[0];
};

struct log_warning{
	uint32_t warning_type;   //�������ͣ�������hashУ��ʧ��[1]   �ؼ��ļ�hashУ��ʧ��[2]
};
#pragma pack(pop)

struct notify
{
	int type;
	int length;
	char buf[MAX_NOTICE_SIZE];
};

#ifdef __cplusplus
extern "C" {
#endif
/*
 * 	������־����
 */
int tsb_set_log_config(const struct log_config *config);//��proc���ƣ��鿴

/*
 * 	���¼�����־����
 */
int tsb_reload_log_config();

/*
 * 	��ȡ��־����
 */
int tsb_get_log_config(struct log_config *config);//��proc���ƣ��鿴

/*
 * 	��ת��־����ļ���
 */

int tsb_rotate_log_file();//
/*
 * 	��ȡ�ڴ���־��
 */
int tsb_read_inmem_log(unsigned char *buffer,int *length_inout,int *hasmore);

/*
 * 	��������ʽ��ȡ�ڴ���־��
 */
int tsb_read_inmem_log_nonblock(unsigned char *buffer,int *length_inout,int *hasmore);

/*
 * 	����֪ͨ���г���(ȡֵ1000-2000)��
 */
int tsb_set_notice_cache_number(int num);

/*
 * 	����֪ͨ�����С�
 */
int tsb_create_notice_read_queue();

/*
 *  close notify read queue
 */
void tsb_close_notice_read_queue(int fd);

/*
 * 	д֪ͨ��
 */
int tsb_write_notice( unsigned char *buffer, int length, int type );


int tsb_reload_cdrom_config(void);
int tsb_reload_udisk_config(void);

/*
 * 	������ʽ��ȡ֪ͨ��
 */
int tsb_read_notice(int fd, struct notify **ppnode, int *num);

/*
 * 	��������ʽ��ȡ֪ͨ��
 */
int tsb_read_notice_noblock(int fd, struct notify **ppnode, int *num);

int tsb_set_process_protect(void);

int tsb_set_unprocess_protect(void);
/*
 * 	���¼��ض�̬��������
 */
int tsb_reload_dmeasure_policy();

/*
 * 	���¼��ض�̬��������
 */
int tsb_set_dmeasure_policy(const char *data ,int length);

/*
 * 	���ӽ��̶�������
 */
int tsb_add_process_dmeasure_policy(const char *data ,int length);
/*
 * ɾ�����̶�������
 */
int tsb_remove_process_dmeasure_policy(const char *data ,int length);
/*
 * ���¼��ؽ��̶�������
 */
int tsb_reload_process_dmeasure_policy();

/*
 * 	���ý���׷�ٷ�������
 */
int tsb_set_ptrace_process_policy(const char *data ,int length);

/*
 * 	���¼��ؽ���׷�ٷ�������
 */
int tsb_reload_ptrace_process_policy(void);

/*
 * 	���¼���ȫ�ֿ��Ʋ���
 */
int tsb_reload_global_control_policy();

/*
 * 	���¼��ض�̬��������
 */
int tsb_set_global_control_policy(const char *data ,int length);

/*
 * 	���¼�����Ҫ�����ļ�����
 */
int tsb_reload_critical_confile_integrity();


int tsb_add_file_integrity(const char *data ,int length);
int tsb_remove_file_integrity(const char *data ,int length);


int tsb_reload_file_integrity();



int tsb_set_process_ids(const char *data ,int length);
int tsb_set_process_roles(const char *data ,int length);
int tsb_reload_process_roles();
int tsb_reload_process_ids();


/*
 * tsb_file_select on notice and inmem log?
 */

/*
 * 	д�û�̬��־(���dataΪ�ṹ��log_n)
 */
int write_user_log(const char *data ,int length);

/*
 * 	д�û�̬��Ϣ��־(���dataΪ�ṹ��log_n��data��)
 */
int write_user_info_log(const char *data ,int length);

/*
 * ���¼����ļ����ʿ��Ʋ���
 */
int tsb_reload_file_protect_policy();

/*
 * ���¼�����Ȩ���̲���
 */
//int tsb_reload_privilege_process_policy();

/*
 * ���ӣ�ɾ�������ذ����������ļ����ʿ��Ʋ���
 */
int tsb_add_fac_whitelist_path_policy(const char *data ,int length);
int tsb_remove_fac_whitelist_path_policy(const char *data ,int length);
int tsb_reload_fac_whitelist_path_policy();

/*
 *  д��tsb license��Ϣ
 */
int tsb_write_license(unsigned int uiDataLen,const char *pcData);

/*
 *  ��ȡtsb license��Ϣ
 */
int tsb_read_license(char *pcData, int *puiDataLen);

/*
 *  ��tsb license��Ϣд��nv�ռ�
 */
int tsb_write_nv_config(uint32_t index, int length,unsigned char *data, unsigned char *usepasswd);

/*
 *  ��nv�ռ��ȡtsb license��Ϣ
 */
int tsb_read_nv_config(uint32_t index, int length,unsigned char *data, unsigned char *usepasswd);

int tsb_set_trust_score(uint32_t  trust_score);

#ifdef XW_BLACK

int tsb_add_blcaklist_policy(unsigned char *data,int length);
int tsb_remove_blacklist_policy(unsigned char *data,int length); 
int tsb_reload_policy_by_file();
int tsb_sync_list_to_file();
#endif

#ifdef __cplusplus
}
#endif
#endif /* TSBAPI_TSB_ADMIN_H_ */
