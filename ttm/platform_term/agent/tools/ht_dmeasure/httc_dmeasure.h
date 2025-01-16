#include <stdint.h>

#define	UID_LOCAL			"ht_agent"
#define HOME_PATH			"/usr/local/httcsec/ttm"

#define MAX_TPCM_ID_SIZE 		32
#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128

#define PRIKEY_LENGTH		32
#define PUBKEY_LENGTH		64


struct dmeasure_policy_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	uint32_t be_item_number;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char data[0];//dmeasure_item array,every item 4 byte align
};

struct dmeasure_process_policy_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	uint32_t be_item_number;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char data[0];//process_dmesaure_item array,every item 4 byte align
};

struct dmeasure_policy_item_user{
	char *name;
	uint32_t type;
	uint32_t interval_milli;
};

struct dmeasure_process_item_user{
	uint8_t object_id_type;//客体标识类型全路径、进程名、HASH
	uint8_t sub_process_mode;//子进程，度量、不度量、默认（按全局策略控制）
	uint8_t old_process_mode;//策略生效前已启动的进程，度量、不度量、默认（按全局策略控制）
	uint8_t share_lib_mode;//共享库，度量、不度量、默认（按全局策略控制）
	uint32_t measure_interval;//度量间隔毫秒，0为默认（按全局策略控制）
	uint16_t object_id_length; //客体长度
	char *object_id;//客体标识（全路径、进程名、HASH）
};

//进程动态度量
struct dmeasure_reference_item_user{
	int hash_length;//
	int hash_number;//support multi version(用于代码段可变)
	char  *hash_buffer;//length=hash_length  * hash_number
	char *name;//hash+name
};

typedef struct admin_s {
	unsigned char prikey[PRIKEY_LENGTH];
	unsigned char pubkey[PUBKEY_LENGTH];
} admin_t;

enum{
	PROCESS_DMEASURE_OBJECT_ID_FULL_PATH,//全路劲
	PROCESS_DMEASURE_OBJECT_ID_PROCESS,//进程名
	PROCESS_DMEASURE_OBJECT_ID_HASH,//HASH
};

enum{
	CERT_TYPE_NONE,//用于无认证，只用于策略
	CERT_TYPE_PUBLIC_KEY_SM2,//128 位SM2公钥
	CERT_TYPE_PASSWORD_32_BYTE,//最长32字节密码，认证时计算HMAC
	CERT_TYPE_X501_SM2,//X501 国密证书
};


enum{
        POLICY_ACTION_SET,
        POLICY_ACTION_ADD,
        POLICY_ACTION_DELETE,
        POLICY_ACTION_MODIFY
};

#define IN
#define OUT

int os_sm2_sign(
IN const unsigned char *msg, IN int msglen,
IN unsigned char *privkey, IN unsigned int privkey_len,
IN unsigned char *pubkey, IN unsigned int pubkey_len,
OUT unsigned char **sig, OUT unsigned int *siglen);
int httc_get_replay_counter(uint64_t *replay_counter);
int tcf_get_tpcm_id(unsigned char *id,int *len_inout);

/*
 * 	准备更新动态度量策略
 */
int tcf_prepare_update_dmeasure_policy(
		struct dmeasure_policy_item_user *items,int num,
		unsigned char *tpcm_id,int tpcm_id_length,
		uint32_t action,	uint64_t replay_counter,
		struct dmeasure_policy_update **policy,int *olen);

/*
 * 	准备更新进程动态度量策略
 */
int tcf_prepare_update_dmeasure_process_policy(
		struct dmeasure_process_item_user *items,int num,
		unsigned char *tpcm_id,int tpcm_id_length,
		uint32_t action,	uint64_t replay_counter,
		struct dmeasure_process_policy_update **policy,int *olen);

/*
 * 	更新动态度量策略
 * 	设置
 */

int tcf_update_dmeasure_policy(struct dmeasure_policy_update *policy,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth);


/*
 * 	更新动态度量策略
 * 	设置、增加、删除。
 */

int tcf_update_dmeasure_process_policy(struct dmeasure_process_policy_update *policy,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth);
/*
 * 	获取动态度量策略
 */
int tcf_get_dmeasure_process_policy(struct dmeasure_process_item_user **policy,int *item_count);//proc 导出


/*
 * 	释放进程动态度量策略内存
 */
void tcf_free_dmeasure_process_policy(struct dmeasure_process_item_user *policy,int item_count);//proc 导出

/*
 * 	获取动态度量策略
 */
int tcf_get_dmeasure_policy(struct dmeasure_policy_item_user **policy,int *item_count);//proc 导出

/*
 * 	释放动态度量策略内存
 */
void tcf_free_dmeasure_policy(struct dmeasure_policy_item_user *policy,int item_count);//proc 导出



