

#ifndef TCSAPI_TCS_MAINTAIN_H_
#define TCSAPI_TCS_MAINTAIN_H_
#define MAX_BACKUP_KEY_SIZE 32

#include <stdint.h>
#include "tcs_constant.h"

#pragma pack(push, 1)
struct backup_param{
	uint32_t be_size;
	uint32_t be_backup_key_len;
	const unsigned char backup_key[MAX_BACKUP_KEY_SIZE];//用于加密卡内部数据的对称，只有管理员知道密钥。
};

struct shell_passwd{
		uint64_t be_replay_counter;
		unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
		uint32_t be_password_length;
		unsigned char password[0];
};
#pragma pack(pop)
//struct backup_data_encrpty_header{
//	uint32_t be_size;
//	uint32_t be_key_size;//公钥加密的厂商密钥
//	uint32_t be_data_size;//
//	unsigned char all[0];
//};

/*
 * 	初始化TPCM
 * 	如果需要，生成背书密钥
 * 	获取可信密码模块（TCM）的所有者权限。
 * 	需传入可信密码模块（TCM）的认证信息。
 *
 */
int tcs_init(unsigned char *passwd);

/*
 *	修改TCM所有者认证信息
 */
int tcs_change_tcm_owner_auth(unsigned char *oldpass,unsigned char *newpass);

/*
 * 	备份流程
 * 	1 生成备份的数据包（主要是SRK）
 * 	2 备份的数据包，先计算HASH,并先用管理员备份密钥加密（备份数据包 + HASH）。
 * 	3 生成厂商备份密钥，进行二次加密(第一轮加密的密文  + License信息 + HASH）
 * 	4 通过厂商公钥加密加密厂商备份密钥。
 *	backup_key//用于加密卡内部数据的对称，只有管理员知道密钥。
 */
int tcs_backup(uint32_t backup_key_len,const unsigned char *backup_key,unsigned char *backup_data,int *olen_inout);

/*
 * 	TPCM备份恢复
 * 	用于灾难和事故恢复，涉及许可权限恢复，由管理员与TPCM厂商协同完成
 * 	恢复流程
 * 	0)  生成新的证书请求,与备份的数据一起提交给华泰。华泰生成恢复包,恢复包用新TPCM的背书密钥加密
 * 	1）  用背书密钥解密备份数据（主要是license和第一次密文）
 * 	2）  验证厂商签名
 * 	3）  用备份密钥解密第一层数据（主要是SRK），并验证完整性。
 * 	4）  恢复备份数据包（不包括license）
 * 	5)  导入新的license
 */
int tcs_restore(uint32_t restore_data_len, unsigned char *restore_data, uint32_t backup_key_len,const unsigned char *backup_key);
//Instead, they can
//only be used to decrypt certificates of other TPM-generated keys, and this can only be done at the
//request of the owner of the TPM cooperating with a certificate authority (CA).

//int tcs_init();
/*
 * 	升级TPCM固件。
 * 	与重置TPCM固件不同，升级会保留用户数据和许可权限
 * 	参照之前的升级包格式
 */
int tcs_upgrade(unsigned char *upgrade_data,int length);

/*
 * 	设置TPCM控制台密码，
 * 	用于在不可重启机器的情况下，
 * 	修改控制策略，让机器可以正常启动并进行进一步维护管理。
 *	本接口改变TPCM控制台密码，提高TPCM自身的保护能力。
 */
int tcs_set_shell_password(struct shell_passwd *passwd,const char *uid,int auth_type,
		   int auth_length,unsigned char *auth);

/*
 * 执行离线命令
 * 在管理中心无法连接的情况，可导出离线命令，在本机执行。
 * 离线命令也可以由启动加载器发起
 * 如UEFI或GRUB，可通过发送离线命令改变控制策略，以便系统能够正常启动
 */
int tcs_exec_offline_cmd(const char *offcmd,int len, char *offres, int *olen);

/*
 * 烧写工具
 */

#endif /* TCSAPI_TCS_MAINTAIN_H_ */
