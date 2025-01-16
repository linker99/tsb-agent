/*
 * key.h
 *
 *  Created on: 2021年1月22日
 *      Author: wangtao
 */

#ifndef TCSAPI_TCS_KEY_H_
#define TCSAPI_TCS_KEY_H_
#include "tcs_auth_def.h"
#include "tcs_key_def.h"
#include "tcs_constant.h"
enum {
	KEY_TYPE_SM2_128, KEY_TYPE_SM4_128
};

enum{	
	SIGN_KEY = (uint16_t)0,
	ENCRYPT_KEY = (uint16_t)1,
	SEAL_KEY = (uint16_t)2,
	STORE_KEY = (uint16_t)3,
	MIGRATE_KEY = (uint16_t)4
};

enum {
	INSIDE_KEY,	OUTSIDE_KEY
};

enum {
	NODE_KEY, LEAF_KEY
};

enum {
	MIGRATABLE_KEY,	UNMIGRATABLE_KEY
};

//#define KEY_FLAG_SHARED (1 << 0)

//#define KEY_FLAG__STATE (1 << 0)
//#define KEY_FLAG_TRUST_STATE (1 << 2)
//p://mig/a/b/c  s://a/b/c

/*
 * 	创建签名密钥
 * 	按指定路径创建密钥，密钥保存在密钥树中。
 */
///A/B/C
int tcs_create_sign_key(
		unsigned char *key_path, int type,
		unsigned char *passwd);

/*
 * 	按策略创建签名密钥
 * 	按策略和指定路径创建密钥，密钥保存在密钥树中。
 */
int tcs_create_sign_key_on_policy(
		unsigned char *key_path, int type,
		struct auth_policy *policy);

/*
 *	使用签名密钥签名
 *	按路径加载签名密钥，并对数据进行签名
 */
int tcs_sign(
		unsigned char *key_path, unsigned char *passwd,
		unsigned char *ibuffer, int ilength,
		unsigned char *obuffer,	int *olen_inout);

/*
 * 	创建加密密钥
 * 	创建一个用于加密大数据的对称密钥。
 *	该密钥实际是由TPCM封印的外部密钥，只在使用是释放出来
 */
int tcs_create_encrypt_key(
		unsigned char *key_path, int type,
		unsigned char *passwd);

/*
 * 	创建加密密钥
 * 	创建一个用于加密大数据的对称密钥。
 *	该密钥实际是一个真正TCM的加密密钥，用于加密数据。
 */
int tcs_create_inner_encrypt_key(
		unsigned char *key_path, int type,
		unsigned char *passwd);

/*
 * 	根据策略创建加密密钥
 * 	创建一个用于加密大数据的对称密钥。
 *	该密钥实际是由TPCM封印的外部密钥，只在使用是释放出来
 */
int tcs_create_encrypt_key_on_policy(
		unsigned char *key_path, int type,
		struct auth_policy *policy);

/*
 *	根据策略创建加密密钥
 *	创建一个用于加密大数据的对称密钥。
 *	该密钥实际是一个真正TCM的加密密钥，用于加密数据。
 */
int tcs_create_inner_encrypt_key_on_policy(
		unsigned char *key_path, int type,
		struct auth_policy *policy);


/*
 * 	使用加密密钥加密数据
 * 	按路径释放加密密钥（由TPCM封印的外部对称密钥）
 * 	并使用这个密钥加密数据
 */
int tcs_encrypt(
		unsigned char *key_path, unsigned char *passwd,
		int mode, unsigned char *ibuffer,
		int ilength, unsigned char *obuffer,
		int *olen_inout);

/*
 * 	使用加密密钥解密数据
 * 	按路径释放加密密钥（由TPCM封印的外部对称密钥）
 * 	并使用这个密钥解密数据
 */
int tcs_decrypt(
		unsigned char *key_path, unsigned char *passwd,
		int mode, unsigned char *ibuffer,
		int ilength, unsigned char *obuffer,
		int *olen_inout);

/*
 * 	修改加密密钥
 * 	按指定路径修改加密密钥，密钥保存在密钥树中。
 * 	该密钥实际是由TPCM封印的外部密钥
 * 	修改相当于在相同的密钥路径重新封印一个新密钥。
 */
int tcs_set_encrypt_key(
		unsigned char *key_path, unsigned char *passwd,
		int length, unsigned char *key);

/*
 * 	获取加密密钥
 * 	按指定路径从密钥树中读取密钥明文。
 * 	该密钥实际是由TPCM封印的外部密钥
 */
int tcs_get_encrypt_key(
		unsigned char *key_path, unsigned char *passwd,
		int *length, unsigned char *key);

/*
 *	创建封印密钥
 *	按路径创建TPCM内部密钥，用于封印关键数据。
 */
int tcs_create_seal_key(
		unsigned char *key_path, int type,
		unsigned char *passwd);
/*
 *	根据策略创建封印密钥
 *	按路径创建TPCM内部密钥，用于封印关键数据。
 */
int tcs_create_seal_key_on_policy(
		unsigned char *key_path, int type,
		struct auth_policy *policy);

/*
 * 	封印数据
 * 	使用路径指定的封印密钥，封印数据并输出封印后的密文数据包。
 * 	封印的输入一般是需要TPCM保护的关键数据，也可以是外部密钥。
 * 	封印输出的数据包可用于解封的输入。
 *
 */
int tcs_seal_data(
		unsigned char *key_path, unsigned char *ibuffer,
		int ilength, unsigned char *obuffer,
		int *olen_inout, unsigned char *passwd);
/*
 * 	解封数据
 * 	使用路径指定的封印密钥，解封数据，得到明文。
 * 	输入数据是之前封印数据输出的数据包。
 */

int tcs_unseal_data(
		unsigned char *key_path, unsigned char *ibuffer,
		int ilength, unsigned char *obuffer,
		int *olen_inout, unsigned char *passwd);

/*
 * 	封印数据保存在密钥树
 * 	使用路径指定的封印密钥，封印数据的密文数据包保存在密钥树中。
 * 	封印的输入一般是需要TPCM保护的关键数据，也可以是外部密钥。
 * 	封印后可以按路径及文件名解封数据。
 */
int tcs_seal_data_store(
			unsigned char *key_path, unsigned char *ibuffer,
			int ilength, unsigned char *file_name, unsigned char *passwd);

/*
 * 	解封密钥树中的封印数据
 * 	使用路径指定的封印密钥，解封密钥树中保存的封印数据，得到明文。
 * 	封印后可以按路径及文件名解封数据。
 */
int tcs_unseal_stored_data(
		unsigned char *key_path, unsigned char *obuffer,
		int *olen_inout, unsigned char *file_name,
		unsigned char *passwd);

/*
 * 	获取密钥树中的封印数据
 * 	根据密钥路径和文件名读取封印的数据，数据不会解封。
 */
int tcs_get_sealed_data(
		unsigned char *key_path, unsigned char *obuffer,
		int *olen_inout, unsigned char *file_name);

/*
 * 	将封印后的数据保存到密钥树中
 * 	将封印后的数据包密文，保存到密钥树中
 * 	调用者应保证封印的数据是由这个指定的密钥封印的，否则无法解封。
 */
int tcs_save_sealed_data(
		unsigned char *key_path, void *ibuffer,
		int ilength, unsigned char *file_name);

/*
 * 	设置默认存储密钥类型
 * 	密钥树中的非叶子存储密钥，如果不存在将自动创建
 * 	本接口设置自动创建非叶子存储密钥的密钥类型。
 *
 */
int tcs_set_default_path_key_type(uint32_t type);

/*
 * 	创建可迁移存储密钥
 * 	自主创建可签名非叶子存储密钥，创建后该密钥树分支可进行迁移。
 * 	自动创建的非叶子存储密钥不可迁移
 * 	自动创建存储密钥使用默认的类型。
 * 	而自主创建可由调用者指定类型
 */
int tcs_create_migratable_path_key(unsigned char *key_path, uint32_t type);

/*
 * 	创建存储密钥
 * 	自主创建非叶子存储密钥
 * 	自动创建存储密钥使用默认的类型。
 * 	而自主创建可由调用者指定类型
 */
int tcs_create_path_key(unsigned char *key_path, uint32_t type);

/*
 *
 */
//int tcs_wrap_key(unsigned char *key_path,int type,uint32_t flags,void *ibuffer, int ilength,unsigned char *passwd);

/*
 * 	获取公钥
 * 	根据密钥路径，从密钥树中获取公钥
 */
int tcs_get_public_key(
		unsigned char *key_path, unsigned char *pbuffer,
		int *obuf_len);

/*
 *	修改密钥树叶子节点认证密码
 * 	根据密钥路径，修改密钥树叶子节点的密码
 */
int tcs_change_leaf_auth(
		unsigned char *key_path, unsigned char *oldpasswd,
		unsigned char *passwd);

//int tcs_change_leaf_policy();
//改变策略

/*
 *	获取密钥信息
 * 	根据密钥路径，获取密钥信息
 */
int tcs_get_keyinfo(unsigned char *key_path, struct key_info *info);

/*
 * 	获取密钥路径的密钥信息
 * 	根据密钥路径，获取从根路径开始的所有密钥信息
 */
int tcs_get_keyinfo_path(
		unsigned char *key_path, struct key_info **info,
		int *onumber_inout);

/*
 * 	创建公共密钥树非易失存储空间
 * 	在TPCM创建非易事存储空间。
 * 	该空间用于保存公共密钥树
 * 	密钥树释放保存到非易失存储空间由上层管理软件决定。
 * 	本接口提供机制，并不自动保存密钥树。
 */

int tcs_create_shared_keytree_storespace(
		unsigned char *ownerpass, int size,	unsigned char *nvpasswd);
/*
 * 	删除公共密钥树非易失存储空间
 */
int tcs_remove_shared_keytree_storespace(unsigned char *ownerpass);

/*
 * 	保存公共密钥树到非易失存储空间
 * 	保存位置需事先创建
 */
int tcs_save_shared_keytree(unsigned char *nvpasswd);

/*
 * 	从非易失存储空间加载公共密钥树
 * 	保存位置需事先创建
 */
int tcs_load_shared_keytree(unsigned char *nvpasswd);

/*
 * 	设置私有密钥树非易失存储空间
 */

int tcs_set_private_keytree_storespace_index(uint32_t nvindex);

/*
 * 	保存私有密钥树到非易失存储空间
 * 	保存位置需事先设置
 */

int tcs_save_private_keytree(unsigned char *nvpasswd);
/*
 * 	从非易失存储空间加载私有密钥树
 * 	保存位置需事先设置
 */
int tcs_load_private_keytree(unsigned char *nvpasswd);

/*
 * 	导出密钥树
 * 	可用于备份
 */
int tcs_export_keytree(
		const char *keypath, unsigned char **pbuffer,
		int *obuf_len);

/*
 * 	导入密钥树
 * 	可恢复备份
 */
int tcs_import_keytree(const char *keypath, unsigned char *pbuffer, int buf_len);

/*
 * 	读取密钥树
 */
int tcs_read_keytree(const char *keypath, struct key_node **node,
		unsigned int level);

/*
 *	释放密钥节点内存
 */
int tcs_free_keynode(struct key_node **node, int recursive);


/*
 *	删除密钥树
 */
int tcs_delete_keytree(const char *keypath);

/*
 *	准备认证数据
 */
int tcs_get_migrate_auth(unsigned char **auth, int *auth_length);

/*
 *	迁出密钥树
 */
int tcs_emigrate_keytree(const char *keypath, unsigned char *passwd, unsigned char *ownerpass, 
							unsigned char *auth,	int authlength,unsigned char **pbuffer, int *obuf_len);


/*
 * 	迁入密钥树
 */
int tcs_immigrate_keytree(const char *keypath, unsigned char *pbuffer,int buf_len);


//Public key authentication functions
//• Integrity measurement functions
//• Attestation functions
//Once booted, data
//(such as private keys) can be “sealed” under a PCR. The sealed data can be unsealed only if the
//PCR has the same value as at the time of sealing.
//The attestation functions keep a list of all the software measurements committed to the
//PCRs, and can then sign them with a private key known only by the TPM. Thus, a trusted client
//can prove to a third party that its software has or has not been compromised.

//• Securely report the environment that booted
//• Securely store data
//• Securely identify the user and system (without encountering privacy concerns)
//• Support standard security systems and protocols
//• Support multiple users on the same system while preserving security among them
//• Be produced inexpensively

//1) separate storage medium to store the data objects.
//2)uses encryption to store data, and encryption and decryption to control access to that data

//One of the design goals for secure storage
//was to take advantage of this persistent storage to provide that the number of private keys,
//symmetric keys, and data that can be stored behind those keys by a TPM is virtually unlimited
//These latter keys, called identities, in turn can only be used for two purposes: to create certificates
//for other non-migratable keys or to sign PCRs,
#endif /* TCSAPI_TCS_KEY_H_ */
