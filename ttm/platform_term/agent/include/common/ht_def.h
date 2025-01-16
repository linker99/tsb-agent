#ifndef __HT_DEF_H__
#define __HT_DEF_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <assert.h>

#define PATH_MAX_LEN			512
#define UUID_LEN			36
#define IP_LEN				16
#define PASS_LENGTH			16
#define NAME_LENGTH			16
#define ID_LENGTH			32
#define HASH_LENGTH			32
#define GUID_LENGTH			48
#define SM4_LOCAL_LENGTH	16
#define PRIKEY_LENGTH		32
#define PUBKEY_LENGTH		64
#define SIG_LENGTH			64
#define KEY_PATH_LENGTH		128
#define PROCESS_NAME_LEN	128
#define PATH_LENGTH			256
#define SOCK_PATH_LENGTH	256
#define	CERT_SIZE			4096
#define LICENSE_NV_INDEX	1017
#define LICENSE_NV_PWD		"httc@123456"

#define TMP_COMPRESS_DIR	"/usr/local/httcsec/temp_file"

enum {
	POLICY_FROM_MANAGER,
	POLICY_FROM_REMOTE,
	POLICY_FROM_LOCAL
};

#define	UID_MANAGER			"manager"
#define	UID_LOCAL			"ht_agent"
#define DEFAULT_ROOT_PATH	"/usr/local/httcsec/ttm"

#define BMC_IPV6  	"fe80::9e7d:a3ff:fe28:6ffa"
#define BMC_PORT  	7777

#define agent_malloc		malloc
#define agent_calloc(b)		calloc(b, 1)
#define agent_free(b)		do { if (b) {free(b); b=NULL;}} while (0);

#define OFFSETOF(type,field)	((long)&((type*)0)->field)
#define atom_inc(k, n)		__sync_add_and_fetch(k, n)
#define atom_dec(k, n)		__sync_sub_and_fetch(k, n)

#define dw(N)	_Pragma("GCC diagnostic push");	\
				_Pragma(#N);

#define AGENT_WARNING_IGNORED(N)	dw(GCC diagnostic ignored N)
#define AGENT_WARNING_RECOVER		_Pragma("GCC diagnostic pop")

typedef struct ht_err_s {
	int error;
	char info[256];
}ht_err_t;

enum {	
	HTTC_ERR_NONE = -255,                           //0xFF
	HTTC_EXIT,                                      //退出程序信号
	HTTC_RELOAD,                                    //重新加载信号
	
	HTTC_ERR_BUSY,                                  //业务繁忙
	HTTC_ERR_COMMON,                               //一般错误

	/* -250 */
	HTTC_ERR_CMD_NOT_SUPPORT,                       //命令不支持
	HTTC_ERR_MODULE_NOT_FOUND,                      //模块未加载
	HTTC_ERR_HAS_REGISTER,                          //已注册
	HTTC_ERR_TCF,                                  //TCF接口调用错误
	HTTC_ERR_SQLITE,                               //sqlite数据库错误
	HTTC_ERR_NVWRITE,                              //NV区域写错误
	HTTC_ERR_NVREAD,                               //NV区域读错误
	HTTC_ERR_PATH,                                 //文件路径不存在
	HTTC_ERR_PATH_SIZE,								//文件大小错误
	HTTC_ERR_NOMEM,                                //内存错误

	/* -240 */
	HTTC_ERR_DATA,                                 //数据包数据错误
	HTTC_ERR_TIMEOUT,                              //连接/接收超时
	HTTC_ERR_CONNECT,                              //连接失败
	HTTC_ERR_PACKET,                               //数据包格式错误
	HTTC_ERR_CONFIG,                               //配置错误
	HTTC_ERR_INIT,                                 //初始化失败
	HTTC_ERR_LIMIT,                                 //资源不足
	HTTC_ERR_REGISTER,								//注册失败
	HTTC_ERR_STATE,									//状态不匹配
	HTTC_ERR_DOWNLOAD,								//下载失败

	/* -230 */
	HTTC_ERR_TCF_ARG,								//TCF接口参数错误
	HTTC_ERR_VERIFY,								//认证失败

	HTTC_OK = 0,

	/*TDD错误码*/
	TPCM_SET_POLICY_AUTH_ERROR = 163,
	TPCM_PCR_TYPR_ERROR = 168,
	TPCM_ID_VERIFY_FAIL = 183,
	TPCM_PLOCY_OBJECT_ID_ERROR,
	TPCM_PLOCY_AUTH_TYPE_ERROR,

	TPCM_ERROR_TIMEOUT = 512,
	TPCM_ERROR_CATEGORY_MISMATCH,
	TPCM_ERROR_NOMEM,
	TPCM_ERROR_SEND_FAIL,
	TPCM_ERROR_EXCEED,

	/*TCS错误码*/
	TSS_ERR_BAD_ARGS = 1024,
};


#endif
