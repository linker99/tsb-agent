#ifndef __TCSAPI_TCS_ERROR_H__
#define __TCSAPI_TCS_ERROR_H__

enum{
	TSS_SUCCESS = 0,
	TSS_ERR_PARAMETER = 1024, 	/* An argument had an invalid value */
	TSS_ERR_NOMEM,				/* Memory is not enough */
	TSS_ERR_IO, 				/* An I/O Error occurred */
	TSS_ERR_INPUT_EXCEED, 		/* The size of args exceed the limit */
	TSS_ERR_OUTPUT_EXCEED, 		/* The size of output exceed the limit of args */
	TSS_ERR_ITEM_NOT_FOUND, 	/* The searched item could not be found  */
	TSS_ERR_BAD_RESPONSE, 		/* Bad response stream in message 30*/
	TSS_ERR_BAD_RESPONSE_TAG, 	/* Bad response tag in message */
	TSS_ERR_DEV_OPEN, 			/* Open device error */
	TSS_ERR_MAP,	 			/* Map error */
	TSS_ERR_FILE,				/* Fail open or create failed */
	TSS_ERR_READ,				/* Fail read failed 35*/
	TSS_ERR_WRITE,				/* Fail write failed */
	TSS_ERR_RECREATE,			/* The target is created repeatedly */
	TSS_ERR_SHELL,				/* Failed to execute shell command */
	TSS_ERR_NOT_SUPPORT,		/* Unsupported operation */
	TSS_ERR_RAND,				/* Create RAND_bytesc failed40*/
	TSS_ERR_DIR,				/* Dir operation error */
	TSS_ERR_VERIFY,				/* Verify error */
	TSS_ERR_NONCE,				/* Dismatched nonce */
	TSS_ERR_UNTRUSTED,			/* Untrusted system */
	TSS_ERR_ADMIN_AUTH,			/* Admin auth */
	TSS_ERR_TSB,				/* TSB Error */
	TSS_ERR_SEM,				/* SEM error */
	TSS_ERR_SEM_TIMEOUT,		/* SEM timeout */
	TSS_ERR_INVALID_UID,		/* Invalid UID */
	TSS_ERR_BAD_DATA,			/* Bad data */
	TSS_ERR_VERIFY_REPLAY,		/* Replay counter error */
	TSS_ERR_INVAILD_HOST_ID,	/* Invalid host id */
	TSS_ERR_SM3_INIT,   		/* sm3 init error */
	TSS_ERR_SM3_UPDATE,		/* sm3 update error */
	TSS_ERR_SM3_FINISH,		/* sm3 finished error */
	TSS_ERR_SM2_SIGN,			/* sm2 sign/sign_e error */
	TSS_ERR_SM2_VERIFY,		/* sm2 verify/verify_e error */
	TSS_ERR_SM4_ENCRYPT,		/* sm4 ecb/cbc encrypt error */
	TSS_ERR_SM4_DECRYPT,		/* sm4 ecb/cbc decrypt error */
	TSS_ERR_RANDOM,			/* tcs get random error */
	TSS_ERR_MAX, 				/* Keep this as the last error code !!!! */
};
	

#define DEBUG(code)


#endif	/** __TCSAPI_TCS_ERROR_H__ */

