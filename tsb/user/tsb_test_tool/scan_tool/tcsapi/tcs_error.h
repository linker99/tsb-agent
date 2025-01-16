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
	TSS_ERR_BAD_RESPONSE, 		/* Bad response stream in message */
	TSS_ERR_BAD_RESPONSE_TAG, 	/* Bad response tag in message */
	TSS_ERR_DEV_OPEN, 			/* Open device error */
	TSS_ERR_MAP,	 			/* Map error */
	TSS_ERR_BAD_DATA,			/* Invalid data */
	TSS_ERR_FILE,				/* File open or create failed */
	TSS_ERR_READ,				/* File read failed */
	TSS_ERR_WRITE,				/* File write failed */
	TSS_ERR_RECREATE,			/* The target is created repeatedly */
	TSS_ERR_SHELL,				/* Failed to execute shell command */
	TSS_ERR_NOT_SUPPORT,		/* Unsupported operation */
	TSS_ERR_RAND,				/* Create RAND_bytesc failed*/
	TSS_ERR_DIR,				/* Dir operation error */
	TSS_ERR_VERIFY,				/* Verify error */
	TSS_ERR_NONCE,				/* Dismatched nonce */
	TSS_ERR_UNTRUSTED,			/* Untrusted system */
	TSS_ERR_MAX, 				/* Keep this as the last error code !!!! */
};
	

#define DEBUG(code)


#endif	/** __TCSAPI_TCS_ERROR_H__ */

