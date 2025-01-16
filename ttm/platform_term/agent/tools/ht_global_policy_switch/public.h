#ifndef PUBLIC_H_
#define PUBLIC_H_

#include "ht_def.h"

#define HOME_PATH			"/usr/local/httcsec/ttm"

#define IN
#define OUT

enum {
	HT_OK = 0,
	HT_HELP,
	HT_ERR_TCF,
    HT_ERR_EXIST,
    HT_ERR_FILE
};

#define CHECK_FAIL(func, action)	do {				\
						int _ret;		\
						if ((_ret = (func))) {	\
							action;		\
							return _ret; 	\
						}			\
					} while (0);

typedef struct admin_s {
	unsigned char prikey[PRIKEY_LENGTH];
	unsigned char pubkey[PUBKEY_LENGTH];
} admin_t;

int os_sm2_sign(
					IN const unsigned char *msg, IN int msglen,
					IN unsigned char *privkey, IN unsigned int privkey_len,
					IN unsigned char *pubkey, IN unsigned int pubkey_len,
					OUT unsigned char **sig, OUT unsigned int *siglen);

#endif