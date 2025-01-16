#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cJSON.h"

#include "ht_def.h"
#include "ht_string.h"
#include "ht_crypt.h"

#define IN
#define OUT

#define ONCE_MAX_COUNT			800

#define MAX_TPCM_ID_SIZE 		32


/* 默认度量时间 1分钟 */
#define DEFAULT_DMEASURE_TIME	(60 * 1000)

#define CHECK_FAIL(func, action)	do {				\
						int _ret;		\
						if ((_ret = (func))) {	\
							action;		\
							return _ret; 	\
						}			\
					} while (0);


					
enum {
	HT_INIT_OK = 0,
	HT_INIT_HELP,

	HT_INIT_ERR_TCF,
	HT_INIT_ERR_ARGS,
	HT_INIT_ERR_CONF,
	HT_INIT_ERR_IP,
	HT_INIT_ERR_FILE,
	HT_INIT_ERR_EXIST,
	HT_INIT_ERR_JSON,
	HT_INIT_ERR_CONNECT,
	HT_INIT_ERR_RECV,
	HT_INIT_ERR_REGISTER,
	HT_INIT_ERR_MALLOC,
	HT_INIT_ERR_DB,
	HT_INIT_ERR_LICENSE
};

typedef struct admin_s {
	unsigned char prikey[PRIKEY_LENGTH];
	unsigned char pubkey[PUBKEY_LENGTH];
} admin_t;

int os_sm2_sign(
					IN const unsigned char *msg, IN int msglen,
					IN unsigned char *privkey, IN unsigned int privkey_len,
					IN unsigned char *pubkey, IN unsigned int pubkey_len,
					OUT unsigned char **sig, OUT unsigned int *siglen);


