#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>

#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cJSON.h"

#include "ht_def.h"
#include "ht_util.h"
#include "ht_string.h"
#include "ht_crypt.h"

#define IN
#define OUT

#define AGENT_ID_LEN			32
#define MAX_PACKET_LEN			4096
#define ONCE_MAX_COUNT			800

#define PROGRAM_NAME			"ht_init"
#define HOME_PATH			"/usr/local/httcsec/ttm"
#define DEFAULT_ENCRYPT_KEY		"0123456789ABCDEF"

/* 默认度量时间 10分钟 */
#define DEFAULT_DMEASURE_TIME	(600 * 1000)

#define CHECK_COUNT(real_count, expect_count, ret)	do {		\
														if (real_count != expect_count)	\
															return ret;		\
													} while (0);

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

enum {
	MODE_ONLINE = 0,
	MODE_OFFLINE,
};

typedef struct admin_s {
	unsigned char prikey[PRIKEY_LENGTH];
	unsigned char pubkey[PUBKEY_LENGTH];
} admin_t;

int is_ipv4_valid(char *ip);
void socket_setnonblocking(int sock);
int socket_fd_write(int fd, cJSON *root);
int socket_fd_wait(int fd, struct timeval timeout);
int socket_fd_read(int fd, char **buffer, int *o_buflen);
int create_encrypt_connection(char *agent_id, char *ip, int port, int *fd);
int ht_init_sm2_sign(admin_t *admin, const unsigned char *data, int data_len, unsigned char **sig);
uint64_t ht_init_get_replay_counter();

int ht_init_command_scan(int argc, char **argv);
int ht_init_command_reset(int argc, char **argv);
int ht_init_command_setadmin();
int ht_init_command_setdefaultpolicy(int argc, char **argv);

int os_sm2_generate_key(OUT unsigned char **privkey, OUT unsigned int *privkey_len,
                        OUT unsigned char **pubkey, OUT unsigned int *pubkey_len);
int os_sm2_encrypt(
					    IN unsigned char *plain_text, IN unsigned int plain_text_len,
					    IN unsigned char *pubkey, IN unsigned int pubkey_len,
					    OUT unsigned char **cipher_text, OUT unsigned int *cipher_text_len);
int os_sm2_decrypt(
					    IN unsigned char *cipher_text, IN unsigned int cipher_text_len,
					    IN unsigned char *prikey, IN unsigned int prikey_len,
					    OUT unsigned char **plain_text, OUT unsigned int *plain_text_len);
int os_sm2_sign(
					IN const unsigned char *msg, IN int msglen,
					IN unsigned char *privkey, IN unsigned int privkey_len,
					IN unsigned char *pubkey, IN unsigned int pubkey_len,
					OUT unsigned char **sig, OUT unsigned int *siglen);


