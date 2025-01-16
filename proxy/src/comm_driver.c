#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <asm/poll.h>
#include <comm_driver.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <tpcm_debug.h>
#include <assert.h>

 char *strerror(int errnum) ;
#include "message.h"
//#include "tcm_debug.h"
struct share_memory{
	uint32_t cmd_type;//????????
	int32_t  cmd_length;//???????????

	uint64_t cmd_sequence;//???????§Ü?
	uint64_t cmd_addr_phys;//???????????,????????cmd_header

	volatile uint32_t cmd_handled;//??????????????????????????0,TPCM ??????????1,?????????¦Ä1????cmd_ret?????cmd_handled?????????0??
	int32_t cmd_ret;//?????§Ø???????????TPCM???

	int32_t notify_type;//??????
	int32_t notify_length;//??????
	uint64_t notify_sequence;//????
	uint64_t notify_addr_phys;//????????????TPCM????
	uint32_t notify_pending;//???????????TPCM????????????0????????????1???????????????§Ø???????????0
	uint32_t pad;
	//char data_area[0];//??????????????????????????
} __attribute__((packed));

struct command_info_impl{
	uint32_t cmd_type;
	int32_t  cmd_length;
	uint64_t cmd_sequence;
	uint64_t input_addr;
	uint64_t output_addr;
	int32_t input_length;
	int32_t output_maxlength;
	uint32_t out_length;
	uint32_t out_return;
	MAPObject cmd_map;
	uint64_t cmd_vaddr;
	MAPObject input_map;
	MAPObject output_map;
};

struct cmd_header{
	//???????
	//uint64_t cmd_sequence;?????????????????????????äª?????????????
	uint64_t input_addr;  //??????????
	uint64_t output_addr;	//??????????
	int32_t input_length;  //??????????
	int32_t output_maxlength;//??????????????

	//???????
//	uint64_t cmd_sequence;//???????§Ü??????????????????????????????notify_sequence????
	volatile int out_length; //????????????????????
	volatile int out_return; //??????§ß??

} __attribute__((packed));

enum{

	//NOTIFY_TYPE_SYNC_FINISHED =  0,//??????????????,?????????
	NOTIFY_TYPE_CMD_FINISHED =  1,//?????????????,?????????
	//NOTIFY_TYPE_LOG = 1 << 16, //??????,???????????
	//NOTIFY_TYPE_CMD_CONTROL//??????????
};
#define ERROR_RET -1
#define SHARE_MEM_SIZE 0x1F00000
#define BIOS_OFFSET 0x3c00
#define NOTIFY_DATA_MASK 0xffff
#define NOTIFY_SIMPLE_MASK 0xffff
#define LISTEN_PORT	6666

struct msg_buff{
	uint32_t cmd_type;
	int32_t  cmd_length;
	uint64_t cmd_sequence;
	
	uint64_t cmd_addrnum;
	uint64_t input_addr_num;
	uint64_t output_addr_num;
	int32_t input_length;
	int32_t output_maxlength;

	int32_t res;
	
	struct cmd_header cmd;
	//char input_buff[BMC_BUFF_LENGTH];//tmp
	//char output_buff[BMC_BUFF_LENGTH];//tmp

	unsigned char *total_buff;
};



static COMMAND_NOIFTY notifier;
MAPObject tpcm_share_mobj;
volatile struct share_memory *sharemem;
unsigned long sharemem_addr;
static uint32_t invalid_command_count = 0;
#define NUM_OF_COMMAND_TYPE 16


//static void test_callback_zero(int msgtype, const char *buffer, int length){
//	tpcm_sys_tpcm_debug("buffer:%s,%d, msgtype:%d\n", buffer, length, msgtype);
//}
//void netlink_init(){
//
//	int  sync = 0, type = 1;
//	char message[] = "Open the netlink";
//	int length;
//	length = sizeof(message);
//	httcsec_netlink_send_msg(type, message, length, 0, 0);
//
//
//}

struct notify_info{
	int notify_type;
	unsigned long notify_sequence;
	char buffer[0];
}__attribute__((packed));
//void debug_dump_hex (const void *p, int bytes);
volatile int test_sending = 0;


//---20240311---start
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <asm/poll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/timeb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <openssl/evp.h>

#define HOST_DEV_NAME "/dev/memread_dev"
char *DEV_NAME = "/dev/lcd3";

typedef enum {
    USB_START_TRANS_REQ = 1,
    USB_TRANS_PROCESS,
    USB_TRANS_COMPLETE,
    USB_START_TRANS_STD_MD5_REQ, // ¿¿iBMCv2¿¿¿MD5¿¿¿¿¿MD5¿iBMCv3¿¿¿¿¿¿¿¿¿¿¿¿¿¿MD5¿¿¿¿
    USB_START_TRANS_SHA256_REQ, // ¿¿sha256¿¿¿¿
    USB_START_TRANS_SM3_REQ     // ¿¿sm3¿¿¿¿
} TPCMUsbMsgType;

typedef unsigned long int u_int64_t;
typedef char gchar;
typedef unsigned char guchar;
typedef unsigned char guint8;
typedef signed char gint8;
typedef short gshort;
typedef signed short gint16;
typedef unsigned short guint16;
typedef int gint;
typedef signed int gint32;
typedef unsigned int guint;
typedef unsigned int guint32;
typedef unsigned short gushort;
typedef long glong;
typedef unsigned long gulong;
typedef signed long long gint64;
typedef unsigned long long guint64;
typedef float gfloat;
typedef double gdouble;
typedef gint gboolean;

#define IPMI_MAX_MSG_LENGTH 2060
#define PRINTED_LINE_SIZE_BIT 128
#define PER_READ_LEN 2048

#define PR_SET_NAME 15 /* Set process name */
#define PR_GET_NAME 16 /* Get process name */

typedef struct tag_usb_buffer_info_s {
    guint32 usb_id;   /*¿¿¿¿¿¿¿USB¿*/
    guint32 fn_id;    /*¿¿¿/¿¿¿¿function¿¿¿¿ID¿¿connect¿¿¿¿¿fn_id¿*/
    guint32 len;      /* ¿¿¿¿/¿¿¿¿¿¿¿*/
    guint32 timeout;  /*¿¿/¿¿¿¿¿¿¿¿¿¿0¿¿¿¿¿¿¿¿¿¿¿
      ¿¿¿¿¿¿¿¿us¿¿¿¿¿¿¿¿¿¿MAX_TIMEOUT_US¿¿¿¿¿*/
    guint8 overflow;  /*¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿
                        ¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿1¿¿¿¿¿¿¿¿¿*/
    guint8 splited;   /*  ¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿
                            ¿¿¿¿¿¿¿¿¿¿2¿¿¿¿¿¿¿¿¿¿¿¿1
                            ¿¿¿¿¿¿¿¿¿*/
    guint16 reserved; /*¿¿¿¿*/
    guint32 result;   /*¿¿¿¿¿*/
    guint8 *buf;      /* ¿¿¿¿/¿¿¿¿¿buffer*/
} USB_BUF_INFO_S;

typedef struct _edma_head_Message {
    guint8
        msg_type; // 0x01:¿¿¿¿¿¿¿¿¿?0x02 ¿¿¿¿¿¿¿¿¿¿¿; 0x03: ¿¿¿¿¿? 0x04: ¿¿¿¿¿¿¿¿?¿¿¿¿
    guint8 flag;  // ¿¿¿¿¿¿¿¿
    guint32 data_len; // ¿¿¿¿¿¿¿¿¿¿¿?
    guint32 offset;   // ¿¿¿¿¿¿¿¿¿¿¿¿
} EDMA_MSG_HEAD, *P_EDMA_MSG_HEAD;

// edma msg
typedef struct _EDMA_Request {
    EDMA_MSG_HEAD head_msg;
    guint8 data[IPMI_MAX_MSG_LENGTH - sizeof(EDMA_MSG_HEAD)];
} EDMA_MSG_REQ, *P_EDMA_MSG_REQ;

#define MD5_DIGEST_LEN 16
#define MD5_CTX_STAT_LEN 4
#define MD5_CTX_CNT_LEN 2
#define MD5_CTX_BUF_LEN 64

#define MD5_11 7
#define MD5_12 12
#define MD5_13 17
#define MD5_14 22
#define MD5_21 5
#define MD5_22 9
#define MD5_23 14
#define MD5_24 20
#define MD5_31 4
#define MD5_32 11
#define MD5_33 16
#define MD5_34 23
#define MD5_41 6
#define MD5_42 10
#define MD5_43 15
#define MD5_44 21

typedef guchar *P_BUFFER_T;
typedef gulong UL;

#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~(z))))
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define FF(a, b, c, d, x, s, ac)                                                                                       \
    do {                                                                                                               \
        (a) += F((b), (c), (d)) + (x) + (UL)(ac);                                                                      \
        (a) = ROTATE_LEFT((a), (s));                                                                                   \
        (a) += (b);                                                                                                    \
    } while (0)
#define GG(a, b, c, d, x, s, ac)                                                                                       \
    do {                                                                                                               \
        (a) += G((b), (c), (d)) + (x) + (UL)(ac);                                                                      \
        (a) = ROTATE_LEFT((a), (s));                                                                                   \
        (a) += (b);                                                                                                    \
    } while (0)
#define HH(a, b, c, d, x, s, ac)                                                                                       \
    do {                                                                                                               \
        (a) += H((b), (c), (d)) + (x) + (UL)(ac);                                                                      \
        (a) = ROTATE_LEFT((a), (s));                                                                                   \
        (a) += (b);                                                                                                    \
    } while (0)
#define II(a, b, c, d, x, s, ac)                                                                                       \
    do {                                                                                                               \
        (a) += I((b), (c), (d)) + (x) + (UL)(ac);                                                                      \
        (a) = ROTATE_LEFT((a), (s));                                                                                   \
        (a) += (b);                                                                                                    \
    } while (0)

#if PROTOTYPES
#define PROTOTYPE_LIST(list) list
#else
#define PROTOTYPE_LIST(list) ()
#endif

#define MD5_DIGEST_LEN 16
#define MD5_CTX_STAT_LEN 4
#define MD5_CTX_CNT_LEN 2
#define MD5_CTX_BUF_LEN 64
#define LOCAL static

/* MD5 context. */
typedef struct {
    UL state[MD5_CTX_STAT_LEN];     /* state (ABCD) */
    UL count[MD5_CTX_CNT_LEN];      /* number of bits, modulo 2^64 (lsb first) */
    guchar buffer[MD5_CTX_BUF_LEN]; /* input buffer */
} MD5_CTX;

void MD5Init(MD5_CTX *);
void MD5Update(MD5_CTX *, guchar *, guint);
void MD5Final(guchar[MD5_DIGEST_LEN], MD5_CTX *, guint32 length);
LOCAL void MD5Transform(UL[MD5_CTX_STAT_LEN], guint, guchar[MD5_CTX_BUF_LEN]);

LOCAL guchar g_padding[64] = {0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                              0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                              0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

LOCAL void MD5Transform(UL[MD5_CTX_STAT_LEN], guint, guchar[MD5_CTX_BUF_LEN]);
LOCAL void UL2UC(guchar *, UL *, guint);
LOCAL void UC2UL(UL *, guchar *, guint);
/*****************************************************************************
 ¿ ¿ ¿  : MD5Init
 ¿¿¿¿  : MD5¿¿¿¿¿
 ¿¿¿¿  : MD5_CTX *md5_ctx
 ¿¿¿¿  : ¿
 ¿ ¿ ¿  :

 ¿¿¿¿      :
  1.¿    ¿   : 2012¿5¿11¿
    ¿    ¿   :
    ¿¿¿¿   : ¿¿¿¿¿

*****************************************************************************/
void MD5Init(MD5_CTX *md5_ctx)
{
    md5_ctx->count[0] = md5_ctx->count[1] = 0;

    // ¿¿¿magic number
    md5_ctx->state[0] = 0x67452301;
    md5_ctx->state[1] = 0xefcdab89;
    md5_ctx->state[2] = 0x98badcfe;
    md5_ctx->state[3] = 0x10325476;
}

/*****************************************************************************
 ¿ ¿ ¿  : MD5Update
 ¿¿¿¿  : ¿¿MD5¿¿¿¿¿
 ¿¿¿¿  : MD5_CTX *md5_ctx
             guchar *input
             guint inputLen
 ¿¿¿¿  : ¿
 ¿ ¿ ¿  :

 ¿¿¿¿      :
  1.¿    ¿   : 2012¿5¿11¿
    ¿    ¿   :
    ¿¿¿¿   : ¿¿¿¿¿

*****************************************************************************/
void MD5Update(MD5_CTX *md5_ctx, guchar *input, guint inputLen)
{
    guint i, index, partLen;

    index = (guint)((md5_ctx->count[0] >> 3) & 0x3F);

    if ((md5_ctx->count[0] += ((UL)inputLen << 3)) < ((UL)inputLen << 3)) {
        md5_ctx->count[1]++;
    }

    md5_ctx->count[1] += ((UL)inputLen >> 29);

    partLen = 64 - index;

    if (inputLen >= partLen) {
        memcpy((P_BUFFER_T)&md5_ctx->buffer[index], (P_BUFFER_T)input, partLen);
        MD5Transform(md5_ctx->state, MD5_CTX_STAT_LEN, md5_ctx->buffer);

        for (i = partLen; i + 63 < inputLen; i += 64) {
            MD5Transform(md5_ctx->state, MD5_CTX_STAT_LEN, &input[i]);
        }

        index = 0;
    } else {
        i = 0;
    }
    memcpy((P_BUFFER_T)&md5_ctx->buffer[index], (P_BUFFER_T)&input[i], inputLen - i);
}

/*****************************************************************************
 ¿ ¿ ¿  : MD5Final
 ¿¿¿¿  : ¿¿MD5¿¿¿¿¿
 ¿¿¿¿  : guchar *digest:¿¿buffer
             MD5_CTX *md5_ctx: md5¿¿
             length: buffer¿¿
 ¿¿¿¿  : ¿
 ¿ ¿ ¿  :

 ¿¿¿¿      :
  1.¿    ¿   : 2012¿5¿11¿
    ¿    ¿   :
    ¿¿¿¿   : ¿¿¿¿¿

*****************************************************************************/
void MD5Final(guchar *digest, MD5_CTX *md5_ctx, guint32 length)
{
    guchar bits[8];
    guint index, padLen;

    UL2UC(bits, md5_ctx->count, 8);

    index = (guint)((md5_ctx->count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    MD5Update(md5_ctx, g_padding, padLen);

    MD5Update(md5_ctx, bits, 8);

    UL2UC(digest, md5_ctx->state, length);

    memset((P_BUFFER_T)md5_ctx, 0, sizeof(*md5_ctx));
}

/*****************************************************************************
 ¿ ¿ ¿  : MD5Transform
 ¿¿¿¿  :     MD5¿¿
 ¿¿¿¿  :     UL *state: MD5¿¿
             guint32 state_len: state buffer¿¿
             guchar *block: input buffer
 ¿¿¿¿  :     ¿
 ¿ ¿ ¿  : LOCAL

 ¿¿¿¿      :
  1.¿    ¿   : 2012¿5¿11¿
    ¿    ¿   :
    ¿¿¿¿   : ¿¿¿¿¿

*****************************************************************************/
LOCAL void MD5Transform(UL *state, guint32 state_len, guchar *block)
{
    UL xa;
    UL xb;
    UL xc;
    UL xd;
    UL x[MD5_DIGEST_LEN] = {0};

    if (state_len != MD5_CTX_STAT_LEN) {
        return;
    }

    xa = state[0]; /* 0:¿¿0 */
    xb = state[1]; /* 1:¿¿1 */
    xc = state[2]; /* 2:¿¿2 */
    xd = state[3]; /* 3:¿¿3 */

    UC2UL(x, block, 64);

    /* Round 1 */
    FF(xa, xb, xc, xd, x[0], MD5_11, 0xd76aa478);  /* 0:¿¿¿¿¿¿¿1 */
    FF(xd, xa, xb, xc, x[1], MD5_12, 0xe8c7b756);  /* 1:¿¿¿¿¿¿¿2 */
    FF(xc, xd, xa, xb, x[2], MD5_13, 0x242070db);  /* 2:¿¿¿¿¿¿¿3 */
    FF(xb, xc, xd, xa, x[3], MD5_14, 0xc1bdceee);  /* 3:¿¿¿¿¿¿¿4 */
    FF(xa, xb, xc, xd, x[4], MD5_11, 0xf57c0faf);  /* 4:¿¿¿¿¿¿¿5 */
    FF(xd, xa, xb, xc, x[5], MD5_12, 0x4787c62a);  /* 5:¿¿¿¿¿¿¿6 */
    FF(xc, xd, xa, xb, x[6], MD5_13, 0xa8304613);  /* 6:¿¿¿¿¿¿¿7 */
    FF(xb, xc, xd, xa, x[7], MD5_14, 0xfd469501);  /* 7:¿¿¿¿¿¿¿8 */
    FF(xa, xb, xc, xd, x[8], MD5_11, 0x698098d8);  /* 8:¿¿¿¿¿¿¿9 */
    FF(xd, xa, xb, xc, x[9], MD5_12, 0x8b44f7af);  /* 9:¿¿¿¿¿¿¿10 */
    FF(xc, xd, xa, xb, x[10], MD5_13, 0xffff5bb1); /* 10:¿¿¿¿¿¿¿11 */
    FF(xb, xc, xd, xa, x[11], MD5_14, 0x895cd7be); /* 11:¿¿¿¿¿¿¿12 */
    FF(xa, xb, xc, xd, x[12], MD5_11, 0x6b901122); /* 12:¿¿¿¿¿¿¿13 */
    FF(xd, xa, xb, xc, x[13], MD5_12, 0xfd987193); /* 13:¿¿¿¿¿¿¿14 */
    FF(xc, xd, xa, xb, x[14], MD5_13, 0xa679438e); /* 14:¿¿¿¿¿¿¿15 */
    FF(xb, xc, xd, xa, x[15], MD5_14, 0x49b40821); /* 15:¿¿¿¿¿¿¿16 */

    /* Round 2 */
    GG(xa, xb, xc, xd, x[1], MD5_21, 0xf61e2562);  /* 1:¿¿¿¿¿¿¿17 */
    GG(xd, xa, xb, xc, x[6], MD5_22, 0xc040b340);  /* 6:¿¿¿¿¿¿¿18 */
    GG(xc, xd, xa, xb, x[11], MD5_23, 0x265e5a51); /* 11:¿¿¿¿¿¿¿19 */
    GG(xb, xc, xd, xa, x[0], MD5_24, 0xe9b6c7aa);  /* 0:¿¿¿¿¿¿¿20 */
    GG(xa, xb, xc, xd, x[5], MD5_21, 0xd62f105d);  /* 5:¿¿¿¿¿¿¿21 */
    GG(xd, xa, xb, xc, x[10], MD5_22, 0x2441453);  /* 10:¿¿¿¿¿¿¿22 */
    GG(xc, xd, xa, xb, x[15], MD5_23, 0xd8a1e681); /* 15:¿¿¿¿¿¿¿23 */
    GG(xb, xc, xd, xa, x[4], MD5_24, 0xe7d3fbc8);  /* 4:¿¿¿¿¿¿¿24 */
    GG(xa, xb, xc, xd, x[9], MD5_21, 0x21e1cde6);  /* 9:¿¿¿¿¿¿¿25 */
    GG(xd, xa, xb, xc, x[14], MD5_22, 0xc33707d6); /* 14:¿¿¿¿¿¿¿26 */
    GG(xc, xd, xa, xb, x[3], MD5_23, 0xf4d50d87);  /* 3:¿¿¿¿¿¿¿27 */
    GG(xb, xc, xd, xa, x[8], MD5_24, 0x455a14ed);  /* 8:¿¿¿¿¿¿¿28 */
    GG(xa, xb, xc, xd, x[13], MD5_21, 0xa9e3e905); /* 13:¿¿¿¿¿¿¿29 */
    GG(xd, xa, xb, xc, x[2], MD5_22, 0xfcefa3f8);  /* 2:¿¿¿¿¿¿¿30 */
    GG(xc, xd, xa, xb, x[7], MD5_23, 0x676f02d9);  /* 7:¿¿¿¿¿¿¿31 */
    GG(xb, xc, xd, xa, x[12], MD5_24, 0x8d2a4c8a); /* 12:¿¿¿¿¿¿¿32 */

    /* Round 3 */
    HH(xa, xb, xc, xd, x[5], MD5_31, 0xfffa3942);  /* 5:¿¿¿¿¿¿¿33 */
    HH(xd, xa, xb, xc, x[8], MD5_32, 0x8771f681);  /* 8:¿¿¿¿¿¿¿34 */
    HH(xc, xd, xa, xb, x[11], MD5_33, 0x6d9d6122); /* 11:¿¿¿¿¿¿¿35 */
    HH(xb, xc, xd, xa, x[14], MD5_34, 0xfde5380c); /* 14:¿¿¿¿¿¿¿36 */
    HH(xa, xb, xc, xd, x[1], MD5_31, 0xa4beea44);  /* 1:¿¿¿¿¿¿¿37 */
    HH(xd, xa, xb, xc, x[4], MD5_32, 0x4bdecfa9);  /* 4:¿¿¿¿¿¿¿38 */
    HH(xc, xd, xa, xb, x[7], MD5_33, 0xf6bb4b60);  /* 7:¿¿¿¿¿¿¿39 */
    HH(xb, xc, xd, xa, x[10], MD5_34, 0xbebfbc70); /* 10:¿¿¿¿¿¿¿40 */
    HH(xa, xb, xc, xd, x[13], MD5_31, 0x289b7ec6); /* 13:¿¿¿¿¿¿¿41 */
    HH(xd, xa, xb, xc, x[0], MD5_32, 0xeaa127fa);  /* 0:¿¿¿¿¿¿¿42 */
    HH(xc, xd, xa, xb, x[3], MD5_33, 0xd4ef3085);  /* 3:¿¿¿¿¿¿¿43 */
    HH(xb, xc, xd, xa, x[6], MD5_34, 0x4881d05);   /* 6:¿¿¿¿¿¿¿44 */
    HH(xa, xb, xc, xd, x[9], MD5_31, 0xd9d4d039);  /* 9:¿¿¿¿¿¿¿45 */
    HH(xd, xa, xb, xc, x[12], MD5_32, 0xe6db99e5); /* 12:¿¿¿¿¿¿¿46 */
    HH(xc, xd, xa, xb, x[15], MD5_33, 0x1fa27cf8); /* 15:¿¿¿¿¿¿¿47 */
    HH(xb, xc, xd, xa, x[2], MD5_34, 0xc4ac5665);  /* 2:¿¿¿¿¿¿¿48 */

    /* Round 4 */
    II(xa, xb, xc, xd, x[0], MD5_41, 0xf4292244);  /* 0:¿¿¿¿¿¿¿49 */
    II(xd, xa, xb, xc, x[7], MD5_42, 0x432aff97);  /* 7:¿¿¿¿¿¿¿50 */
    II(xc, xd, xa, xb, x[14], MD5_43, 0xab9423a7); /* 14:¿¿¿¿¿¿¿51 */
    II(xb, xc, xd, xa, x[5], MD5_44, 0xfc93a039);  /* 5:¿¿¿¿¿¿¿52 */
    II(xa, xb, xc, xd, x[12], MD5_41, 0x655b59c3); /* 12:¿¿¿¿¿¿¿53 */
    II(xd, xa, xb, xc, x[3], MD5_42, 0x8f0ccc92);  /* 3:¿¿¿¿¿¿¿54 */
    II(xc, xd, xa, xb, x[10], MD5_43, 0xffeff47d); /* 10:¿¿¿¿¿¿¿55 */
    II(xb, xc, xd, xa, x[1], MD5_44, 0x85845dd1);  /* 1:¿¿¿¿¿¿¿56 */
    II(xa, xb, xc, xd, x[8], MD5_41, 0x6fa87e4f);  /* 8:¿¿¿¿¿¿¿57 */
    II(xd, xa, xb, xc, x[15], MD5_42, 0xfe2ce6e0); /* 15:¿¿¿¿¿¿¿58 */
    II(xc, xd, xa, xb, x[6], MD5_43, 0xa3014314);  /* 6:¿¿¿¿¿¿¿59 */
    II(xb, xc, xd, xa, x[13], MD5_44, 0x4e0811a1); /* 13:¿¿¿¿¿¿¿60 */
    II(xa, xb, xc, xd, x[4], MD5_41, 0xf7537e82);  /* 4:¿¿¿¿¿¿¿61 */
    II(xd, xa, xb, xc, x[11], MD5_42, 0xbd3af235); /* 11:¿¿¿¿¿¿¿62 */
    II(xc, xd, xa, xb, x[2], MD5_43, 0x2ad7d2bb);  /* 2:¿¿¿¿¿¿¿63 */
    II(xb, xc, xd, xa, x[9], MD5_44, 0xeb86d391);  /* 9:¿¿¿¿¿¿¿64 */

    state[0] += xa; /* 0:¿¿0 */
    state[1] += xb; /* 1:¿¿1 */
    state[2] += xc; /* 2:¿¿2 */
    state[3] += xd; /* 3:¿¿3 */

    memset((P_BUFFER_T)x, 0, sizeof(x));
}

/*****************************************************************************
 ¿ ¿ ¿  : UL2UC
 ¿¿¿¿  : ¿gulong¿¿¿¿¿guchar¿¿
 ¿¿¿¿  : guchar *output
             UL *input
             guint len
 ¿¿¿¿  : ¿
 ¿ ¿ ¿  : LOCAL

 ¿¿¿¿      :
  1.¿    ¿   : 2012¿5¿11¿
    ¿    ¿   :
    ¿¿¿¿   : ¿¿¿¿¿

*****************************************************************************/
LOCAL void UL2UC(guchar *output, UL *input, guint len)
{
    guint i, j;

    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = (guchar)(input[i] & 0xff);
        output[j + 1] = (guchar)((input[i] >> 8) & 0xff);  /*lint !e661*/
        output[j + 2] = (guchar)((input[i] >> 16) & 0xff); /*lint !e661 !e662*/
        output[j + 3] = (guchar)((input[i] >> 24) & 0xff); /*lint !e661 !e662*/
    }
}

/*****************************************************************************
 ¿ ¿ ¿  : UC2UL
 ¿¿¿¿  : ¿guchar¿¿¿¿¿gulong¿¿
 ¿¿¿¿  : UL *output
             guchar *input
             guint len
 ¿¿¿¿  : ¿
 ¿ ¿ ¿  : LOCAL
 ¿¿¿¿  :

 ¿¿¿¿      :
  1.¿    ¿   : 2012¿5¿11¿
    ¿    ¿   :
    ¿¿¿¿   : ¿¿¿¿¿

*****************************************************************************/
LOCAL void UC2UL(UL *output, guchar *input, guint len)
{
    guint i, j;

    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[i] = ((UL)input[j]) | (((UL)input[j + 1]) << 8) |             /*lint !e661 !e662*/
                    (((UL)input[j + 2]) << 16) | (((UL)input[j + 3]) << 24); /*lint !e661 !e662*/
    }
}
guchar g_digest[32];
guint g_digest_len = 0;
int md5check(const char *buf, int inputlen)
{
    memset(g_digest, 0, 32);
    gchar encodedDigest[25];
    MD5_CTX context;
    guint32 i;
    gchar *p = NULL;
    MD5Init(&context);
    MD5Update(&context, buf, inputlen);
    MD5Final(g_digest, &context, MD5_DIGEST_LEN);
    g_digest_len = MD5_DIGEST_LEN;
}

/* ============================= MD5¿¿¿¿¿openssl¿¿¿¿ ============================= */
static void md5check_std(guint8 *buf, gint32 inputlen)
{
    memset(g_digest, 0, 32);
    EVP_MD_CTX *mdctx;
    guint32 md5_digest_len = (guint32)EVP_MD_size(EVP_md5());

    // MD5_Init
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);

    // MD5_Update
    EVP_DigestUpdate(mdctx, buf, inputlen);

    // MD5_Final
    guint8 *md5_digest = (guint8 *)OPENSSL_malloc(md5_digest_len);
    EVP_DigestFinal_ex(mdctx, md5_digest, &md5_digest_len);
    EVP_MD_CTX_free(mdctx);

    memcpy(g_digest, md5_digest, md5_digest_len);
    OPENSSL_free(md5_digest);
    g_digest_len = md5_digest_len;
}

/*
 * Description: ¿¿sm3
 */
static void sm3hash(unsigned char *input, unsigned int input_len)
{
    memset(g_digest, 0, 32);
    EVP_MD_CTX *md_ctx;
    const EVP_MD *md;

    md = EVP_sm3();
    md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, input, input_len);
    EVP_DigestFinal_ex(md_ctx, g_digest, &g_digest_len);
    EVP_MD_CTX_free(md_ctx);
}

/*
 * Description: ¿¿sha256
 */
static void sha256hash(unsigned char *input, unsigned int input_len)
{
    memset(g_digest, 0, 32);
    EVP_MD_CTX *md_ctx;
    const EVP_MD *md;

    md = EVP_sha256();
    md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, input, input_len);
    EVP_DigestFinal_ex(md_ctx, g_digest, &g_digest_len);
    EVP_MD_CTX_free(md_ctx);
}

unsigned long DEV_ADDR = 0;
unsigned long DATA_LEN = 0;

int ADDR_LEN = 0;
guint8 *COM_DATA = NULL;
unsigned int OFFSET = 0;

int g_edmaUsbFd = -1;
int trans_len = 0;

int prepare_data(EDMA_MSG_REQ msg_read, TPCMUsbMsgType msg_type)
{
    FILE *file_handle = NULL;
    time_t tmpcal_ptr;
    struct tm *tmp_ptr = NULL;
    memcpy(&DEV_ADDR, msg_read.data, sizeof(unsigned long));
    //printf("addr = 0x%lx ", DEV_ADDR);

    memcpy(&DATA_LEN, msg_read.data + sizeof(unsigned long), sizeof(unsigned long));
    //printf("datalen = %lu\n", DATA_LEN);

    COM_DATA = (guint8 *)malloc(DATA_LEN);
    memset(COM_DATA, 0, DATA_LEN);

    int fd = open(HOST_DEV_NAME, O_RDONLY);
    if (fd == -1) {
        printf("file %s is opening......failure!", HOST_DEV_NAME);
        return -1;
    } else {
        //printf("file %s is opening......successfully!\nits fd is %d\n", HOST_DEV_NAME, fd);
    }
    int ret = 0;

    unsigned long cur_len = DATA_LEN;
    unsigned long cur_pos = DEV_ADDR;
    guint8 *tmp_buf = COM_DATA;

    while (0 < cur_len) {
        if (cur_len < PER_READ_LEN) {
            ret = ioctl(fd, 0, cur_pos);
            ret = ioctl(fd, 1, cur_len);
            ret = read(fd, tmp_buf, cur_len);
            if (ret == -1) {
                goto error;
            }
            cur_len = cur_len - cur_len;
            tmp_buf = tmp_buf + cur_len;
            cur_pos = cur_pos + cur_len;
        } else {
            ret = ioctl(fd, 0, cur_pos);
            ret = ioctl(fd, 1, PER_READ_LEN);
            ret = read(fd, tmp_buf, PER_READ_LEN);
            if (ret == -1) {
                goto error;
            }
            cur_len = cur_len - PER_READ_LEN;
            tmp_buf = tmp_buf + PER_READ_LEN;
            cur_pos = cur_pos + PER_READ_LEN;
        }
    }
    if (msg_type == USB_START_TRANS_REQ) {
        md5check(COM_DATA, DATA_LEN);
    } else if (msg_type == USB_START_TRANS_STD_MD5_REQ) {
        md5check_std(COM_DATA, DATA_LEN);
    } else if (msg_type == USB_START_TRANS_SHA256_REQ) {
        sha256hash(COM_DATA, DATA_LEN);
    } else if (msg_type == USB_START_TRANS_SM3_REQ) {
        sm3hash(COM_DATA, DATA_LEN);
    } else {
        //printf("msg_type(%d) cannot support to calculate md5\n", msg_type);
        goto error;
    }
    //printf("total digest(type: %d):\n", msg_type);
    for (int i = 0; i < g_digest_len; i++) {
        //printf("%02x ", g_digest[i]);
    }
    //printf("\n");

    close(fd);
    return 0;
error:
    close(fd);
    return -2;
}

int send_response(int prepare) //
{
    int prepare_stat = 0x00;
    if (prepare == 0) {
        prepare_stat = 0x00;
    } else if (prepare == -1) {
        prepare_stat = 0x01;
    } else {
        prepare_stat = 0x02;
    }

    EDMA_MSG_REQ msg_write = {0};
    msg_write.head_msg.msg_type = 0x01;
    msg_write.head_msg.flag = prepare_stat;
    msg_write.head_msg.offset = 0x00;
    msg_write.head_msg.data_len = 0;

    gint32 ret = write(g_edmaUsbFd, &msg_write, sizeof(EDMA_MSG_HEAD));
    return ret;
}

guint8 pmbus_crc8_make_bitwise(const guint8 *buf, guint16 size)
{
#define CHAR_BITS 8
#define CRC8_POLY 0x07
#define CRC8_INIT_REM 0x0
    guint16 i;
    guint8 j;
    guint8 crc = CRC8_INIT_REM;

    for (i = 0; i < size; i++) {
        crc ^= buf[i];

        for (j = 0; j < CHAR_BITS; j++) { /* ¿ byte ¿ bit ¿¿ */
            if (crc & 0x80) {
                crc <<= 1;
                crc ^= CRC8_POLY;
            } else {
                crc <<= 1;
            }
        }
    }

    return crc;
}

int write_data()
{
    EDMA_MSG_HEAD msg_hdr = {0};
    msg_hdr.msg_type = 0x02;
    guint8 checksum;
    int max_data_len = IPMI_MAX_MSG_LENGTH - sizeof(EDMA_MSG_HEAD);
    int digest_len = g_digest_len;

    int remain_data_len = DATA_LEN - OFFSET; // ¿¿¿¿¿¿¿?
    if (remain_data_len <= max_data_len) {
        trans_len = remain_data_len + digest_len;
        msg_hdr.flag = 0x01;
    } else {
        trans_len = max_data_len;
        msg_hdr.flag = 0x00;
    }

    msg_hdr.offset = OFFSET;
    msg_hdr.data_len = trans_len;

    int ret = write(g_edmaUsbFd, &msg_hdr, sizeof(EDMA_MSG_HEAD));

    guint8 *msg_data = (guint8 *)malloc(trans_len);
    if (msg_hdr.flag == 0x01) {
        for (int i = 0; i < digest_len; i++) {
            msg_data[trans_len - digest_len + i] = g_digest[i];
        }
        for (int i = trans_len - digest_len; i > 0; i--) {
            msg_data[trans_len - digest_len - i] = COM_DATA[OFFSET + trans_len - digest_len - i];
        }
    } else {
        for (int i = trans_len; i > 0; i--) {
            msg_data[trans_len - i] = COM_DATA[OFFSET + trans_len - i];
        }
    }

    ret = write(g_edmaUsbFd, msg_data, trans_len);
    free(msg_data);
    OFFSET = OFFSET + trans_len; // ¿¿¿¿¿¿¿¿¿?
}

void EdmaUsbLcd2ReadTask(void)
{
    gint32 ret = -1;
    USB_BUF_INFO_S buff_info;
    gchar edma_buf[40] = {0};
    EDMA_MSG_REQ msg_read = {0};
    int retry = 0;

    struct pollfd client = {};
    client.fd = g_edmaUsbFd;
    client.events = POLLRDNORM | POLLIN;
    //printf("listening on %s ... \n", DEV_NAME);
    unsigned char *pp;

    while (1) {
        ret = poll(&client, 1, 1000);
        if (ret) {
            if (client.revents & client.events) {
                ret = read(g_edmaUsbFd, &msg_read.head_msg, sizeof(EDMA_MSG_HEAD));
                if (ret < 0) {
                    retry++;

                    if (retry >= 3) {
                        //printf("close\n");
                        close(g_edmaUsbFd);
                        DEV_ADDR = 0;
                        DATA_LEN = 0;
                        OFFSET = 0;
                        if (COM_DATA != NULL) {
                            free(COM_DATA);
                            COM_DATA = NULL;
                        }
                        return;
                    }

                    continue;
                } else if (ret > 0) {
                    if (msg_read.head_msg.data_len > 0) {
                        read(g_edmaUsbFd, msg_read.data, 2 * sizeof(gulong));
                    }

                    if (msg_read.head_msg.msg_type == USB_START_TRANS_REQ ||
                        msg_read.head_msg.msg_type == USB_START_TRANS_STD_MD5_REQ ||
                        msg_read.head_msg.msg_type == USB_START_TRANS_SHA256_REQ ||
                        msg_read.head_msg.msg_type ==
                            USB_START_TRANS_SM3_REQ) { // ¿¿¿¿¿¿¿?x01¿¿¿¿¿¿¿¿¿¿¿¿¿¿
                        int prepare =
                            prepare_data(msg_read, msg_read.head_msg.msg_type); // prepare 0¿¿¿¿¿¿¿?¿¿¿¿¿¿
                        send_response(prepare);
		    } else if (msg_read.head_msg.msg_type ==
				    USB_TRANS_PROCESS) { // ¿¿¿¿¿¿¿?x02¿¿¿¿¿¿¿¿¿¿¿
			    write_data();
		    } else if (msg_read.head_msg.msg_type ==
				    USB_TRANS_COMPLETE) { // ¿¿¿¿¿?x03¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿?
			    DEV_ADDR = 0;
			    DATA_LEN = 0;
			    OFFSET = 0;
			    if (COM_DATA != NULL) {
				    free(COM_DATA);
				    COM_DATA = NULL;
			    }
			    close(g_edmaUsbFd);
			    g_edmaUsbFd = -1;
			    return;
		    } else { // ¿¿¿¿¿¿¿¿¿?
			     //printf("The request code is incorrect: 0x%x", msg_read.head_msg.msg_type);
			    return;
		    }
		}
	    }
	}
    }
}

void ready_to_usb()
{
    char s1[30] = {0};
    char s2[30] = {0};
    char s3[30] = {0};
    while (1) {
        g_edmaUsbFd = open(DEV_NAME, O_RDWR | O_NONBLOCK);
        if (g_edmaUsbFd < 0) {
            sleep(1);
            continue;
        }
        break;
    }

    EdmaUsbLcd2ReadTask();

    //printf("end\n");
}

int main_loop()
{
    while (1) {
        int fd = open("usblockfile", O_RDWR | O_CREAT, 0666);
        if (fd == -1) {
            printf("open fail, errno = %d:%s\n", errno, strerror(errno));
            sleep(5);
            continue;
        }

        if (flock(fd, LOCK_EX) == -1) {
            printf("flock fail, errno = %d:%s\n", errno, strerror(errno));
            close(fd);
            sleep(5);
            continue;
        }

        // ¿¿¿¿¿¿¿¿¿
        //printf("start open usb\n");
        ready_to_usb();
        sleep(1);

        flock(fd, LOCK_UN);
        close(fd);
    }
}

//---20240311---end



 int socket_tcpsocket_connect(char *ip, int port)
 {				 
	 assert(ip);	 
 
	 struct sockaddr_in serveraddr;
	 struct timeval tm = {1, 0};
	 socklen_t len = sizeof(tm);
 
	 int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	 
	 if (sockfd < 0)
		 return -1;
 
	 setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tm, len);
	 
	 bzero(&serveraddr, sizeof(struct sockaddr_in));
	 serveraddr.sin_family = AF_INET;
	 serveraddr.sin_addr.s_addr = inet_addr(ip);
	 serveraddr.sin_port = htons(port);
 
	 if (connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(struct sockaddr_in)) < 0) {
		 close(sockfd);
		 tpcm_debug( "connect fail, server IP :%s, port :%d, errmsg: %s", ip, port, strerror(errno));
		 printf( "connect fail, server IP :%s, port :%d, errmsg: %s %ld\n", ip, port, strerror(errno),time(NULL));
		 return -1;
	 }
		 
	 tpcm_debug("new connect to server IP :%s, port :%d, fd: %d", ip, port, sockfd);
	 printf("new connect to server IP :%s, port :%d, fd: %d\n", ip, port, sockfd);
	 return sockfd; 
 }

#if  0 
 int socket_tcpv6socket_connect(char *ip, int port)
 {				 
	 assert(ip);	 
 
	 struct sockaddr_in6 serveraddr;
	 struct timeval tm = {1, 0};
	 socklen_t len = sizeof(tm);
 
	 int sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	 
	 if (sockfd < 0)
		 return -1;
 
	 setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tm, len);
	 
	 bzero(&serveraddr, sizeof(struct sockaddr_in6));
	 serveraddr.sin6_family = AF_INET6;
	 //serveraddr.sin_addr.s_addr = inet_addr(ip);
	 inet_pton(AF_INET6, ip, &serveraddr.sin6_addr);
	 serveraddr.sin6_port = htons(port);
	 serveraddr.sin6_scope_id = if_nametoindex("enp125s0f3");
 
	 if (connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(struct sockaddr_in)) < 0) {
		 close(sockfd);
		 printf( "connect fail, server IP :%s, port :%d, errmsg: %s", ip, port, strerror(errno));
		 return -1;
	 }
		 
	 tpcm_debug("new connect to server IP :%s, port :%d, fd: %d", ip, port, sockfd);
	 return sockfd; 
 }
#else

int socket_tcpv6socket_connect(char *ip, int port)
{
	int sk;
	int ret = 0;
	int retry = 0;
	struct sockaddr_in6 addr;

	//struct sockaddr_in6 laddr;

	sk = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		return -1; 
	}   

//	memset(&laddr, 0, sizeof(laddr));
	//laddr.sin6_family = AF_INET6;
	//laddr.sin6_port = htons(8092);
	//laddr.sin6_scope_id = if_nametoindex("veth");
	//ret = inet_pton(AF_INET6, "fe80::9e7d:a3ff:fe28:6ff9", &laddr.sin6_addr);
	//if (ret <= 0) {
//		printf("Can't convert addr\n");
//		return -1; 
//	}

//	if(bind(sk,(struct sockaddr_in6*)&laddr,sizeof(struct sockaddr_in6)) != 0){
//		printf("can't connect local ipv6 addr\n");
//		close(sk);
//		return -1;
//	}

	//printf("Connecting to %s:%d\n", ip, port);
	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	ret = inet_pton(AF_INET6, ip, &addr.sin6_addr);
	if (ret <= 0) {
		printf("Can't convert addr\n");
		return -1; 
	}   
	addr.sin6_port = htons(port);
	//addr.sin6_scope_id = if_nametoindex("enp125s0f3");
	addr.sin6_scope_id = if_nametoindex("veth");

	tpcm_debug("before connect ,ip %s,port %d\n",ip,port);
	ret = connect(sk, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		tpcm_debug("Can't connect,ip %s,port %d, err:%s\n",ip,port,strerror(errno));
	}   


	tpcm_debug("connect,ip %s,port %d\n",ip,port);

	return sk;

}

#endif



 void os_handle(int msgtype, const char *buffer, int length){

	unsigned char cmd[1024] = {0};
	uint64_t cmd_addr_phys;
	int bmc_sockfd = 0;
	struct command_info_impl info;
	MAPObject mobj = NULL;
	struct cmd_header *vadrr =NULL;
	memset(&info,0,sizeof(info));
	info.cmd_sequence = sharemem->cmd_sequence;
	info.cmd_type = sharemem->cmd_type;
	if(info.cmd_type == TDD_CMD_CATEGORY_INIT)
		info.cmd_type = TDD_CMD_CATEGORY_TPCM;
	info.cmd_length = sharemem->cmd_length;
	cmd_addr_phys = sharemem->cmd_addr_phys;
	tpcm_debug("Normal Command type=%u seq = %lx, addr = %lx,length=%u\n",info.cmd_type,
			info.cmd_sequence,cmd_addr_phys,info.cmd_length);
	


	

	if(info.cmd_type == TDD_CMD_CATEGORY_RESERVED_4){
				tpcm_error("Invalid command type=%u seq = %lx, addr = %lx,length=%u\n",info.cmd_type,
				info.cmd_sequence,cmd_addr_phys,info.cmd_length);
				sharemem->cmd_ret =  TPCM_ERROR_INVALID_COMMAND;
				//asm volatile ("dsb st");
				sharemem->cmd_handled = 1;
				invalid_command_count++;
				test_sending = 1;
				//asm volatile ("dsb st");
				//return ;
	}

	if(!cmd_addr_phys || !info.cmd_length  || info.cmd_length  > 0x200000){
		tpcm_error("Invalid command type=%u seq = %lx, addr = %lx,length=%u\n",info.cmd_type,
				info.cmd_sequence,cmd_addr_phys,info.cmd_length);
		sharemem->cmd_ret =  TPCM_ERROR_INVALID_COMMAND;
		//asm volatile ("dsb st");
		sharemem->cmd_handled = 1;
		invalid_command_count++;
		//asm volatile ("dsb st");
		return ;
	}

	if(info.cmd_type >= NUM_OF_COMMAND_TYPE){
		tpcm_error("Unsuppored CMD type %u\n",info.cmd_type);
		sharemem->cmd_ret = TPCM_ERROR_UNSUPPORTED_CMD_TYPE;
		//asm volatile ("dsb st");
		sharemem->cmd_handled = 1;
		invalid_command_count++;
		//asm volatile ("dsb st");
		return ;
	}
	mobj = tpcm_sys_map(cmd_addr_phys,info.cmd_length,(void **)&vadrr);
	if(!mobj){
		tpcm_error("Map Address fail %lx \n",cmd_addr_phys);
		sharemem->cmd_ret =  TPCM_ERROR_INVALID_COMMAND;
		//asm volatile ("dsb st");
		sharemem->cmd_handled = 1;
		invalid_command_count++;
		//asm volatile ("dsb st");
		tpcm_sys_unmap(mobj);
		return ;
	}
	info.cmd_map = mobj;
	info.input_addr = vadrr->input_addr;
	info.input_length = vadrr->input_length;
	info.output_addr = vadrr->output_addr;
	info.output_maxlength = vadrr->output_maxlength;
	info.cmd_vaddr = (uint64_t)vadrr;
	tpcm_debug("Sync command type=%u seq = %lx, in addr = %lx,in length=%u,out addr = %lx,out max length=%u\n",info.cmd_type,
					info.cmd_sequence,info.input_addr,info.input_length,
					info.output_addr,info.output_maxlength
					);

#if 1 
	int send_header_len = 0;
	int send_body_len = 0;
	struct msg_buff send_msg;
	int recv_header_len = 0;
	int recv_body_len = 0;
	struct msg_buff recv_msg;
	unsigned char* recv_total_buff = NULL;

	

	memset(&send_msg, 0 ,sizeof(struct msg_buff));
	memset(&recv_msg, 0 ,sizeof(struct msg_buff));
	
	send_msg.cmd_type = sharemem->cmd_type;
	send_msg.cmd_length = sharemem->cmd_length;
	send_msg.cmd_sequence = sharemem->cmd_sequence;

	send_msg.cmd_addrnum = sharemem->cmd_addr_phys;
	send_msg.input_addr_num = vadrr->input_addr;
	send_msg.output_addr_num = vadrr->output_addr;

	send_msg.input_length = vadrr->input_length;
	send_msg.output_maxlength = vadrr->output_maxlength;
	
	memset(&send_msg.cmd,0,sizeof(struct cmd_header));
	memcpy(&send_msg.cmd,vadrr,sizeof(struct cmd_header));

#if  0
	memset(send_msg.input_buff,0,sizeof(send_msg.input_buff));
	memcpy(send_msg.input_buff,sharemem_addr+vadrr->input_addr,vadrr->input_length);

	memset(send_msg.output_buff,-1,sizeof(send_msg.output_buff));
	memcpy(send_msg.output_buff,sharemem_addr+vadrr->output_addr,vadrr->output_maxlength);
#endif

	send_msg.total_buff = malloc(vadrr->input_length+vadrr->output_maxlength);
	if(send_msg.total_buff){
		memcpy(send_msg.total_buff,sharemem_addr+vadrr->input_addr,vadrr->input_length);
		memcpy(send_msg.total_buff+vadrr->input_length,sharemem_addr+vadrr->output_addr,vadrr->output_maxlength);
	}

        tpcm_debug("test buffer info\n");
        tpcm_debug("Sync command type=%u seq = %lx, in addr = %lx,in length=%u,out addr = %lx,out max length=%u\n",info.cmd_type,
                                        info.cmd_sequence,info.input_addr,info.input_length,
                                        info.output_addr,info.output_maxlength
		  );  
	tpcm_debug("cmd_header addr %lx,cmd_header len %d\n",sharemem->cmd_addr_phys,sharemem->cmd_length);



	void *input = NULL;
	void *output = NULL;

	int recv_total_len = 0;
	int read_len = 0;


	tpcm_comm_map_address(&info,&input,&output);
	tpcm_debug("cmd tag %lu,cmd len %lu, cmd uicode %lu\n",ntohl(*(uint32_t*)input),ntohl(*(uint32_t*)(input+4)),ntohl(*(uint32_t*)(input+8)));


#if  0 
	bmc_sockfd = socket_tcpsocket_connect("127.0.0.1", LISTEN_PORT);
#else
	//bmc_sockfd = socket_tcpv6socket_connect("fe80::47aa:c942:597f:2460", LISTEN_PORT);
	bmc_sockfd = socket_tcpv6socket_connect("fe80::9e7d:a3ff:fe28:6ffa", LISTEN_PORT);
#endif

	if(bmc_sockfd > 0){




		send_header_len = write(bmc_sockfd,&send_msg,sizeof(struct msg_buff));
		

		send_body_len = write(bmc_sockfd,send_msg.total_buff,vadrr->input_length+vadrr->output_maxlength);



		tpcm_debug("send buffer length %d, header len %d, body len %d\n",send_header_len+send_body_len,send_header_len,send_body_len);
	}else{

		tpcm_debug("connect failed\n");
		goto out;
	}	

	free(send_msg.total_buff);
	memset(&send_msg, 0 ,sizeof(struct msg_buff));


	recv_header_len = read(bmc_sockfd,&recv_msg,sizeof(struct msg_buff));
	

	vadrr->out_length = recv_msg.cmd.out_length;
	vadrr->out_return = recv_msg.cmd.out_return;

	if(recv_msg.input_length + recv_msg.output_maxlength){
		tpcm_debug("TTTT recv total length %d,input len %d,output len %d\n",recv_msg.input_length + recv_msg.output_maxlength,recv_msg.input_length,recv_msg.output_maxlength);
		tpcm_debug("TTTT recv output addr  %lx\n",recv_msg.output_addr_num);
		recv_total_buff = malloc(recv_msg.input_length + recv_msg.output_maxlength);

		if(recv_total_buff){
			int tmp = 0;
			memset(recv_total_buff,0,recv_msg.input_length + recv_msg.output_maxlength);
			read_len = read(bmc_sockfd,recv_total_buff,recv_msg.input_length + recv_msg.output_maxlength);				

			recv_total_len = read_len;

			while((recv_total_len < (recv_msg.input_length + recv_msg.output_maxlength)) && (read_len > 0)){
				
				tpcm_debug("TtTT recv output addr  %lx %d %d\n",recv_msg.output_addr_num,recv_total_len,read_len);
				read_len = read(bmc_sockfd,recv_total_buff+recv_total_len,recv_msg.input_length + recv_msg.output_maxlength-recv_total_len);				
				recv_total_len += read_len;
			}

			memcpy(sharemem_addr + recv_msg.output_addr_num,recv_total_buff+recv_msg.input_length,recv_msg.output_maxlength);
			sharemem->cmd_ret = recv_msg.res;
			sharemem->cmd_handled = 1;


#if 1 
			for(int tmp = 0;tmp<12;tmp++){
				tpcm_debug("%02x ",*(char*)(recv_total_buff+tmp));
			}
			free(recv_total_buff);

#endif

#if 1 
			for(int tmp = 0;tmp<12;tmp++){
				tpcm_debug(" %02x ",*(char*)(sharemem_addr + recv_msg.output_addr_num+tmp));
				//tpcm_debug("index %d, %02x ",tmp,*(char*)(recv_total_buff+recv_msg.input_length+tmp));
			}
#endif
			tpcm_debug("process finish,recv output addr %lx!\n",recv_msg.output_addr_num);
		}
	}else{
		tpcm_debug("recv buffer error!   %d\n",recv_msg.input_length + recv_msg.output_maxlength);
	}

	tpcm_debug("res tag %lu,res len %lu, res ret %lu\n",ntohl(*(uint32_t*)output),ntohl(*(uint32_t*)(output+4)),ntohl(*(uint32_t*)(output+8)));
	tpcm_debug("orig res tag %lu,res len %lu, res ret %lu\n",(*(uint32_t*)output),(*(uint32_t*)(output+4)),(*(uint32_t*)(output+8)));

out:

	//printf("test buffer info end L442\n");



	if(bmc_sockfd){
		close(bmc_sockfd);
		bmc_sockfd = 0;
	}




	//end
#endif
	return ;
}

 int tpcm_comm_map_address(struct command_info *info,void **input,void **output){
		struct command_info_impl *impl = (struct command_info_impl *)(info);

	if(impl->input_addr && impl->input_length){
		impl->input_map = tpcm_sys_map(impl->input_addr,impl->input_length,input);
		tpcm_debug("map result:%d", impl->input_map);
		if(!impl->input_map){
			tpcm_error("Map input Address fail %lx \n",impl->input_addr);
			return -1;
		}
	}
	if(impl->output_addr && impl->output_maxlength){
		impl->output_map = tpcm_sys_map(impl->output_addr,impl->output_maxlength,output);
		if(!impl->output_map){
			tpcm_error("Map out Address fail %lx \n",impl->output_addr);
			return -1;
		}
	}
	tpcm_debug("PK cmd_map = %p,%p,%p\n",impl->cmd_map,impl->input_map,impl->output_map);
	return 0;
}
 void tpcm_comm_release_command(struct command_info *info){
	struct command_info_impl *impl = (struct command_info_impl *)(info);
	tpcm_debug("PK cmd_map = %p,%p,%p\n",impl->cmd_map,impl->input_map,impl->output_map);
	if(impl->cmd_map){
		tpcm_sys_unmap(impl->cmd_map);
	}
	if(impl->input_map){
			tpcm_sys_unmap(impl->input_map);
		}
	if(impl->output_map){
		tpcm_sys_unmap(impl->output_map);
	}
	tpcm_debug("Out map return\n");
}

 void tpcm_comm_set_notify_handler(COMMAND_NOIFTY func){
	notifier = func;
}

 static inline void interrut(int type,unsigned long cmd_sequence ){
	//tpcm_sys_tpcm_debug("Sending notify not implemented\n");
	int r;
	struct notify_info ninfo;
	ninfo.notify_type = type;
	ninfo.notify_sequence = cmd_sequence;
	r = httcsec_netlink_send_msg(1,&ninfo,sizeof(struct notify_info),0,0);
	tpcm_debug("Send result %d\n",r);
}
 void tpcm_comm_async_command_handled(struct command_info *info){

	struct command_info_impl *impl = (struct command_info_impl *)(info);
	struct cmd_header *header = (struct cmd_header *)impl->cmd_vaddr;
//	while( sharemem->notify_type == 1 ){//&&	(sharemem->notify_type & NOTIFY_DATA_MASK
//		tpcm_sys_tpcm_debug("Waiting for previous command finished\n");
//		tpcm_sys_msleep(1);
//	}

	//if(sharemem->notify_pending){
	//	sharemem->notify_type = sharemem->notify_type | NOTIFY_TYPE_CMD_FINISHED;
	//}
	//else{
		sharemem->notify_type = NOTIFY_TYPE_CMD_FINISHED;
	//}
	header->out_length = info->out_length;
	sharemem->cmd_ret = header->out_return = impl->out_return;
	sharemem->notify_sequence = info->cmd_sequence;
	sharemem->notify_pending = 1;
	tpcm_debug("Send commnd finished notify cmd sequence = %lu\n",info->cmd_sequence);
	interrut(1,info->cmd_sequence);
//	void *cmd_addr = NULL;
//	int length = sizeof(struct cmd_header);
//	struct command_info_impl *impl = (struct command_info_impl *)(inf);
//	MAPObject share = tpcm_sys_map((unsigned long)impl->cmd_vaddr,length,(void **)&cmd_addr);
//	struct cmd_header *header = (struct cmd_header *)cmd_addr;
//	while(sharemem->notify_pending &&
//			(sharemem->notify_type & NOTIFY_DATA_MASK) ){
//		tpcm_sys_tpcm_debug("Waiting for previous command finished\n");
//		tpcm_sys_msleep(1);
//	}
//
//	if(sharemem->notify_pending){
//		sharemem->notify_type = sharemem->notify_type | NOTIFY_TYPE_CMD_FINISHED;
//	}
//	else{
//		sharemem->notify_type = NOTIFY_TYPE_CMD_FINISHED;
//	}
//	header->out_length = inf->out_length;
//	sharemem->cmd_ret = header->out_return = impl->out_return;
//	sharemem->notify_sequence = inf->cmd_sequence;
//	sharemem->notify_pending = 1;
//	tpcm_sys_tpcm_debug("Send commnd finished notify cmd sequence = %lu\n",inf->cmd_sequence);
//	tpcm_sys_unmap(share);
	//return 0;
}

 void tpcm_comm_send_bios_measure_result(uint32_t ret){
	tpcm_info("send Boot measure result %x\n",ret);
}
 void tpcm_comm_send_simple_notify(uint32_t notify_type){
//	if(notify_type <=  1){
//		tpcm_sys_tpcm_debug("Invalid notify type %d\n",notify_type);
//		return;
//	}
//	while(sharemem->notify_pending && sharemem->notify_type == 1){//&&(sharemem->notify_type & NOTIFY_DATA_MASK)
//		tpcm_sys_tpcm_debug("Waiting for command finished\n");
//		tpcm_sys_msleep(1);
//	}
//	if(sharemem->notify_pending){
//		sharemem->notify_type = sharemem->notify_type | (notify_type <<  16 ) ;
//	}
//	else{
		sharemem->notify_type = notify_type;//notify_type << 16  ;
//	}
		tpcm_debug("Try to sending notify %d\n",sharemem->notify_type);
		*(unsigned char * )(sharemem + 1) = 'A';
	sharemem->notify_sequence = 9;
	sharemem->notify_length = 2;
	sharemem->notify_addr_phys = (unsigned long )(sharemem + 1);
	sharemem->notify_pending = 1;
	interrut(sharemem->notify_type,sharemem->notify_sequence);
}
void debug_dump_hex (const void *p, int bytes);
static int dev_fd;
 int comm_init(void){

	//char buffer[1024]
	unsigned char cmd[1024] = {0};
	dev_fd = open("/dev/tpcm_comm", O_RDWR);
	if(dev_fd < 0){
		tpcm_error("Open comm dev file error\n");
		return -1;
	}
	sharemem_addr = (unsigned long)mmap(NULL, SHARE_MEM_SIZE,  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED,
			dev_fd, 0);

	if(!sharemem_addr){
		tpcm_error("Share memory map error\n");
		return -1;
	}
	tpcm_info("Share memory virtual addr %p\n",sharemem_addr);
	sharemem = (volatile struct share_memory *)sharemem_addr;
	//tpcm_sys_tpcm_debug("Mapperd");
	//tpcm_sys_rand(((char *)sharemem) + 4096,4096);
	//tpcm_dump(((char *)sharemem) + 4096,100);
	HTTCSEC_NETLINK_HANLDLE  handle = httcsec_alloc_netlink_listener();
	if(httcsec_register_netlink_callback(handle, 1, os_handle)){
		tpcm_error("httcsec_register_netlink_callback error\n");
		return -1;
	}
	

	return httcsec_start_netlink_listener(handle, 0);
}

#define ___IO(cmd)  _IO(0xD2,(cmd))

int httcsec_ioctl(unsigned long cmd,unsigned long param){
	int r = 0;
	if ((r =  ioctl(dev_fd, ___IO(cmd), param)) < 0) {
		tpcm_debug("ioctl cmd %lu ,param %lu fail,%s\n",cmd,param,strerror(errno));
		return -1;
	}
	return r;
}
