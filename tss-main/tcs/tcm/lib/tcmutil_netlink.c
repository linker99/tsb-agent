#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <fcntl.h>

#include "tcm.h"
#include "tcmfunc.h"
#include "tcm_types.h"
#include "tcm_constants.h"
#include "tcmutil.h"
#include "tcm_lowlevel.h"
#include "tcm_error.h"


#define NETLINK_TPCM     29
#define TCM_PORT		100

#if 0
//////////////////////////////////////////////////////////////////////////
// netlink macro define
//////////////////////////////////////////////////////////////////////////
#define NETLINK_ROUTE		0	// Routing/device hook
#define NETLINK_SKIP		1	// Reserved for ENskip
#define NETLINK_USERSOCK	2	// Reserved for user mode socket protocols
#define NETLINK_FIREWALL	3	// Firewalling hook
#define NETLINK_TCPDIAG		4	// TCP socket monitoring
#define NETLINK_NFLOG		5	// netfilter/iptables ULOG
#define NETLINK_ARPD		8
#define NETLINK_ROUTE6		11	// af_inet6 route comm channel
#define NETLINK_IP6_FW		13
#define NETLINK_DNRTMSG		14	// DECnet routing messages
#define NETLINK_TAPBASE		16	// 16 to 31 are ethertap
#define MAX_LINKS			32

// Flags values
#define NLM_F_REQUEST		1	// It is request message
#define NLM_F_MULTI			2	// Multipart message, terminated by NLMSG_DONE
#define NLM_F_ACK			4	// Reply with ack, with zero or error code
#define NLM_F_ECHO			8	// Echo this request

// Modifiers to GET request
#define NLM_F_ROOT			0x100		// specify tree	root
#define NLM_F_MATCH			0x200		// return all matching
#define NLM_F_ATOMIC		0x400		// atomic GET
#define NLM_F_DUMP			(NLM_F_ROOT|NLM_F_MATCH)

// Modifiers to NEW request
#define NLM_F_REPLACE		0x100	// Override existing
#define NLM_F_EXCL			0x200	// Do not touch, if it exists
#define NLM_F_CREATE		0x400	// Create, if it does not exist
#define NLM_F_APPEND		0x800	// Add to end of list

#define NLMSG_ALIGNTO		4
#define NLMSG_ALIGN(len)	( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_LENGTH(len)	((len)+NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_SPACE(len)	NLMSG_ALIGN(NLMSG_LENGTH(len))
#define NLMSG_DATA(nlh)		((void*)(((char*)nlh) + NLMSG_LENGTH(0)))

#define NLMSG_NEXT(nlh,len)	((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
							(struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))

#define NLMSG_OK(nlh,len)	((len) > 0 && (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
							(nlh)->nlmsg_len <= (len))

#define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))


//////////////////////////////////////////////////////////////////////////
// netlink struct define
//////////////////////////////////////////////////////////////////////////
struct sockaddr_nl {
    sa_family_t	nl_family;		// AF_NETLINK
    unsigned short	nl_pad;		// zero
    u_int32_t		nl_pid;		// process pid
    u_int32_t		nl_groups;	// multicast groups mask
};

struct nlmsghdr {
    u_int32_t		nlmsg_len;		// Length of message including header
    u_int16_t		nlmsg_type;		// Message content
    u_int16_t		nlmsg_flags;	// Additional flags
    u_int32_t		nlmsg_seq;		// Sequence number
    u_int32_t		nlmsg_pid;		// Sending process PID
};

struct nlmsgerr {
    int		error;
    struct nlmsghdr msg;
};
#endif

#define TSS_TCM_TXBLOB_SIZE		4096

typedef struct _user_msg_info {
    struct nlmsghdr hdr;
    char  msg[TSS_TCM_TXBLOB_SIZE];
} user_msg_info;


static void tcm_util_dump_hex (unsigned char *name, void *p, int bytes)
{
    int i = 0;
    uint8_t *data = p;
    int hexlen = 0;
    int chrlen = 0;
    uint8_t hexbuf[128] = {0};
    uint8_t chrbuf[128] = {0};
    uint8_t dumpbuf[128] = {0};

    printf ("%s length=%d:\n", name, bytes);

    for (i = 0; i < bytes; i ++) {
        hexlen += sprintf (&hexbuf[hexlen], "%02X ", data[i]);
        chrlen += sprintf (&chrbuf[chrlen], "%c", ((data[i] >= 33) && (data[i] <= 126)) ? (unsigned char)data[i] : '.');
        if (i % 16 == 15) {
            sprintf (&dumpbuf[0], "%08X: %s %s", i / 16 * 16, hexbuf, chrbuf);
            printf ("%s\n", dumpbuf);
            hexlen = 0;
            chrlen = 0;
        }
    }

    if (i % 16 != 0) {
        sprintf (&dumpbuf[0], "%08X: %-48s %s", i / 16 * 16, hexbuf, chrbuf);
        printf ("%s\n", dumpbuf);
    }
}


//////////////////////////////////////////////////////////////////////////
// net link interface
//////////////////////////////////////////////////////////////////////////
// netlink initialize
static uint32_t TCM_OpenClientNetlink(int *sock_fd)
{
    struct sockaddr_nl src_addr;

    //printf("netlink_init###################################\n");
    // CREATE SOCKET IN THE USER-SPACE
    *sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_TPCM);
    if ((*sock_fd) < 0) {
        printf("create NETLINK socket failed in function :%s\r\n", strerror(errno));
        return -1;
    }

    //printf ("sock_fd: %d\n", *sock_fd);

    // FILL IN THE SRC_ADDR AND BIND
    memset(&src_addr, 0, sizeof(struct sockaddr_nl));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = TCM_PORT;
    src_addr.nl_groups = 0;

    if(bind(*sock_fd, (struct sockaddr *)&src_addr, sizeof(struct sockaddr_nl)) != 0) {
        printf("bind NETLINK socket error in function :%s\r\n", __FUNCTION__);
        return -1;
    }

    // set nonblock mode
    if ( fcntl(*sock_fd, F_SETFL, O_NONBLOCK) != 0) {
        printf("fcntl NETLINK socket error in function :%s\r\n", __FUNCTION__);
        return -1;
    }

    return 0;
}

// nrylivk close
static uint32_t TCM_CloseClientNetlink(int sock_fd)
{
    close(sock_fd);
}

// send command packet
static uint32_t TCM_TransmitNetlink(int sock_fd, struct tcm_buffer *tb, const char *msg)
{
    int slen = 0;
    struct msghdr msg_sent;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct sockaddr_nl dest_addr;
    char mymsg[4096] = {0};

    snprintf(mymsg, sizeof(mymsg), "TCM_TransmitSocket: To TCM [%s]", msg);
    showBuff(tb->buffer, mymsg);

    // FILL IN THE DEST_ADDR THE MESSAGE WILL BE SENT TO
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;				// to linux kernel
    dest_addr.nl_groups = 0;

    // FILL IN THE NETLINK MESSAGE HEADER
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(TSS_TCM_TXBLOB_SIZE));
    if(nlh == NULL) {
        printf("[%s:%d] Allocating memory for nlh fails\n", __func__, __LINE__);
    }

    memset(nlh, 0, NLMSG_LENGTH(TSS_TCM_TXBLOB_SIZE));
    nlh->nlmsg_len = NLMSG_SPACE (tb->used);
    nlh->nlmsg_type = 0;
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = TCM_PORT;

    // FILL IN THE NETLINK MESSAGE PAYLOAD
    memcpy(NLMSG_DATA(nlh), tb->buffer, tb->used);

    // send message
    if ((slen = sendto(sock_fd, nlh, nlh->nlmsg_len, 0,
                       (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_nl)) < 0)) {
        printf("[%s:%d] send message failed: %s\r\n", __func__, __LINE__, strerror (errno));
        if(nlh)	free(nlh);
        return -1;
    }

    free(nlh);
    return 0;
}

static uint32_t TCM_ReceiveBytes (int sock_fd, void *buffer, size_t nbytes)
{

    struct msghdr msg_received;
    struct nlmsghdr *nlh = NULL;
    struct sockaddr_nl dest_addr;
    struct iovec iov;
    int i = 0;
    int iRes = -1;

    user_msg_info u_info;
    struct sockaddr_nl daddr;
    int len = sizeof(struct sockaddr_nl);
    memset(&daddr, 0, sizeof(daddr));
    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0; // to kernel

    // CLEAR THE NETLINK MESSAGE HEADER
    nlh = (struct nlmsghdr *)malloc(NLMSG_LENGTH(TSS_TCM_TXBLOB_SIZE));
    if(nlh == NULL) {
        printf("[%s:%d] Allocating memory for nlh fails\n", __func__, __LINE__);
    }
    memset(nlh, 0, NLMSG_LENGTH(TSS_TCM_TXBLOB_SIZE));

    // RECV THE MSG <modify by yww for mutiply process access 20120321>
    for(i = 0; i < 10; i++) {
        if((iRes = recvfrom(sock_fd, &u_info,
                            sizeof(user_msg_info), 0,
                            (struct sockaddr *)&daddr, &len)) >= 0)		break;
        sleep(1);
    }

    if (iRes < 0) {
        printf("[%s:%d] Receive message from TCS fail <Time Over>:\r\n", __func__, __LINE__);
        free(nlh);
        return -1;
    }

    if(daddr.nl_pid != 0) {
        printf("[%s:%d] Not reliable packet received in function\r\n", __func__, __LINE__);
        free(nlh);
        return -1;
    }
    memcpy (buffer, u_info.msg, u_info.hdr.nlmsg_len - sizeof (struct nlmsghdr) );
    free(nlh);
    return 0;
}

/* read a TCM packet from socket sock_fd */
static uint32_t TCM_ReceiveNetlink(int sock_fd, struct tcm_buffer *tb)
{
    uint32_t rc = 0;
    uint32_t paramSize = 0;
    uint32_t addsize = 0;
    unsigned char *buffer = tb->buffer;

    if (TCM_LowLevel_Use_VTCM()) {
        addsize = sizeof(uint32_t);
    }

    /* read the packet */
    if (rc == 0) {
        rc = TCM_ReceiveBytes(sock_fd, buffer, addsize + TCM_U16_SIZE + TCM_U32_SIZE);
    }
    /* extract the paramSize */
    if (rc == 0) {
        paramSize = LOAD32(buffer, addsize + TCM_PARAMSIZE_OFFSET);
        if (paramSize > TCM_MAX_BUFF_SIZE) {
            printf("[%s:%d]: ERROR: paramSize %u greater than %u\n",
                   __func__, __LINE__, paramSize, TCM_MAX_BUFF_SIZE);
            rc = ERR_BAD_RESP;
        }
    }
    /* read the TCM return code from the packet */
    if (rc == 0) {
        showBuff(buffer, "TCM_ReceiveSocket: From TCM");
        rc = LOAD32(buffer, addsize + TCM_RETURN_OFFSET);

        if (rc == TCM_USER_NO_PRIVILEGE) {
            tcm_buffer_load32(tb, TCM_PRIVCODE_OFFSET, &rc);
        }
        tb->used = addsize + paramSize;
    }
    return rc;
}

/* local variables */
static struct tcm_transport netlink_transport = {
    .open = TCM_OpenClientNetlink,
    .close = TCM_CloseClientNetlink,
    .send = TCM_TransmitNetlink,
    .recv = TCM_ReceiveNetlink,
};

void TCM_LowLevel_TransportNetlink_Set(void)
{
    TCM_LowLevel_Transport_Set(&netlink_transport);
}

