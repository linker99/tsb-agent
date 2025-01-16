#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "tcm.h"
#include "tcmfunc.h"
#include "tcm_types.h"
#include "tcm_constants.h"
#include "tcmutil.h"
#include "tcm_lowlevel.h"
#include "tcm_error.h"

#define MAGIC 'T'

#define IOCTL_TYPE_TCM		1
#define IOCTL_TYPE_TPCM		2

#define IOCTL_PROC_TRANSMIT		1
#define IOCTL_PROC_SPEC			2

#define ioctlCmd(type,proc)	_IOWR(MAGIC, ((type)|(proc<<2)), unsigned int)
#define ioctlType(cmd)	(cmd&0x03)
#define ioctlProc(cmd)	((cmd>>2)&0x03)

#pragma pack(push, 1)
struct tddl_buffer {
    uint32_t cmd_len;
    uint32_t rsp_len;
    uint32_t rsp_maxlen;
    uint32_t res;
    unsigned char buffer[0];
};
#pragma pack(pop)

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

static __thread int tcm_tddl_fd = 0;


uint32_t TCM_Open(void){
	if(!tcm_tddl_fd){
		if((tcm_tddl_fd = open("/dev/tcm_ttd", O_RDWR)) < 0){
	        printf("Open tcm_ttd fail!\n");
	        return ERR_TTD_DEV;
	    }
		return 0;
	}
	 printf("Repeat open tcm_ttd!\n");
	return ERR_TTD_DEV;
}

uint32_t TCM_Close(void){
	if(tcm_tddl_fd){
		if(close(tcm_tddl_fd)){
	        printf("Close tcm_ttd fail!\n");
	        return ERR_TTD_DEV;
	    }
		tcm_tddl_fd = 0;
	}
	return 0;
}

static uint32_t TCM_OpenTddlDev(int *sock_fd)
{
#if 0
	if((tcm_tddl_fd = open("/dev/tcm_ttd", O_RDWR)) < 0){
        printf("Open tcm_ttd fail!\n");
        return ERR_TTD_DEV;
    }
#endif
	*sock_fd = tcm_tddl_fd;
	return 0;
}

static uint32_t TCM_CloseTddlDev(int sock_fd)
{
#if 0
	if(sock_fd){
		if(close(sock_fd)){
	        printf("Close tcm_ttd fail!\n");
	        return ERR_TTD_DEV;
	    }
	}
#endif
	return 0;
}

#define HTTC_ALIGN_SIZE(len,align) ((len)%(align) == 0 ? (len) : (len) + (align) - (len)%(align))
static uint32_t TCM_TransmitTddlDev(int sock_fd, struct tcm_buffer *tb, const char *msg)
{
    int ret = 0;
    char mymsg[4096] = {0};
    uint32_t paramSize = 0;
    uint32_t addsize = 0;
	int msg_len = 0;

    struct tddl_buffer *gst_tddl_msg = NULL;

    if (TCM_LowLevel_Use_VTCM()) {
        addsize = sizeof(uint32_t);
    }
    snprintf(mymsg, sizeof(mymsg), "%s: To TCM [%s]", __func__,  msg);
    showBuff(tb->buffer, mymsg);
	
	msg_len = HTTC_ALIGN_SIZE (tb->size + sizeof (struct tddl_buffer), 8); 

    if (NULL == (gst_tddl_msg = malloc (msg_len))) {
        printf ("gst_tddl_msg alloc error!\n");
        return ERR_MEM_ERR;
    }

    gst_tddl_msg->cmd_len = tb->used;
    gst_tddl_msg->rsp_maxlen = tb->size;
    memcpy (gst_tddl_msg->buffer, tb->buffer, tb->used);

    if (ioctl (tcm_tddl_fd, ioctlCmd(IOCTL_TYPE_TCM, IOCTL_PROC_TRANSMIT), gst_tddl_msg)) {
        free (gst_tddl_msg);
        return ERR_IO;
    }

    if (gst_tddl_msg->res) {
        ret = gst_tddl_msg->res;
        free (gst_tddl_msg);
        return ret;
    }

    if (!gst_tddl_msg->rsp_len) {
        free (gst_tddl_msg);
        return ERR_IO;
    }

    tb->used = gst_tddl_msg->rsp_len;
    memcpy (tb->buffer, gst_tddl_msg->buffer, gst_tddl_msg->rsp_len);

    /* extract the paramSize */
    if (ret == 0) {
        paramSize = LOAD32(tb->buffer, addsize + TCM_PARAMSIZE_OFFSET);
        if (paramSize > tb->size) {
            printf("[%s:%d]: ERROR: paramSize %u greater than %u\n",
                   __func__, __LINE__, paramSize, tb->size);
            free (gst_tddl_msg);
            return ERR_BAD_RESP;
        }
    }

    if (ret == 0) {
        snprintf(mymsg, sizeof(mymsg), "%s: From TCM", __func__);
        showBuff (tb->buffer, mymsg);
    }

    ret = LOAD32 (tb->buffer, addsize + TCM_RETURN_OFFSET);

    if (ret == TCM_USER_NO_PRIVILEGE)
        tcm_buffer_load32(tb, addsize + TCM_PRIVCODE_OFFSET, &ret);
    tb->used = addsize + paramSize;
	
    free (gst_tddl_msg);

    return ret;
}

static uint32_t TCM_ReceiveTddlDev(int sock_fd, struct tcm_buffer *tb)
{
    return 0;
}

/* local variables */
static struct tcm_transport tddl_transport = {
    .open = TCM_OpenTddlDev,
    .close = TCM_CloseTddlDev,
    .send = TCM_TransmitTddlDev,
    .recv = TCM_ReceiveTddlDev,
};

void TCM_LowLevel_TransportTddlDev_Set(void)
{
    TCM_LowLevel_Transport_Set(&tddl_transport);
}

