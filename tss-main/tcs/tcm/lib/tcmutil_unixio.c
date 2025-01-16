/********************************************************************************/
/*										*/
/*			     	TCM Utility Functions				*/
/*			     Written by Kenneth Goldman, Stefan Berger		*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tcmutil_unixio.c 4089 2010-06-09 00:50:31Z kgoldman $	*/
/*										*/
/* (c) Copyright IBM Corporation 2006, 2010.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/


/* These are platform specific.  This version uses a UnixIO socket interface.

   Environment variables are:

   TCM_UNIXIO_PATH - the path to the UNIX IO socket
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/types.h>
#include <fcntl.h>

#include "tcm.h"
#include "tcmfunc.h"
#include "tcm_types.h"
#include "tcm_constants.h"
#include "tcmutil.h"
#include "tcm_lowlevel.h"

/* local prototypes */
static uint32_t TCM_OpenClientSocket_UnixIO(int *sock_fd);
static uint32_t TCM_CloseClientSocket(int sock_fd);
static uint32_t TCM_TransmitSocket(int sock_fd, struct tcm_buffer *tb,
                                   const char *msg);
static uint32_t TCM_ReceiveSocket(int sock_fd, struct tcm_buffer *tb);
static uint32_t TCM_ReceiveBytes(int sock_fd,
                                 unsigned char *buffer,
                                 size_t nbytes);


/* local variables */
static struct tcm_transport unixio_transport = {
    .open = TCM_OpenClientSocket_UnixIO,
    .close = TCM_CloseClientSocket,
    .send = TCM_TransmitSocket,
    .recv = TCM_ReceiveSocket,
};

void TCM_LowLevel_TransportUnixIO_Set(void)
{
    TCM_LowLevel_Transport_Set(&unixio_transport);
}

/****************************************************************************/
/*                                                                          */
/* Open the socket to the TCM Host emulation                                */
/*                                                                          */
/****************************************************************************/

static uint32_t TCM_OpenClientSocket_UnixIO(int *sock_fd)
{
    struct stat         _stat;
    char 		*unixio_path;

    unixio_path = getenv("TCM_UNIXIO_PATH");
    if (unixio_path == NULL) {
        printf("TCM_OpenClientSocket: Error, TCM_UNIXIO_PATH environment variable not set\n");
        return ERR_IO;
    }

    if (0 == stat(unixio_path, &_stat)) {
        if (S_ISSOCK(_stat.st_mode)) {
            *sock_fd = socket(PF_UNIX, SOCK_STREAM, 0);
            if (*sock_fd > 0) {
                struct sockaddr_un addr;
                addr.sun_family = AF_UNIX;
                strcpy(addr.sun_path, unixio_path);
                if (connect(*sock_fd,
                            (struct sockaddr *)&addr,
                            sizeof(addr)) == 0) {
                    return 0;
                } else {
                    close(*sock_fd);
                    *sock_fd = 0;
                }
            }
        }
    }
    return ERR_IO;
}

/****************************************************************************/
/*                                                                          */
/* Close the socket to the TCM Host emulation                               */
/*                                                                          */
/****************************************************************************/

static uint32_t TCM_CloseClientSocket(int sock_fd)
{
    close(sock_fd);
    return 0;
}

/* write buffer to socket sock_fd */

static uint32_t TCM_TransmitSocket(int sock_fd, struct tcm_buffer *tb,
                                   const char *msg)
{
    size_t nbytes = 0;
    ssize_t nwritten = 0;
    size_t nleft = 0;
    unsigned int offset = 0;
    char mymsg[1024];

    snprintf(mymsg, sizeof(mymsg), "TCM_TransmitSocket: To TCM [%s]",
             msg);

    nbytes = tb->used;

    showBuff(tb->buffer, mymsg);

    nleft = nbytes;
    while (nleft > 0) {
        nwritten = write(sock_fd, &tb->buffer[offset], nleft);
        if (nwritten < 0) {        /* error */
            printf("TCM_TransmitSocket: write error %d\n", (int)nwritten);
            return nwritten;
        }
        nleft -= nwritten;
        offset += nwritten;
    }
    return 0;
}

/* read a TCM packet from socket sock_fd */

static uint32_t TCM_ReceiveSocket(int sock_fd, struct tcm_buffer *tb)
{
    uint32_t rc = 0;
    uint32_t paramSize = 0;
    uint32_t addsize = 0;
    unsigned char *buffer = tb->buffer;

    if (TCM_LowLevel_Use_VTCM()) {
        addsize = sizeof(uint32_t);
    }

    /* read the tag and paramSize */
    if (rc == 0) {
        rc = TCM_ReceiveBytes(sock_fd, buffer, addsize + TCM_U16_SIZE + TCM_U32_SIZE);
    }
    /* extract the paramSize */
    if (rc == 0) {
        paramSize = LOAD32(buffer, addsize + TCM_PARAMSIZE_OFFSET);
        if (paramSize > TCM_MAX_BUFF_SIZE) {
            printf("TCM_ReceiveSocket: ERROR: paramSize %u greater than %u\n",
                   paramSize, TCM_MAX_BUFF_SIZE);
            rc = ERR_BAD_RESP;
        }
    }
    /* read the rest of the packet */
    if (rc == 0) {
        rc = TCM_ReceiveBytes(sock_fd,
                              buffer + addsize + TCM_U16_SIZE + TCM_U32_SIZE,
                              paramSize - (TCM_U16_SIZE + TCM_U32_SIZE));
    }
    /* read the TCM return code from the packet */
    if (rc == 0) {
        showBuff(buffer, "TCM_ReceiveSocket: From TCM");
        rc = LOAD32(buffer, addsize + TCM_RETURN_OFFSET);
        tb->used = addsize + paramSize;
    }
    return rc;
}

/* read nbytes from socket sock_fd and put them in buffer */

static uint32_t TCM_ReceiveBytes(int sock_fd,
                                 unsigned char *buffer,
                                 size_t nbytes)
{
    int nread = 0;
    int nleft = 0;

    nleft = nbytes;
    while (nleft > 0) {
        nread = read(sock_fd, buffer, nleft);
        if (nread <= 0) {       /* error */
            printf("TCM_ReceiveBytes: read error %d\n", nread);
            return ERR_IO;
        } else if (nread == 0) { /* EOF */
            printf("TCM_ReceiveBytes: read EOF\n");
            return ERR_IO;
        }
        nleft -= nread;
        buffer += nread;
    }
    return 0;
}
