/********************************************************************************/
/*										*/
/*			     	TCM Socket Communication Functions		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tcmutil_sock.c 4648 2011-10-25 19:22:18Z kgoldman $		*/
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


/* These are platform specific.  This version uses a TCP/IP socket interface.

   Environment variables are:

   TCM_SERVER_PORT - the client and server socket port number
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include <unistd.h>

#ifdef TCM_POSIX
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif
#ifdef TCM_WINDOWS
#include <winsock2.h>
#endif
#include <sys/types.h>
#include <fcntl.h>

#include "tcm.h"
#include "tcmfunc.h"
#include "tcm_types.h"
#include "tcm_constants.h"
#include "tcmutil.h"
#include "tcm_lowlevel.h"
#include "tcm_error.h"

/* local prototypes */
static uint32_t TCM_OpenClientSocket(int *sock_fd);
static uint32_t TCM_CloseClientSocket(int sock_fd);
static uint32_t TCM_TransmitSocket(int sock_fd, struct tcm_buffer *tb,
                                   const char *msg);
static uint32_t TCM_ReceiveSocket(int sock_fd, struct tcm_buffer *tb);
static uint32_t TCM_ReceiveBytes(int sock_fd,
                                 unsigned char *buffer,
                                 size_t nbytes);


/* local variables */
static struct tcm_transport socket_transport = {
    .open = TCM_OpenClientSocket,
    .close = TCM_CloseClientSocket,
    .send = TCM_TransmitSocket,
    .recv = TCM_ReceiveSocket,
};

void TCM_LowLevel_TransportSocket_Set(void)
{
    TCM_LowLevel_Transport_Set(&socket_transport);
}

/****************************************************************************/
/*                                                                          */
/* Open the socket to the TCM Host emulation                                */
/*                                                                          */
/****************************************************************************/

/* For Windows, sock_fd is uint */

static uint32_t TCM_OpenClientSocket(int *sock_fd)
{
    int			irc;
#ifdef TCM_WINDOWS
    WSADATA 		wsaData;
#endif
    char 		*port_str;
    short 		port;
    struct sockaddr_in 	serv_addr;
    struct hostent 	*host = NULL;
    char 		*server_name = NULL;

    port_str = getenv("TCM_SERVER_PORT");
    if (port_str == NULL) {
        printf("TCM_OpenClientSocket: Error, TCM_SERVER_PORT environment variable not set\n");
        return ERR_IO;
    }
    irc = sscanf(port_str, "%hu", &port);
    if (irc != 1) {
        printf("TCM_OpenClientSocket: Error, TCM_SERVER_PORT environment variable invalid\n");
        return ERR_IO;
    }
    /* get the server host name from the environment variable */
    server_name = getenv("TCM_SERVER_NAME");
    if (server_name == NULL) {        /* environment variable not found */
        printf("TCM_OpenClientSocket: TCM_SERVER_NAME environment variable not set\n");
        return ERR_IO;
    }
#ifdef TCM_WINDOWS
    if ((irc = WSAStartup(0x202, &wsaData)) != 0) {		/* if not successful */
        printf("TCM_OpenClientSocket: Error, WSAStartup failed\n");
        WSACleanup();
        return ERR_IO;
    }
    if ((*sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("TCM_OpenClientSocket: client socket() error: %u\n", *sock_fd);
        return ERR_IO;
    }
#endif
#ifdef TCM_POSIX
    if ((*sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("TCM_OpenClientSocket: client socket error: %d %s\n", errno, strerror(errno));
        return ERR_IO;
    } else {
        /*  	printf("TCM_OpenClientSocket: client socket: success\n"); */
    }
#endif
    /* establish the connection to server */
    memset((char *)&serv_addr, 0x0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    /* first assume server is dotted decimal number and call inet_addr */
    if ((int)(serv_addr.sin_addr.s_addr = inet_addr(server_name)) == -1) {
        /* if inet_addr fails, assume server is a name and call gethostbyname to look it up */
        if ((host = gethostbyname(server_name)) == NULL) {	/* if gethostbyname also fails */
            printf("TCM_OpenClientSocket: server name error, name %s\n", server_name);
            return ERR_IO;
        }
        serv_addr.sin_family = host->h_addrtype;
        memcpy(&serv_addr.sin_addr, host->h_addr, host->h_length);
    } else {
        /*  	printf("TCM_OpenClientSocket: server address: %s\n",server_name); */
    }
#ifdef TCM_POSIX
    if (connect(*sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("TCM_OpenClientsocket: Error on connect to %s:%u\n", server_name, port);
        printf("TCM_OpenClientsocket: client connect: error %d %s\n", errno, strerror(errno));
        return ERR_IO;
    }
#endif
#ifdef TCM_WINDOWS
    if (connect(*sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
        printf("TCM_OpenClientsocket: Error on connect to %s:%u\n", server_name, port);
        printf("TCM_OpenClientsocket: client connect: error %d %s\n", errno, strerror(errno));
        return ERR_IO;
    }
#endif
    else {
        /*  	printf("TCM_OpenClientSocket: client connect: success\n"); */
    }
    return 0;
}

/****************************************************************************/
/*                                                                          */
/* Close the socket to the TCM Host emulation                               */
/*                                                                          */
/****************************************************************************/

static uint32_t TCM_CloseClientSocket(int sock_fd)
{
#ifdef TCM_POSIX
    if (close(sock_fd) != 0)
        return ERR_BAD_FILE_CLOSE;
#endif
#ifdef TCM_WINDOWS
    closesocket(sock_fd);
    WSACleanup();
#endif
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
#ifdef TCM_POSIX
        nwritten = write(sock_fd, &tb->buffer[offset], nleft);
        if (nwritten < 0) {        /* error */
            printf("TCM_TransmitSocket: write error %d\n", (int)nwritten);
            return ERR_IO;
        }
#endif
#ifdef TCM_WINDOWS
        /* cast for winsock.  Unix uses void * */
        nwritten = send(sock_fd, (char *)(&tb->buffer[offset]), nleft, 0);
        if (nwritten == SOCKET_ERROR) {        /* error */
            printf("TCM_TransmitSocket: write error %d\n", (int)nwritten);
            return ERR_IO;
        }
#endif
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

        if (rc == TCM_USER_NO_PRIVILEGE) {
            tcm_buffer_load32(tb, TCM_PRIVCODE_OFFSET, &rc);
        }
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
#ifdef TCM_POSIX
        nread = read(sock_fd, buffer, nleft);
        if (nread <= 0) {       /* error */
            printf("TCM_ReceiveBytes: read error %d\n", nread);
            return ERR_IO;
        }
#endif
#ifdef TCM_WINDOWS
        /* cast for winsock.  Unix uses void * */
        nread = recv(sock_fd, (char *)buffer, nleft, 0);
        if (nread == SOCKET_ERROR) {       /* error */
            printf("TCM_ReceiveBytes: read error %d\n", nread);
            return ERR_IO;
        }
#endif
        else if (nread == 0) {  /* EOF */
            printf("TCM_ReceiveBytes: read EOF\n");
            return ERR_IO;
        }
        nleft -= nread;
        buffer += nread;
    }
    return 0;
}
