/********************************************************************************/
/*										*/
/*			     	TCM Utility Functions				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tcmutil.c 4634 2011-10-11 00:32:25Z stefanb $		*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>

#ifdef TCM_POSIX
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <fcntl.h>
#endif
#ifdef TCM_WINDOWS
#include <winsock2.h>
#endif

#include "tcm.h"
#include "tcmfunc.h"
#include "tcm_types.h"
#include "tcm_constants.h"
#include "tcmutil.h"
#include "tcm_error.h"
#include "tcm_lowlevel.h"
#include "crypto/sm/rand.h"
#include "sm_if.h"



/* local prototypes */
static void TCM_XOR(unsigned char *out,
                    const unsigned char *in1,
                    const unsigned char *in2,
                    size_t length);
TCM_RESULT TCMC_SM3_valist(TCM_DIGEST md,
                           uint32_t length0, unsigned char *buffer0,
                           va_list ap);

static TCM_RESULT TCMC_SM3Init(void **context);
static TCM_RESULT TCMC_SM3_Update(void *context, const unsigned char *data, uint32_t length);
static TCM_RESULT TCMC_SM3Final(unsigned char *md, void *context);
static TCM_RESULT TCMC_SM3Delete(void **context);

static int priv2str(SM2_PRIVATE_KEY *key, unsigned char **privkey, unsigned int *len);

static int pub2str(SM2_PUBLIC_KEY *key, unsigned char **pubkey, unsigned int *len);

static int sign2str(SM2_SIGNATURE *signature, unsigned char **sign, unsigned int *len);

static int str2priv(unsigned char *key, SM2_PRIVATE_KEY *privkey);

static int str2pub(unsigned char *key, SM2_PUBLIC_KEY *pubkey);

static int str2sign(unsigned char *sign, SM2_SIGNATURE *signature);

/* local variables */

static unsigned int logflag = 1;
/* the to-be-used lowlevel transport */
static struct tcm_transport *use_transp = NULL;
static int actual_used_transport = 0;

#ifdef TCM_USE_CHARDEV
static int preferred_transport = TCM_LOWLEVEL_TRANSPORT_CHARDEV;
#elif defined XCRYPTO_USE_CCA
static int preferred_transport = TCM_LOWLEVEL_TRANSPORT_CCA;
//#elif TCM_USE_LIBTCMS
//Never choose this as the default transport since programs will
//need to call TCMLIB_MainInit() themselves and possibly register
//callbacks with libtcms
//static int preferred_transport = TCM_LOWLEVEL_TRANSPORT_LIBTCMS;
#elif TCM_USE_UNIXIO
static int preferred_transport = TCM_LOWLEVEL_TRANSPORT_UNIXIO;
#else
static int preferred_transport = TCM_LOWLEVEL_TRANSPORT_TCP_SOCKET;
#endif


#ifdef TCM_USE_CHARDEV
static int use_vtcm = 0;
#else
static int use_vtcm = 0;
#endif


/****************************************************************************/
/*                                                                          */
/* Function to set the transport to be used.                                */
/*                                                                          */
/****************************************************************************/
struct tcm_transport *TCM_LowLevel_Transport_Set(struct tcm_transport *new_tp)
{
    struct tcm_transport *old = use_transp;
    use_transp = new_tp;
    return old;
}

/*
 * Initialize the low level transport layer to use the chosen
 * transport for communication with the TCM.
 * This function returns the actually chosen transport, which
 * may be different than the choice provided by the user, if
 * the transport chosen by the user was not compiled in.
 */
int TCM_LowLevel_Transport_Init(int choice)
{
    int tp = choice;

    if (tp == 0) {
        tp = preferred_transport;
    }

    switch (tp) {
    default:
    case TCM_LOWLEVEL_TRANSPORT_CHARDEV:
#ifdef TCM_POSIX
        use_vtcm = 0;
        TCM_LowLevel_TransportCharDev_Set();
#endif
        break;

    case TCM_LOWLEVEL_TRANSPORT_TCP_SOCKET:
        TCM_LowLevel_TransportSocket_Set();
        break;
    case TCM_LOWLEVEL_TRANSPORT_TCP_NETLINK:
        TCM_LowLevel_TransportNetlink_Set ();
        break;
    case TCM_LOWLEVEL_TRANSPORT_DEV:
        TCM_LowLevel_TransportTddlDev_Set();
        break;


    case TCM_LOWLEVEL_TRANSPORT_UNIXIO:
#ifdef TCM_POSIX
        TCM_LowLevel_TransportUnixIO_Set();
#endif
        break;


#ifdef TCM_USE_LIBTCMS
    case TCM_LOWLEVEL_TRANSPORT_LIBTCMS:
        TCM_LowLevel_TransportLibTCMS_Set();
        break;
#endif
    }
    actual_used_transport = tp;

    return tp;
}

int TCM_LowLevel_Use_VTCM(void)
{
    return use_vtcm;
}

int TCM_LowLevel_VTCM_Set(int state)
{
    int rc = use_vtcm;
    switch (actual_used_transport) {
    case TCM_LOWLEVEL_TRANSPORT_CHARDEV:
        if (state) {
            rc = -1;
        } else {
            use_vtcm = state;
        }
        break;
    default:
        use_vtcm = state;
        break;
    }
    return rc;
}

/****************************************************************************/
/*                                                                          */
/* Get the Size in a returned response                                      */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_getsize(unsigned char *rsp)
{
    uint32_t size;
    size = LOAD32(rsp, TCM_PARAMSIZE_OFFSET);
    return size;
}

/****************************************************************************/
/*                                                                          */
/* Generate a random nonce                                                  */
/*                                                                          */
/****************************************************************************/
int TSS_gennonce(unsigned char *nonce)
{
	ht_rand_bytes(nonce, TCM_HASH_SIZE);
	return TCM_HASH_SIZE;
}

/****************************************************************************/
/*                                                                          */
/*  This routine takes a format string, sort of analogous to sprintf,       */
/*  a buffer, and a variable number of arguments, and copies the arguments  */
/*  and data from the format string into the buffer, based on the characters*/
/*  in the format string.                                                   */
/*                                                                          */
/*  The routine returns a negative value if it detects an error in the      */
/*  format string, or a positive value containing the total length          */
/*  of the data copied to the buffer.                                       */
/*                                                                          */
/*  The legal characters in the format string are...                        */
/*                                                                          */
/*  0123456789abcdefABCDEF                                                  */
/*     These are used to insert bytes directly into the buffer, represented */
/*     in the format string as hex ASCII.  These MUST be in pairs,          */
/*     representing the two hex nibbles in a byte. e.g. C3 would insert     */
/*     a byte containing the hex value 0xC3 next position in the buffer.    */
/*     There is no argument associated with these format characters.        */
/*                                                                          */
/*  L                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     long (32 bit) unsigned word, in NETWORK byte order (big endian)      */
/*                                                                          */
/*  S                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     short (16 bit) unsigned word, in NETWORK byte order (big endian)     */
/*                                                                          */
/*                                                                          */
/*  l                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     long (32 bit) unsigned word, in NATIVE byte order.                   */
/*                                                                          */
/*  s                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     short (16 bit) unsigned word, in NATIVE byte order.                  */
/*                                                                          */
/*  o                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     byte or character                                                    */
/*                                                                          */
/*  @                                                                       */
/*     This is used to insert a sequence of bytes into the buffer, based    */
/*     on the next two arguments. The first is the length of the sequence.  */
/*     The second is a pointer to the array of bytes to be inserted.        */
/*     The length is inserted into the buffer as a 32 bit big-endian        */
/*     word, preceding the array.  If the length is 0, no array is          */
/*     copied, but the length word containing zero is inserted.             */
/*                                                                          */
/*  ^  This is used to insert a sequence of bytes into the buffer, based    */
/*     on the next two arguments. The first is the length of the sequence.  */
/*     The second is a pointer to the array of bytes to be inserted.        */
/*     The length is inserted into the buffer as a 16 bit big-endian        */
/*     word, preceding the array.  If the length is 0, no array is          */
/*     copied, but the length word containing zero is inserted.             */
/*                                                                          */
/*  %                                                                       */
/*     This is used to insert a sequence of bytes into the buffer, based    */
/*     on the next two arguments. The first is the length of the sequence.  */
/*     The second is a pointer to the array of bytes to be inserted.        */
/*     The length is NOT inserted into the buffer.                          */
/*                                                                          */
/*  T                                                                       */
/*     This is used to insert a 4 byte long value (32 bits, big endian)     */
/*     containing the total length of the data inserted into the buffer.    */
/*     There is no argument associated with this format character.          */
/*                                                                          */
/*                                                                          */
/*  Example                                                                 */
/*                                                                          */
/*   buildbuff("03Ts@99%",buf,10,6,"ABCDEF",3,"123");                       */
/*                                                                          */
/*   would produce a buffer containing...                                   */
/*                                                                          */
/*                                                                          */
/*   03 00 00 00 15 00 0A 00 00 00 06 41 42 43 44 45 46 99 31 32 33         */
/*                                                                          */
/*                                                                          */
/****************************************************************************/
int TSS_buildbuff(char *format, struct tcm_buffer *tb, ...)
{
    unsigned char *totpos;
    va_list argp;
    char *p;
    unsigned int totlen;
    unsigned char *o;
    unsigned long l;
    unsigned short s;
    unsigned char c;
    unsigned long len;
    uint16_t len16;
    unsigned char byte = 0;
    unsigned char hexflag;
    unsigned char *ptr;
    unsigned char *buffer = tb->buffer;
    unsigned int start = tb->used;
    int dummy;

    va_start(argp, tb);
    totpos = 0;
    totlen = tb->used;
    o = &buffer[totlen];
    hexflag = 0;
    p = format;
    while (*p != '\0') {
        switch (*p) {
        case ' ':
            break;
        case 'L':
        case 'X':
            if (hexflag) return ERR_BAD_ARG;
            if (totlen + 4 >= tb->size) return ERR_BUFFER;
            byte = 0;
            l = (unsigned long)va_arg(argp, unsigned long);
            STORE32(o, 0, l);
            if (*p == 'X')
                va_arg(argp, unsigned long);
            o += 4;
            totlen += TCM_U32_SIZE;
            break;
        case 'S':
            if (hexflag) return ERR_BAD_ARG;
            if (totlen + 2 >= tb->size) return ERR_BUFFER;
            byte = 0;
            s = (unsigned short)va_arg(argp, int);
            STORE16(o, 0, s);
            o += TCM_U16_SIZE;
            totlen += TCM_U16_SIZE;
            break;
        case 'l':
            if (hexflag) return ERR_BAD_ARG;
            if (totlen + 4 >= tb->size) return ERR_BUFFER;
            byte = 0;
            l = (unsigned long)va_arg(argp, unsigned long);
            STORE32N(o, 0, l);
            o += TCM_U32_SIZE;
            totlen += TCM_U32_SIZE;
            break;
        case 's':
            if (hexflag) return ERR_BAD_ARG;
            if (totlen + 2 >= tb->size) return ERR_BUFFER;
            byte = 0;
            s = (unsigned short)va_arg(argp, int);
            STORE16N(o, 0, s);
            o += TCM_U16_SIZE;
            totlen += TCM_U16_SIZE;
            break;
        case 'o':
            if (hexflag) return ERR_BAD_ARG;
            if (totlen + 1 >= tb->size) return ERR_BUFFER;
            byte = 0;
            c = (unsigned char)va_arg(argp, int);
            *(o) = c;
            o += 1;
            totlen += 1;
            break;
        case '@':
        case '*':
            if (hexflag) return ERR_BAD_ARG;
            byte = 0;
            len = (int)va_arg(argp, int);
            if (totlen + 4 + len >= tb->size) return ERR_BUFFER;
            ptr = (unsigned char *)va_arg(argp, unsigned char *);
            if (len > 0 && ptr == NULL) return ERR_NULL_ARG;
            STORE32(o, 0, len);
            o += TCM_U32_SIZE;
            if (len > 0) memcpy(o, ptr, len);
            o += len;
            totlen += len + TCM_U32_SIZE;
            break;
        case '&':
            if (hexflag) return ERR_BAD_ARG;
            byte = 0;
            len16 = (uint16_t)va_arg(argp, int);
            if (totlen + 2 + len16 >= tb->size) return ERR_BUFFER;
            ptr = (unsigned char *)va_arg(argp, unsigned char *);
            if (len16 > 0 && ptr == NULL) return ERR_NULL_ARG;
            STORE16(o, 0, len16);
            o += TCM_U16_SIZE;
            if (len16 > 0) memcpy(o, ptr, len16);
            o += len16;
            totlen += len16 + TCM_U16_SIZE;
            break;
        case '%':
            if (hexflag) return ERR_BAD_ARG;
            byte = 0;
            len = (int)va_arg(argp, int);
            if (totlen + len >= tb->size) return ERR_BUFFER;
            ptr = (unsigned char *)va_arg(argp, unsigned char *);
            if (len > 0 && ptr == NULL) return ERR_NULL_ARG;
            if (len > 0) memcpy(o, ptr, len);
            o += len;
            totlen += len;
            break;
        case 'T':
            if (hexflag) return ERR_BAD_ARG;
            if (totlen + 4 >= tb->size) return ERR_BUFFER;
            byte = 0;
            totpos = o;
            o += TCM_U32_SIZE;
            totlen += TCM_U32_SIZE;
            break;
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            if (totlen + 1 >= tb->size) return ERR_BUFFER;
            byte = byte << 4;
            byte = byte |  ((*p - '0') & 0x0F);
            if (hexflag) {
                *o = byte;
                ++o;
                hexflag = 0;
                totlen += 1;
            } else ++hexflag;
            break;
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            if (totlen + 1 >= tb->size) return ERR_BUFFER;
            byte = byte << 4;
            byte = byte |  (((*p - 'A') & 0x0F) + 0x0A);
            if (hexflag) {
                *o = byte;
                ++o;
                hexflag = 0;
                totlen += 1;
            } else ++hexflag;
            break;
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            if (totlen + 1 >= tb->size) return ERR_BUFFER;
            byte = byte << 4;
            byte = byte |  (((*p - 'a') & 0x0F) + 0x0A);
            if (hexflag) {
                *o = byte;
                ++o;
                hexflag = 0;
                totlen += 1;
            } else ++hexflag;
            break;
        case '^':
            /* the size indicator is only 16 bits long */
            /* parameters: address of length indicator,
               maximum number of bytes
               address of buffer  */
            if (hexflag) return ERR_BAD_ARG;
            byte = 0;
            len16 = (uint16_t)va_arg(argp, int);
            dummy = va_arg(argp, int);
            dummy = dummy; /* make compiler happy */
            if (totlen + TCM_U16_SIZE + len16 >= tb->size) return ERR_BUFFER;
            ptr = (unsigned char *)va_arg(argp, unsigned char *);
            if (len16 > 0 && ptr == NULL) return ERR_NULL_ARG;
            STORE16(o, 0, len16);
            o += TCM_U16_SIZE;
            if (len16 > 0) memcpy(o, ptr, len16);
            o += len16;
            totlen += TCM_U16_SIZE + len16;
            break;
        case '!':
            /* the size indicator is 32 bytes long */
            /* parameters: address of length indicator,
               maximum number of bytes
               address of buffer  */
            if (hexflag) return ERR_BAD_ARG;
            byte = 0;
            len = va_arg(argp, int);
            dummy = va_arg(argp, int);
            if (totlen + TCM_U32_SIZE + len >= tb->size) return ERR_BUFFER;
            ptr = (unsigned char *)va_arg(argp, unsigned char *);
            if (len > 0 && ptr == NULL) return ERR_NULL_ARG;
            STORE32(o, 0, len);
            o += TCM_U32_SIZE;
            if (len > 0) memcpy(o, ptr, len);
            o += len;
            totlen += TCM_U32_SIZE + len;
            break;
        case '#':
            /* reverse write the buffer (good for 'exponent') */
            /* the size indicator is 32 bytes long */
            /* parameters: address of length indicator,
               maximum number of bytes
               address of buffer  */
            if (hexflag) return ERR_BAD_ARG;
            byte = 0;
            len = va_arg(argp, int);
            dummy = va_arg(argp, int);
            if (totlen + TCM_U32_SIZE + len >= tb->size) return ERR_BUFFER;
            ptr = (unsigned char *)va_arg(argp, unsigned char *);
            if (len > 0 && ptr == NULL) return ERR_NULL_ARG;
            STORE32(o, 0, len);
            o += TCM_U32_SIZE;
            totlen += TCM_U32_SIZE + len;
            while (len > 0) {
                *o = ptr[len - 1];
                o++;
                len--;
            }
            break;
        default:
            return ERR_BAD_ARG;
        }
        ++p;
    }
    if (totpos != 0) STORE32(totpos, 0, totlen);
    va_end(argp);
#ifdef DEBUG
    printf("buildbuff results...\n");
    for (i = 0; i < totlen; i++) {
        if (i && !( i % 16 )) {
            printf("\n");
        }
        printf("%.2X ", buffer[i]);
    }
    printf("\n");
#endif
    tb->used = totlen;
    return totlen - start;
}

int TSS_parsebuff(char *format, const struct tcm_buffer *tb, uint32_t start, ...)
{
    va_list argp;
    char *p;
    unsigned int offset;
    uint32_t *l;
    uint16_t *s;
    unsigned char *c;
    uint32_t *len;
    uint16_t *len16;
    uint32_t lenmax;
    unsigned int length;
    unsigned char *ptr;
    unsigned char **pptr;
    uint32_t tmp;
    uint32_t ret;
    unsigned char *buf;

    va_start(argp, start);
    offset = start;
    p = format;
    while (*p != '\0') {
        switch (*p) {
        case ' ':
            break;
        case 'L':
            l = (uint32_t *)va_arg(argp, unsigned long *);
            ret = tcm_buffer_load32(tb, offset, l);
            if ((ret & ERR_MASK)) {
                return ret;
            }
            offset += TCM_U32_SIZE;
            break;
        case 'X':
            tmp = (uint32_t)va_arg(argp, int);
            tmp = tmp; /* make compiler happy */
            l = (uint32_t *)va_arg(argp, unsigned long *);
            ret = tcm_buffer_load32(tb, offset, l);
            if ((ret & ERR_MASK)) {
                return ret;
            }
            offset += TCM_U32_SIZE;
            break;
        case 'S':
            s = (uint16_t *)va_arg(argp, int *);
            ret = tcm_buffer_load16(tb, offset, s);
            if ((ret & ERR_MASK)) {
                return ret;
            }
            offset += TCM_U16_SIZE;
            break;
        case 'l':
            l = (uint32_t *)va_arg(argp, unsigned long *);
            ret = tcm_buffer_load32N(tb, offset, l);
            if ((ret & ERR_MASK)) {
                return ret;
            }
            offset += TCM_U32_SIZE;
            break;
        case 's':
            s = (uint16_t *)va_arg(argp, int *);
            ret = tcm_buffer_load16N(tb, offset, s);
            if ((ret & ERR_MASK)) {
                return ret;
            }
            offset += TCM_U16_SIZE;
            break;
        case 'o':
            if (offset + 1 > tb->used) return ERR_BUFFER;
            c = (unsigned char *)va_arg(argp, unsigned char *);
            *c = tb->buffer[offset];
            offset += 1;
            break;
        case '@':
            len = (uint32_t *)va_arg(argp, int *);
            ret = tcm_buffer_load32(tb, offset, len);
            if ((ret & ERR_MASK)) {
                return ret;
            }
            offset += 4;
            ptr = (unsigned char *)va_arg(argp, unsigned char *);
            if (*len > 0 && ptr == NULL) return -3;
            if (offset + *len > tb->used) return ERR_BUFFER;
            if (*len > 0) memcpy(ptr, &tb->buffer[offset], *len);
            offset += *len;
            break;
        case '*': /* a sized buffer with 32bit size indicator whose
		               buffer needs to be allocated */
            len = (uint32_t *)va_arg(argp, int *);
            ret = tcm_buffer_load32(tb, offset, len);
            if ((ret & ERR_MASK)) {
                return ret;
            }
            offset += 4;
            pptr = (unsigned char **)va_arg(argp, unsigned char **);
            if (*len > 0 && pptr == NULL) return -3;
            if (offset + *len > tb->used) return ERR_BUFFER;
            if (*len > 0) {
                buf = malloc(*len);
                if (NULL == buf) return ERR_MEM_ERR;
                *pptr = buf;
                memcpy(buf, &tb->buffer[offset], *len);
            }
            offset += *len;
            break;
        case '&': /* a sized buffer with 16bit size indicator whose
		               buffer needs to be allocated */
            len16 = (uint16_t *)va_arg(argp, uint16_t *);
            ret = tcm_buffer_load16(tb, offset, len16);
            if ((ret & ERR_MASK)) {
                return ret;
            }
            offset += 2;
            pptr = (unsigned char **)va_arg(argp, unsigned char **);
            if (*len16 > 0 && pptr == NULL) return -3;
            if (offset + *len16 > tb->used) return ERR_BUFFER;
            if (*len16 > 0) {
                buf = malloc(*len16);
                if (NULL == buf) return ERR_MEM_ERR;
                *pptr = buf;
                memcpy(buf, &tb->buffer[offset], *len16);
            }
            offset += *len16;
            break;
        case '^': /* a sized buffer structure whose buffer is available */
            /* the size indicator is only 16 bits long */
            /* parameters: address of length indicator,
               maximum number of bytes
               address of buffer  */
            len16 = (uint16_t *)va_arg(argp, uint16_t *);
            lenmax = va_arg(argp, int);
            ret = tcm_buffer_load16(tb, offset, len16);
            if ((ret & ERR_MASK)) {
                return ret;
            }
            offset += 2;
            ptr = (unsigned char *)va_arg(argp, unsigned char *);
            if (*len16 > 0 && ptr == NULL) return ERR_BUFFER;
            if (offset + *len16 > tb->used) return ERR_BUFFER;
            if (*len16 > lenmax) return ERR_BUFFER;
            if (*len16 > 0) {
                memcpy(ptr, &tb->buffer[offset], *len16);
            }
            offset += *len16;
            break;
        case '!': /* a sized buffer structure whose buffer needs to be allocated */
            /* the size indicator is 32 bits long */
            /* parameters: address of length indicator,
               maximum number of bytes
               address of buffer  */
            len = (uint32_t *)va_arg(argp, int *);
            lenmax = va_arg(argp, int);
            ret = tcm_buffer_load32(tb, offset, len);
            if ((ret & ERR_MASK)) {
                return ret;
            }
            offset += TCM_U32_SIZE;
            ptr = (unsigned char *)va_arg(argp, unsigned char *);
            if (*len > 0 && ptr == NULL) return -3;
            if (offset + *len > tb->used) return ERR_BUFFER;
            if (*len > lenmax) return ERR_BUFFER;
            if (*len > 0) {
                memcpy(ptr, &tb->buffer[offset], *len);
            }
            offset += *len;
            break;
        case '#': /* a sized buffer structure whose buffer needs to be allocated */
            /* reverse the data (good for 'exponent') */
            /* the size indicator is 32 bits long */
            /* parameters: address of length indicator,
               maximum number of bytes
               address of buffer  */
            len = (uint32_t *)va_arg(argp, int *);
            lenmax = va_arg(argp, int);
            ret = tcm_buffer_load32(tb, offset, len);
            if ((ret & ERR_MASK)) {
                return ret;
            }
            offset += TCM_U32_SIZE;
            ptr = (unsigned char *)va_arg(argp, unsigned char *);
            if (*len > 0 && ptr == NULL) return -3;
            if (offset + *len > tb->used) return ERR_BUFFER;
            if (*len > lenmax) return ERR_BUFFER;
            length = *len;
            while (length > 0) {
                *ptr = tb->buffer[offset + length - 1];
                length--;
                ptr++;
            }
            offset += *len;
            break;
        case '%':
            length = (int)va_arg(argp, int);
            if (offset + length > tb->used) return ERR_BUFFER;
            ptr = (unsigned char *)va_arg(argp, unsigned char *);
            if (length > 0 && ptr == NULL) return ERR_NULL_ARG;
            if (length > 0) memcpy(ptr, &tb->buffer[offset], length);
            offset += length;
            ptr = NULL;
            break;
        default:
            return ERR_BAD_ARG;
        }
        ++p;
    }
    va_end(argp);

    return offset - start;
}

/****************************************************************************/
/*                                                                          */
/*  optional verbose logging of data to/from tcm chip                       */
/*                                                                          */
/****************************************************************************/
void showBuff(unsigned char *buff, char *string)
{
    uint32_t i, len;
    uint32_t addsize = 0;
    if (use_vtcm) {
        addsize = 4;
    }

    if (!logflag) return;
    len = addsize + LOAD32(buff, addsize + TCM_PARAMSIZE_OFFSET);

    printf("%s length=%d\n", string, (int)len);
    for (i = 0; i < len; i++) {
        if (i && !( i % 16 )) {
            printf("\n");
        }
        printf("%.2X ", buff[i]);
    }
    printf("\n");
}

uint32_t TCM_Send(struct tcm_buffer *tb, const char *msg)
{
    uint32_t rc = 0;
    int sock_fd;

    if (!actual_used_transport) {
        TCM_LowLevel_Transport_Init (TCM_LOWLEVEL_TRANSPORT_DEV);
    }

    /* To emulate the real behavior, open and close the socket each
       time.  If this kills performance, we can introduce a static and
       keep the socket open. */
    if (rc == 0) {
        rc = use_transp->open(&sock_fd);
    }
    if (rc == 0) {
        if (logflag) printf("\nTCM_Send: %s\n", msg);
        rc = use_transp->send(sock_fd, tb, msg);
    }
    if (rc == 0) {
        rc = use_transp->recv(sock_fd, tb);
    }
    use_transp->close(sock_fd);
    return rc;
}


static uint32_t createTransport(session *transSession, uint32_t *in_tp      )
{
    uint32_t ret = 0;
    char *tcm_transport     = getenv("TCM_TRANSPORT");
    char *tcm_transport_ek  = getenv("TCM_TRANSPORT_EK");   //KEY HANDLE
    char *tcm_transport_ekp = getenv("TCM_TRANSPORT_EKP");  //KEY AUTH
    char *tcm_transport_pass = getenv("TCM_TRANSPORT_PASS"); //Transport Session Auth
    char *tcm_transport_handle = getenv("TCM_TRANSPORT_HANDLE");
    *in_tp = 0;
    if (tcm_transport     &&
            0 == strcmp("1", tcm_transport) &&
            tcm_transport_ek  &&
            /* tcm_transport_ekp &&*/
            tcm_transport_pass ) {
        uint32_t ekhandle;
        TCM_TRANSPORT_PUBLIC ttp;
        TCM_TRANSPORT_AUTH tta;
        unsigned char *keyPassHashPtr = NULL;
        unsigned char keyPassHash[TCM_HASH_SIZE];
        unsigned char *transPassHashPtr = NULL;
        unsigned char transPassHash[TCM_HASH_SIZE];
        TCM_CURRENT_TICKS currentTicks;
        int i;
        STACK_TCM_BUFFER(buffer)
        STACK_TCM_BUFFER(secret)
        pubkeydata pubkey;
        uint32_t blocksize;

        if (1 != sscanf(tcm_transport_ek, "%x", &ekhandle)) {
            return ERR_BAD_ARG;
        }
        memset(keyPassHash, 0, TCM_HASH_SIZE);
        if (tcm_transport_ekp) {
            TSS_sm3((unsigned char *)tcm_transport_ekp,
                    strlen(tcm_transport_ekp),
                    keyPassHash);
        }
        keyPassHashPtr = keyPassHash;
        if (tcm_transport_pass) {
            TSS_sm3((unsigned char *)tcm_transport_pass,
                    strlen(tcm_transport_pass),
                    transPassHash);
            transPassHashPtr = transPassHash;
        }
        ttp.tag = TCM_TAG_TRANSPORT_PUBLIC;
        ttp.transAttributes = TCM_TRANSPORT_ENCRYPT | TCM_TRANSPORT_LOG;

        _TCM_getTransportAlgIdEncScheme(&ttp.algId, &ttp.encMode, &blocksize);
        //lyf
        tta.tag = TCM_TAG_TRANSPORT_AUTH;
        for (i = 0; i < TCM_AUTHDATA_SIZE; i ++) {
            tta.authData[i] = transPassHashPtr[i];
        }
        TCM_WriteTransportAuth(&buffer, &tta);
        //lyf
        ret = TCM_GetPubKey_UseRoom(ekhandle,
                                    keyPassHashPtr,
                                    &pubkey   );
        if (ret != 0) {
            printf("tcmutil: Error '%s' from TCM_GetPubKey_UseRoom(0x%08x)\n",
                   TCM_GetErrMsg(ret), ekhandle);
            return ret;
        }

        secret.used = secret.size;
        TCM_encrypt(&secret, &buffer, &pubkey);

        ret = TCM_EstablishTransport_UseRoom(ekhandle,
                                             keyPassHashPtr,
                                             &ttp,
                                             transPassHashPtr,
                                             &secret,
                                             &currentTicks,
                                             transSession );
        if (ret == 0) {
            uint32_t idx = 1;
            TSS_PushTransportFunction(TCM_ExecuteTransport,
                                      &idx);

            TSS_SetTransportParameters(transSession, idx);
        } else {
            printf("Error %s from EstablishTransport.\n",
                   TCM_GetErrMsg(ret));
        }
        ret = 0;
        *in_tp = 1;
    } else if (tcm_transport     &&
               0 == strcmp("2", tcm_transport) &&
               tcm_transport_pass &&
               tcm_transport_handle ) {
        unsigned char transPassHash[TCM_HASH_SIZE];
        unsigned char *transSeq;
        uint32_t transSeqSize;
        uint32_t transhandle;
        uint32_t ret;
        uint32_t idx;

        ret = parseHash((char *)tcm_transport_pass,
                        transPassHash);
        if ((ret & ERR_MASK)) {
            return ret;
        }

        ret = TCM_ReadFile(".enonce",
                           &transSeq,
                           &transSeqSize);

        if ((ret & ERR_MASK)) {
            return ret;
        }

        if (1 != sscanf(tcm_transport_handle,
                        "%x",
                        &transhandle)) {
            return ERR_BAD_ARG;
        }

        TSS_Session_CreateTransport(transSession,
                                    transPassHash,
                                    transhandle,
                                    transSeq);
        TSS_PushTransportFunction(TCM_ExecuteTransport,
                                  &idx);

        TSS_SetTransportParameters(transSession, idx);
        *in_tp = 1;
    } else {
        if ((tcm_transport && !strcmp("1", tcm_transport) &&
                (!tcm_transport_ek  ||
                 /*  !tcm_transport_ekp ||*/		//lyf
                 !tcm_transport_pass)
            ) ||
                (tcm_transport && !strcmp("2", tcm_transport) &&
                 (!tcm_transport_pass || !tcm_transport_handle)
                )
           ) {
#if 0
            printf("Something is wrong with the environment variables:\n"
                   "TCM_TRANSPORT	= %s\n"
                   "TCM_TRANSPORT_EK     = %s\n"
                   "TCM_TRANSPORT_EKP    = %s\n"
                   "TCM_TRANSPORT_PASS   = %s\n"
                   "TCM_TRANSPORT_HANDLE = %s\n",
                   tcm_transport,
                   tcm_transport_ek,
                   tcm_transport_ekp,
                   tcm_transport_pass,
                   tcm_transport_handle);
#endif
            //		ret = ERR_ENV_VARIABLE;
        }
    }
    return ret;
}

static uint32_t destroyTransport(session *transSession      )
{
    uint32_t ret = 0;
    char *tcm_transport     = getenv("TCM_TRANSPORT");
    char *tcm_transport_sk  = getenv("TCM_TRANSPORT_SK");  //sign keyhandle
    char *tcm_transport_skp = getenv("TCM_TRANSPORT_SKP"); //sign key auth
    TCM_DIGEST transDigest;
    if (tcm_transport     &&
            0 == strcmp("1", tcm_transport) &&
            tcm_transport_sk /*&&
	    tcm_transport_skp*/) {				//lyf
        unsigned char *keyPassHashPtr = NULL;
        unsigned char keyPassHash[TCM_HASH_SIZE];
        uint32_t skhandle;
        unsigned char antiReplay[TCM_NONCE_SIZE];
        uint32_t idx = 0;
        pubkeydata pk;
        STACK_TCM_BUFFER (signature);

        if (1 != sscanf(tcm_transport_sk, "%x", &skhandle)) {
            return ERR_BAD_ARG;
        }
        memset(keyPassHash, 0, TCM_HASH_SIZE);
        if (tcm_transport_skp) {
            TSS_sm3((unsigned char *)tcm_transport_skp,
                    strlen(tcm_transport_skp),
                    keyPassHash);
        }
        keyPassHashPtr = keyPassHash;
        ret = TCM_GetPubKey(skhandle,
                            keyPassHashPtr,
                            &pk);
        TSS_PopTransportFunction(&idx);
        if(ret == 0) {
            ret = TCM_ReleaseTransport(transSession );
        }
        if(ret == 0) {

            ret = os_sm2_verify(transDigest, TCM_HASH_SIZE, pk.pubKey.modulus, pk.pubKey.keyLength, signature.buffer, signature.used);
        }
    } else if (tcm_transport &&
               0 == strcmp("2", tcm_transport)) {
        uint32_t idx = 0;
        ret = TCM_WriteFile(".enonce",
                            TSS_Session_GetSeq(transSession),
                            TCM_SEQ_SIZE);
        TSS_PopTransportFunction(&idx);
    }
    return ret;
}


extern uint32_t (*g_transportFunction[])(struct tcm_buffer *tb,
        const char *msg);
extern uint32_t g_num_transports;


static uint32_t TCM_Transmit_Internal(struct tcm_buffer *tb, const char *msg,
                                      int allowTransport)
{
    uint32_t rc = 0, irc;
    static int transport_created = 0;

    if (0 == transport_created) {
        uint32_t ord = 0;
        session sess;
        tcm_buffer_load32(tb, 6, &ord);
        transport_created = 1;
        if (allowTransport && allowsTransport(ord)) {
            uint32_t in_tp;
            irc = 0;
            /*
               don't have createTransport assign irc
               it also is called if the transport is invalid
               in_tp returns '1' if the transport should be destroyed
             */
            createTransport(&sess, &in_tp          );
            if (irc == 0) {
                rc = TCM_Transmit(tb, msg);
            }
            if (in_tp) {
                /* don't assign it the return value! It works fine
                   without propagating possible errors upwards.*/
                /*irc =*/ destroyTransport(&sess          );
            }
            if (irc != 0) {
                rc = irc;
            }
        } else {
            rc = TCM_Transmit(tb, msg);
        }
        transport_created = 0;
        return rc;
    }

    if (g_num_transports > 0 && NULL != g_transportFunction[g_num_transports - 1]) {

        --g_num_transports;
        /*
         * I cannot do the auditing here. Must do this in
         * all transports separately.
         */
        rc = g_transportFunction[g_num_transports](tb, msg);
        if (0 == rc) {
            /*
             * Transport function was doing OK, so let me see whether
             * the caller also did OK.
             */
            tcm_buffer_load32(tb, TCM_RETURN_OFFSET, &rc);
            if(rc == TCM_USER_NO_PRIVILEGE) {
                tcm_buffer_load32(tb, TCM_PRIVCODE_OFFSET, &rc);
            }
        }
        g_num_transports++;
    } else {
        char mesg[1024];
        unsigned int inst = 0;
        unsigned int locty = 0;
        uint16_t tag_out = 0;
        //uint16_t tag_in = 0;
        uint32_t ordinal = 0;
        unsigned int tagoffset = 0;
        unsigned char *buff = tb->buffer;
        uint32_t resp_result = 0;
        struct tcm_buffer *orig_request;
        /*
         * NEVER prepend anything when using a chardev since I could be
         * talking to a hardware TCM. If I am talking to a chardev in
         * a virtualized system, the prepending will happen on the
         * receiving side in the driver layer.
         * DO prepend for sockets - assumption is that such a TCM does
         * not really exits and we are only using this for testing
         * purposes.
         */
        unsigned int ret_inst = 0;
        char *instance = getenv("TCM_INSTANCE");
        char *locality = getenv("TCM_USE_LOCALITY");
        tcm_buffer_load32(tb, 6, &ordinal);

#if 0
        /* older specs always audited independent of result return code */
        _TCM_AuditInputstream(tb, 0);
#else
        /* newer specs require late auditing since only audited upon success */
        orig_request = clone_tcm_buffer(tb  );

        if(orig_request == NULL) {
            printf("TCM_Transmit_InternalWithLoc: clone tcm buffer failed!\n");
            return -1;
        }
#endif

        if (use_vtcm) {
            /*
             * Check whether an instance of the TCM is to be used.
             */
            if (NULL != instance) {
                inst = (unsigned int)atoi(instance);
            }
            if (NULL != locality) {
                locty = (unsigned int)atoi(locality);
                if (locty > 4) {
                    locty = 0;
                }
                /* add locality into bits 31-29 of instance identifier */
                inst = (inst & 0x1fffffff) | (locty << 29);
            }
            if (tb->used + 4 >= tb->size) {
                TSS_FreeTCMBuffer(orig_request);
                return -1;
            }
            memmove(&buff[4], &buff[0], tb->used);
            buff[0] = (inst >> 24) & 0xff;
            buff[1] = (inst >> 16) & 0xff;
            buff[2] = (inst >>  8) & 0xff;
            buff[3] = (inst >>  0) & 0xff;
            tb->used += 4;

            tagoffset = 4;
        }

        tcm_buffer_load16(tb, tagoffset, &tag_out);
        if (use_vtcm)
            sprintf(mesg, "%s (instance=%d, locality=%d)", msg, inst, locty);
        else
            sprintf(mesg, "%s", msg);
        rc = TCM_Send(tb, mesg);
#if 0
#if 0
        if (actual_used_transport != TCM_LOWLEVEL_TRANSPORT_CHARDEV) {
            /*
             * For some reason the HW TCM seems to return a wrong initial byte
             * when doing a Quote(). So I have to deactivate this part here
             * when talking to a chardev!
             */
            if (0 == rc) {
                tcm_buffer_load16(tb, tagoffset, &tag_in);
                if ((tag_in - 3)  != tag_out) {
                    rc = ERR_BADRESPONSETAG;
                }
            }
        }
#endif
        if (use_vtcm) {
            /*
             * Only when using character device I do not expect the instance number to come back
             */
            ret_inst = ntohl( *((uint32_t *)&buff[0]) );
            if (inst != ret_inst) {
                printf("Returned instance bad (0x%x != 0x%x)\n", inst, ret_inst);
                return -1;
            }
            tb->used -= 4;
            memmove(&buff[0], &buff[4], tb->used);
        }

#if 0
        _TCM_AuditOutputstream(tb, ordinal, 0);
#else
        tcm_buffer_load32(tb, 6, &resp_result);
        /*
        * Execute Transport is audited outside ( in _TCM_ExecuteTransport func).
        */
        if (resp_result == 0 && (ordinal != TCM_ORD_ExecuteTransport)) {
            _TCM_AuditInputstream(orig_request, 0);
            _TCM_AuditOutputstream(tb, ordinal, 0);
        }
#endif

        if (0 == rc) {
            uint32_t used = 0;
            tcm_buffer_load32(tb, 2, &used);
            if (tb->used != used) {
                rc = ERR_BAD_RESP;
            }
        }
        if (0 == rc) {
            tcm_buffer_load32(tb, TCM_RETURN_OFFSET, &rc);

            if(rc == TCM_USER_NO_PRIVILEGE) {
                tcm_buffer_load32(tb, TCM_PRIVCODE_OFFSET, &rc);
            }
        }
#endif
        TSS_FreeTCMBuffer(orig_request);
    }
    return rc;
}


uint32_t TCM_Transmit(struct tcm_buffer *tb, const char *msg)
{
    return TCM_Transmit_Internal(tb, msg, 1);
}

uint32_t TCM_Transmit_NoTransport(struct tcm_buffer *tb, const char *msg)
{
    return TCM_Transmit_Internal(tb, msg, 0);
}


/****************************************************************************/
/*									  */
/* Perform a SHA1 hash on a single buffer				   */
/*									  */
/****************************************************************************/
void TSS_sm3(void *input, unsigned int len, unsigned char *output)
{
    sm3_context sm3c;

    sm3_init(&sm3c);
    sm3_update(&sm3c, input, len);
    sm3_finish(&sm3c, output);
}


unsigned int SM3_valist(TCM_DIGEST md, uint32_t length0, unsigned char *buffer0, va_list ap)
{
    TCM_RESULT 	rc = 0;
    uint32_t		length;
    unsigned char	*buffer;
    sm3_context context;	/* platform dependent context */
    TCM_BOOL		done = FALSE;

    //printf(" SM3_valist:\n");
    if (rc == 0) {
        rc = sm3_init(&context);
    }
    if (rc == 0) {
        if (length0 != 0) {		/* optional first text block */
            //printf("  SM3_valist: Digesting %u bytes\n", length0);
            rc = sm3_update(&context, buffer0, length0);	/* hash the buffer */
        }
    }
    while ((rc == 0) && !done) {
        length = va_arg(ap, uint32_t);		/* first vararg is the length */
        if (length != 0) {			/* loop until a zero length argument terminates */
            buffer = va_arg(ap, unsigned char *);	/* second vararg is the array */
            //printf("  SM3_valist: Digesting %u bytes\n", length);
            rc = sm3_update(&context, buffer, length);	/* hash the buffer */
        } else {
            done = TRUE;
        }
    }
    if (rc == 0) {
        rc = sm3_finish(&context, md);
    }
    return rc;
}



/****************************************************************************/
/*									  */
/* Perform a SHA1 hash on a file					    */
/*									  */
/****************************************************************************/
uint32_t TSS_SM3File(const char *filename, unsigned char *buffer)
{
    uint32_t ret = 0;
    FILE *f;
    f = fopen(filename, "r");

    if (NULL != f) {
        size_t len;
        unsigned char mybuffer[10240];
        sm3_context sha;
        sm3_init(&sha);
        do {
            len = fread(mybuffer, 1, sizeof(mybuffer), f);
            if (len) {
                sm3_update(&sha, mybuffer, len);
            }
        } while (len == sizeof(mybuffer));
        fclose(f);
        sm3_finish(&sha , buffer);
    } else {
        ret = ERR_BAD_FILE;
    }
    return ret;
}

/****************************************************************************/
/*									  */
/* set logging flag							 */
/*									  */
/****************************************************************************/
int TCM_setlog(int flag)
{
    int old;
    char *dump = getenv("TCM_DUMP_COMMANDS");

    old = logflag;
    /* user has control if TCM_DUMP_COMMANDS == "0" */
    if (NULL == dump || strcmp(dump, "0") == 0)
        logflag = flag;
    return old;
}

uint32_t tcm_buffer_load32(const struct tcm_buffer *tb, uint32_t off, uint32_t *val)
{
    //	printf("%s:\n",__func__);
    if (off + 3 >= tb->used) {
        return ERR_BUFFER;
    }
    *val = LOAD32(tb->buffer, off);
    return 0;
}

uint32_t tcm_buffer_store32(struct tcm_buffer *tb, uint32_t val)
{
    if (tb->used + 4 > tb->size) {
        return ERR_BUFFER;
    }
    STORE32(tb->buffer, tb->used, val);
    tb->used += 4;
    return 0;
}

uint32_t tcm_buffer_load32N(const struct tcm_buffer *tb, uint32_t off, uint32_t *val)
{
    if (off + 3 >= tb->used) {
        return ERR_BUFFER;
    }
    *val = LOAD32N(tb->buffer, off);
    return 0;
}

uint32_t tcm_buffer_load16(const struct tcm_buffer *tb, uint32_t off, uint16_t *val)
{
    if (off + 1 >= tb->used) {
        return ERR_BUFFER;
    }
    *val = LOAD16(tb->buffer, off);
    return 0;
}

uint32_t tcm_buffer_load16N(const struct tcm_buffer *tb, uint32_t off, uint16_t *val)
{
    if (off + 1 >= tb->used) {
        return ERR_BUFFER;
    }
    *val = LOAD16N(tb->buffer, off);
    return 0;
}

uint32_t tcm_buffer_store(struct tcm_buffer *dest, struct tcm_buffer *src,
                          uint32_t soff, uint32_t slen)
{
    if (dest->used + slen > dest->size ||
            soff + slen > src->size) {
        return ERR_BUFFER;
    }
    memcpy(&dest->buffer[dest->used],
           &src ->buffer[soff],
           slen);
    dest->used += slen;
    return 0;
}

uint32_t parseHash(char *string, unsigned char *hash)
{
    uint32_t ret = 0;
    uint32_t i = 0;
    unsigned char byte = 0;
    while (i < 64) {
        byte <<= 4;
        if (string[i] >= '0' && string[i] <= '9') {
            byte |= string[i] - '0';
        } else if (string[i] >= 'A' && string[i] <= 'F') {
            byte |= string[i] - 'A' + 10;
        } else if (string[i] >= 'a' && string[i] <= 'f') {
            byte |= string[i] - 'a' + 10;
        } else {
            return 1;
        }
        hash[i / 2] = byte;
        i++;
    }
    return ret;
}

/****************************************************************************/
/*									  */
/* AES CTR mode - non-standard TPM increment				*/
/*									  */
/****************************************************************************/

/* TPM_AES_ctr128_encrypt() is a TPM variant of the openSSL AES_ctr128_encrypt() function that
   increments only the low 4 bytes of the counter.

   openSSL increments the entire CTR array.  The TPM does not follow that convention.
*/
#if 0
TPM_RESULT TCM_AES_ctr128_Encrypt(unsigned char *data_out,
                                  const unsigned char *data_in,
                                  unsigned long data_size,
                                  const AES_KEY *aes_enc_key,
                                  unsigned char ctr[TPM_AES_BLOCK_SIZE])
{
    TPM_RESULT 	rc = 0;
    uint32_t cint;
    unsigned char pad_buffer[TPM_AES_BLOCK_SIZE];	/* the XOR pad */

    while (data_size != 0) {
        /* get an XOR pad array by encrypting the CTR with the AES key */
        AES_encrypt(ctr, pad_buffer, aes_enc_key);
        /* partial or full last data block */
        if (data_size <= TPM_AES_BLOCK_SIZE) {
            TPM_XOR(data_out, data_in, pad_buffer, data_size);
            data_size = 0;
        }
        /* full block, not the last block */
        else {
            TPM_XOR(data_out, data_in, pad_buffer, TPM_AES_BLOCK_SIZE);
            data_in += TPM_AES_BLOCK_SIZE;
            data_out += TPM_AES_BLOCK_SIZE;
            data_size -= TPM_AES_BLOCK_SIZE;
        }
        /* if not the last block, increment CTR */
        if (data_size != 0) {
            cint = LOAD32(ctr, 12);	/* byte array to uint32_t */
            cint++;			/* increment */
            STORE32(ctr, 12, cint);	/* uint32_t to byte array */
        }
    }
    return rc;
}
#endif
TCM_RESULT TCM_SM4_ctr128_encrypt(unsigned char *data_out,
                                  const unsigned char *data_in,
                                  uint32_t data_size,
                                  unsigned char key[16],
                                  unsigned char ctr[TCM_SM4_BLOCK_SIZE])
{
    int rc = 0;
    uint32_t cint;
    unsigned char pad_buffer[16];       /* the XOR pad */
    unsigned char *output = NULL;	//lyf
    //unsigned int outlen;		//lyf
    sm4_context ctx; //lyf

    printf("  TCM_SM4_ctr128_encrypt:\n");
    output = (unsigned char *)malloc(data_size);//lyf
    sm4_importkey(&ctx, key, NULL);				//lyf
    while (data_size != 0) {
        printf("   TCM_SM4_ctr128_encrypt: data_size %lu\n", (unsigned long)data_size);
        /* get an XOR pad array by encrypting the CTR with the SM4 key */
        //TCM_SM4Encrypt( &output, &outlen,key, NULL,/*FM_ALGMODE_CBC,*/ctr, 16);
        sm4_encrypt_nopadding(&ctx, FM_ALGMODE_ECB, ctr, 16, output);
        memcpy(pad_buffer, output, 16);
        /* partial or full last data block */
        if (data_size <= 16) {
            TCM_XOR(data_out, data_in, pad_buffer, data_size);
            data_size = 0;
        }
        /* full block, not the last block */
        else {
            TCM_XOR(data_out, data_in, pad_buffer, 16);
            data_in += 16;
            data_out += 16;
            data_size -= 16;
        }
        /* if not the last block, increment CTR, only the low 4 bytes */
        if (data_size != 0) {
            /* CTR is a big endian array, so the low 4 bytes are 12-15 */
            cint = LOAD32(ctr, 12);     /* byte array to uint32_t */
            cint++;                     /* increment */
            STORE32(ctr, 12, cint);     /* uint32_t to byte array */
        }
    }
    free(output);
    return rc;
}




/* TPM_XOR XOR's 'in1' and 'in2' of 'length', putting the result in 'out'

 */

static void TCM_XOR(unsigned char *out,
                    const unsigned char *in1,
                    const unsigned char *in2,
                    size_t length)
{
    size_t i;

    for (i = 0 ; i < length ; i++) {
        out[i] = in1[i] ^ in2[i];
    }
    return;
}

/* TSS_MGF1() generates an MGF1 'array' of length 'arrayLen' from 'seed' of length 'seedlen'

   The openSSL DLL doesn't export MGF1 in Windows or Linux 1.0.0, so this version is created from
   scratch.

   Algorithm and comments (not the code) from:

   PKCS #1: RSA Cryptography Specifications Version 2.1 B.2.1 MGF1

   Prototype designed to be compatible with openSSL

   MGF1 is a Mask Generation Function based on a hash function.

   MGF1 (mgfSeed, maskLen)

   Options:

   Hash hash function (hLen denotes the length in octets of the hash
   function output)

   Input:

   mgfSeed         seed from which mask is generated, an octet string
   maskLen         intended length in octets of the mask, at most 2^32(hLen)

   Output:
   mask            mask, an octet string of length l; or "mask too long"

   Error:          "mask too long'
*/
#if 0
TCM_RESULT TSS_MGF1(unsigned char       *mask,
                    uint32_t            maskLen,
                    const unsigned char *mgfSeed,
                    uint32_t            mgfSeedlen)
{
    TCM_RESULT 		rc = 0;
    unsigned char       counter[4];     /* 4 octets */
    unsigned long       count;          /* counter as an integral type */
    unsigned long       outLen;
    TCM_DIGEST          lastDigest;

    if (rc == 0) {
        /* this is possible with arrayLen on a 64 bit architecture, comment to quiet beam */
        if ((maskLen / TCM_DIGEST_SIZE) > 0xffffffff) {        /*constant condition*/
            printf(" TSS_MGF1: Error (fatal), Output length too large for 32 bit counter\n");
            rc = TCM_FAIL;              /* should never occur */
        }
    }
    /* 1.If l > 2^32(hLen), output "mask too long" and stop. */
    /* NOTE Checked by caller */
    /* 2. Let T be the empty octet string. */
    /* 3. For counter from 0 to [masklen/hLen] - 1, do the following: */
    for (count = 0, outLen = 0 ; (rc == 0) && (outLen < (unsigned long)maskLen) ; count++) {
        uint32_t count_n = htonl(count);
        /* a. Convert counter to an octet string C of length 4 octets - see Section 4.1 */
        /* C = I2OSP(counter, 4) NOTE Basically big endian */
        memcpy(&counter[0], &count_n, 4);
        /* b.Concatenate the hash of the seed mgfSeed and C to the octet string T: */
        /* T = T || Hash (mgfSeed || C) */
        /* If the entire digest is needed for the mask */
        if ((outLen + TCM_DIGEST_SIZE) < (unsigned long)maskLen) {
            rc = TSS_SHA1(mask + outLen,
                          mgfSeedlen, mgfSeed,
                          4, counter,
                          0, NULL);
            outLen += TCM_DIGEST_SIZE;
        }
        /* if the mask is not modulo TCM_DIGEST_SIZE, only part of the final digest is needed */
        else {
            /* hash to a temporary digest variable */
            rc = TSS_SHA1(lastDigest,
                          mgfSeedlen, mgfSeed,
                          4, counter,
                          0, NULL);
            /* copy what's needed */
            memcpy(mask + outLen, lastDigest, maskLen - outLen);
            outLen = maskLen;           /* outLen = outLen + maskLen - outLen */
        }
    }
    /* 4.Output the leading l octets of T as the octet string mask. */
    return rc;
}
#endif
TCM_RESULT TSS_KDF1(unsigned char       *mask,
                    uint32_t            maskLen,
                    const unsigned char *mgfSeed,
                    uint32_t		mgfSeedlen)
{
    TCM_RESULT 		rc = 0;

    printf(" TCM_KDF1: Output length %u\n", maskLen);
    if (rc == 0) {
        os_sm_kdf(mgfSeed, mgfSeedlen, maskLen, mask);
    }
    return rc;
}

/* TSS_SHA1() can be called directly to hash a list of streams.

   The ... arguments to be hashed are a list of the form
   size_t length, unsigned char *buffer
   terminated by a 0 length
*/

TCM_RESULT TSS_SM3(TCM_DIGEST md, ...)
{
    TCM_RESULT	rc = 0;
    va_list	ap;

    va_start(ap, md);
    rc = TCMC_SM3_valist(md, 0, NULL, ap);
    va_end(ap);
    return rc;
}

/* SHA1_valist() is the internal function, called with the va_list already created.

   It is called from TSS_SHA1() to do a simple hash.  Typically length0==0 and buffer0==NULL.

   It can also be called from the HMAC function to hash the variable number of input parameters.  In
   that case, the va_list for the text is already formed.  length0 and buffer0 are used to input the
   padded key.
*/
TCM_RESULT TCMC_SM3_valist(TCM_DIGEST md,
                           uint32_t length0, unsigned char *buffer0,
                           va_list ap)
{
    TCM_RESULT		rc = 0;
    TCM_RESULT		rc1 = 0;
    uint32_t		length;
    unsigned char	*buffer;
    void		*context = NULL;	/* platform dependent context */
    TCM_BOOL		done = FALSE;

    if (rc == 0) {
        rc = TCMC_SM3Init(&context);
    }
    if (rc == 0) {
        if (length0 != 0) {		/* optional first text block */
            rc =  TCMC_SM3_Update(context, buffer0, length0);	/* hash the buffer */
        }
    }
    while ((rc == 0) && !done) {
        length = va_arg(ap, uint32_t);			/* first vararg is the length */
        if (length != 0) {			/* loop until a zero length argument terminates */
            buffer = va_arg(ap, unsigned char *);	/* second vararg is the array */
            rc =  TCMC_SM3_Update(context, buffer, length);	/* hash the buffer */
        } else {
            done = TRUE;
        }
    }
    if (rc == 0) {
        rc =  TCMC_SM3Final(md, context);
    }
    if (rc == 0) {
    }
    /* previous errors have priority, but call Delete even if there was an error */
    rc1 =  TCMC_SM3Delete(&context);
    if (rc == 0) {	/* if no processing error */
        rc = rc1;	/* report Delete error */
    }
    return rc;
}

/* for the openSSL version, TPM_SHA1Context is a SHA_CTX structure */

/* TPM_SHA1Init() initializes a platform dependent TPM_SHA1Context structure.

   The structure must be freed using TPM_SHA1Final()
*/

static TCM_RESULT TCMC_SM3Init(void **context)
{
    TCM_RESULT  rc = 0;

    if (rc == 0) {
        *context = malloc(sizeof(sm3_context));
        if (*context == NULL) {
            rc = ERR_MEM_ERR;
        }
    }
    if (rc == 0) {
        sm3_init(*context);
    }
    return rc;
}


static TCM_RESULT TCMC_SM3_Update(void *context, const unsigned char *data, uint32_t length)
{
    TCM_RESULT  rc = 0;

    if (context != NULL) {
        sm3_update(context, data, length);
    } else {
        rc = TCM_SM3_THREAD;
    }
    return rc;
}


static TCM_RESULT TCMC_SM3Final(unsigned char *md, void *context)
{
    TCM_RESULT  rc = 0;

    if (context != NULL) {
        sm3_finish(context , md);
    } else {
        rc = TCM_SM3_THREAD;
    }
    return rc;
}

static TCM_RESULT TCMC_SM3Delete(void **context)
{
    if (*context != NULL) {
        free(*context);
        *context = NULL;
    }
    return 0;
}

TCM_RESULT TCM_SM4Encrypt(unsigned char **output,
                          unsigned int *olen,
                          unsigned char key[16],
                          unsigned char iv[16],
                          //int mode,
                          unsigned char *message,
                          unsigned int len)
{
    int ret = 0;
    sm4_context ctx;
    int mode = TCM_ES_SM4_CBC;

    sm4_importkey(&ctx, key, iv);

    *olen = (len / 16 + 1) * 16;
    *output = (unsigned char *)malloc((*olen));
    if((*output) == NULL) {
        printf("mallocerror!\n");
        return 1;
    }
    sm4_encrypt(&ctx, mode, message, len, *output, (int *)olen);
    return ret;
}


TCM_RESULT TCM_SM4Decrypt(unsigned char **output,
                          unsigned int *olen,
                          unsigned char key[16],
                          unsigned char iv[16],
                          //int mode,
                          unsigned char *message,
                          unsigned int len)
{
    int ret = 0;
    sm4_context ctx;
    int mode = TCM_ES_SM4_CBC;

    sm4_importkey(&ctx, key, iv);

    *output = (unsigned char *)malloc((len));
    if((*output) == NULL) {
        printf("mallocerror!\n");
        return 1;
    }
    sm4_decrypt(&ctx, mode, message, len, *output, (int *)olen);
    return ret;
}



/* TCM_SymmetricKeyData_StreamCrypt() encrypts or decrypts 'data_in' to 'data_out '

   It assumes that the size of data_out and data_in are equal, and that a stream cipher mode is
   used.  For the supported stream ciphers, encrypt and decrypt are equivalent, so no direction flag
   is required.

   SM4 with CTR or OFB modes are supported.	 For CTR mode, pad is the initial count, all zero.  For OFB
   mode, pad is the IV.

   OFB not  support.
*/

TCM_RESULT TCM_SymmetricKeyData_StreamCrypt(unsigned char *data_out,		/* output */
        const unsigned char *data_in,	/* input */
        uint32_t data_size,			/* input */
        TCM_ALGORITHM_ID algId,		/* algorithm */
        TCM_ENC_SCHEME mode,		/* mode */
        unsigned char *symmetric_key, /* input */
        uint32_t symmetric_key_size,	/* input */
        unsigned char *pad_in,		/* input */
        uint32_t pad_in_size)		/* input */
{
    TCM_RESULT		rc = 0;

    printf(" TCM_SymmetricKeyData_StreamCrypt:\n");
    switch (algId) {
    case TCM_ALG_SM4:
        switch (mode) {
        case TCM_ES_SM4_CTR:
            rc = TCM_SymmetricKeyData_CtrCrypt(data_out,
                                               data_in,
                                               data_size,
                                               symmetric_key,
                                               symmetric_key_size,
                                               pad_in,
                                               pad_in_size);
            break;
        case TCM_ES_SM4_OFB:
            rc = TCM_SymmetricKeyData_OfbCrypt(data_out,
                                               data_in,
                                               data_size,
                                               symmetric_key,
                                               symmetric_key_size,
                                               pad_in,
                                               pad_in_size);
            break;
        default:
            printf("TCM_SymmetricKeyData_StreamCrypt: Error, bad SM4 encScheme %04x\n",
                   mode);
            rc = TCM_INAPPROPRIATE_ENC;
            break;
        }
        break;
    default:
        printf("TCM_SymmetricKeyData_StreamCrypt: Error, bad algID %08x\n", algId);
        rc = TCM_INAPPROPRIATE_ENC;
        break;
    }
    return rc;
}



/* TCM_SymmetricKeyData_CtrCrypt() does an encrypt or decrypt (they are the same XOR operation with
   a CTR mode pad) of 'data_in' to 'data_out'.

   NOTE: This function looks general, but is currently hard coded to SM4.

   'symmetric key' is the raw key, not converted to a non-portable form
   'ctr_in' is the initial CTR value before possible truncation

   default iv are all zero.
*/

TCM_RESULT TCM_SymmetricKeyData_CtrCrypt(unsigned char *data_out,               /* output */
        const unsigned char *data_in,          /* input */
        uint32_t data_size,			/* input */
        unsigned char *symmetric_key,    /* input */
        uint32_t symmetric_key_size,		/* input */
        const unsigned char *ctr_in,		/* input */
        uint32_t ctr_in_size)			/* input */
{
    TCM_RESULT  rc = 0;
    unsigned char ctr[16] = {0}; //{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

    printf(" TCM_SymmetricKeyData_CtrCrypt: data_size %u\n", data_size);

    /* check the input CTR size, it can be truncated, but cannot be smaller than the AES key */
    if (rc == 0) {
        if (ctr_in_size < sizeof(ctr) || ctr_in == NULL) {
#if 0
            printf("  TCM_SymmetricKeyData_CtrCrypt: Error (fatal)"
                   ", CTR size %u too small for SM4 key\n", ctr_in_size);
            rc = TCM_FAIL;              /* should never occur */
#endif
        } else {
            memcpy(ctr, ctr_in, sizeof(ctr));
        }
    }
    if (rc == 0) {
        if (symmetric_key_size < 16) {
            printf("  TCM_SymmetricKeyData_CtrCrypt: Error (fatal)"
                   ", symmetric_key size %u must be equal SM4 key size 16\n", symmetric_key_size);
            rc = TCM_FAIL;              /* should never occur */
        }
    }
    if (rc == 0) {
        /* make a truncated copy of CTR, since SM4_ctr128_encrypt alters the value */
        memcpy(ctr, ctr_in, sizeof(ctr));
        printf("  TCM_SymmetricKeyData_CtrCrypt: Calling SM4 in CTR mode\n");
        rc = TCM_SM4_ctr128_encrypt(data_out,
                                    data_in,
                                    data_size,
                                    symmetric_key,
                                    ctr);
    }
    return rc;
}


TCM_RESULT TCM_SymmetricKeyData_OfbCrypt(unsigned char *data_out,
        const unsigned char *data_in,
        uint32_t data_size,
        unsigned char *symmetric_key,
        uint32_t symmetric_key_size,
        unsigned char *ivec_in,
        uint32_t ivec_in_size)
{
    TCM_RESULT  rc = 0;
    data_out = data_out;
    data_in = data_in;
    data_size = data_size;
    symmetric_key = symmetric_key;
    symmetric_key_size = symmetric_key_size;
    ivec_in = ivec_in;
    ivec_in_size = ivec_in_size;
    printf("  TCM_SymmetricKeyData_OfbCrypt: not implemented... \n");
    return rc;
}

uint32_t TCM_encrypt(struct tcm_buffer *bufferout, struct tcm_buffer *bufferin, pubkeydata *k)
{
    uint32_t ret = 0;
    unsigned char *encryptdata = NULL;
    unsigned int len = 0;

    switch (k->algorithmParms.algorithmID) {
    case TCM_ALG_SM2:
        ret = os_sm2_encrypt_pubkey(bufferin->buffer, bufferin->used,
                                     k->pubKey.modulus, k->pubKey.keyLength,
                                     &encryptdata, &len);
        break;
    case TCM_ALG_SM4:
        ret = TCM_SM4Decrypt(&encryptdata,
                             &len,
                             k->pubKey.modulus,
                             k->algorithmParms.sm4para.IV,
                             bufferin->buffer,
                             bufferin->used);
        break;

    default:
        ret = ERR_BAD_ARG;
        break;
    }
    if(ret == 0) {
        bufferout->used = len;
        memcpy(bufferout->buffer, encryptdata, len);
        if(encryptdata) free(encryptdata);
    }
    return ret;
}


