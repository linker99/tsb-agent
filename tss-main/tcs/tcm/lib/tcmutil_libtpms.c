/********************************************************************************/
/*										*/
/*			  TCM LibTCMS Interface Functions			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tcmutil_libtcms.c 4620 2011-09-07 21:43:19Z kgoldman $		*/
/*										*/
/*			       IBM Confidential					*/
/*			     OCO Source Materials				*/
/*			 (c) Copyright IBM Corp. 2010				*/
/*			      All Rights Reserved			        */
/*										*/
/*	   The source code for this program is not published or otherwise	*/
/*	   divested of its trade secrets, irrespective of what has been		*/
/*	   deposited with the U.S. Copyright Office.				*/
/*										*/
/********************************************************************************/

#ifdef TCM_USE_LIBTCMS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "tcm_types.h"
#include "tcm_error.h"

#ifdef USE_IN_TREE_LIBTCMS

#include "../../../src/tcm_library.h"

#else

#include <libtcms/tcm_library.h>

#endif

#include "tcmutil.h"
#include "tcm_lowlevel.h"


static uint32_t TCM_OpenLibTCMS(int *sockfd);
static uint32_t TCM_CloseLibTCMS(int sockfd);
static uint32_t TCM_SendLibTCMS(int sockfd, struct tcm_buffer *tb,
                                const char *msg);
static uint32_t TCM_ReceiveLibTCMS(int sockfd, struct tcm_buffer *tb);

static struct tcm_transport libtcms_transport = {
    .open = TCM_OpenLibTCMS,
    .close = TCM_CloseLibTCMS,
    .send = TCM_SendLibTCMS,
    .recv  = TCM_ReceiveLibTCMS,
};

void TCM_LowLevel_TransportLibTCMS_Set(void)
{
    TCM_LowLevel_Transport_Set(&libtcms_transport);
}


/*
 * Functions that implement the transport
 */
static uint32_t TCM_OpenLibTCMS(int *sockfd)
{
    (void)sockfd;
    return 0;
}

static uint32_t TCM_CloseLibTCMS(int sockfd)
{
    (void)sockfd;
    return 0;
}


static uint32_t TCM_SendLibTCMS(int sockfd, struct tcm_buffer *tb,
                                const char *msg)
{
    unsigned char *respbuffer = NULL;
    uint32_t resp_size;
    uint32_t respbufsize;
    uint32_t rc;
    char mymsg[1024];

    (void)sockfd;

    snprintf(mymsg, sizeof(mymsg), "TCM_SendLibTCMS: To TCM [%s]",
             msg);

    showBuff(tb->buffer, mymsg);

    rc = TCMLIB_Process(&respbuffer, &resp_size, &respbufsize,
                        tb->buffer, tb->used);

    if (rc != TCM_SUCCESS)
        return ERR_IO;

    if (tb->size < resp_size)
        return ERR_BUFFER;

    memcpy(tb->buffer, respbuffer, resp_size);
    tb->used = resp_size;

    free(respbuffer);

    snprintf(mymsg, sizeof(mymsg), "TCM_SendLibTCMS: From TCM [%s]",
             msg);

    showBuff(tb->buffer, mymsg);

    return 0;
}


static uint32_t TCM_ReceiveLibTCMS(int sockfd, struct tcm_buffer *tb)
{
    /*
     * Doing everything in the transmit function
     */
    (void)sockfd;
    (void)tb;
    return 0;
}

#endif /* TCM_USE_LIBTCMS */

