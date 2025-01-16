/********************************************************************************/
/*										*/
/*			     	TCM Misc Command Functions			*/
/*			     Written by J. Kravitz				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: miscfunc.c 4633 2011-10-11 00:28:56Z stefanb $		*/
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
#ifdef TCM_POSIX
#include <netinet/in.h>
#endif
#ifdef TCM_WINDOWS
#include <winsock2.h>
#endif
#include <tcm.h>
#include <tcmutil.h>
#include <oiaposap.h>
#include <tcmfunc.h>
#include <hmac.h>
#include "tcm.h"
#include "tcm_constants.h"
#include "tcm_error.h"
#include "tcmutil.h"
#define HASHMAXSIZE  (4*1024*1024)



/****************************************************************************/
/*                                                                          */
/*  GetCapability                                                           */
/*                                                                          */
/****************************************************************************/
uint32_t TCM_GetCapability_Internal(uint32_t caparea,
                                    struct tcm_buffer *scap,
                                    struct tcm_buffer *response, //out

                                    int allowTransport)
{
    uint32_t ret;
    uint32_t rlen;
    uint32_t ordinal_no = htonl(TCM_ORD_GetCapability);
    STACK_TCM_BUFFER(tcmdata)       /* request/response buffer */
    uint32_t scaplen = 0;
    unsigned char *buffer = NULL;

    /* check arguments */
    if (scap) {
        scaplen = scap->used;
        buffer = scap->buffer;
    }
    if (response == NULL)
        return ERR_NULL_ARG;


    ret = TSS_buildbuff("00 c1 T l  L @", &tcmdata,
                        ordinal_no,
                        caparea,
                        scaplen, buffer);
    if ((ret & ERR_MASK) != 0)
        return ret;

    /* transmit the request buffer to the TCM device and read the reply */
    if (allowTransport)
        ret = TCM_Transmit(&tcmdata, "GetCapability");
    else
        ret = TCM_Transmit_NoTransport(&tcmdata, "GetCapability");

    if (ret != 0)
        return ret;

    ret = tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET , &rlen);
    if ((ret & ERR_MASK)) {
        return ret;
    }
    if (NULL != response) {
        SET_TCM_BUFFER(response,
                       &tcmdata.buffer[TCM_DATA_OFFSET + TCM_U32_SIZE ],
                       rlen);
    }
    return 0;
}

uint32_t TCM_GetCapability(uint32_t caparea,
                           struct tcm_buffer *scap,

                           struct tcm_buffer *response)
{
    return TCM_GetCapability_Internal(caparea, scap, response,      1);
}

uint32_t TCM_GetCapability_NoTransport(uint32_t caparea,
                                       struct tcm_buffer *scap,

                                       struct tcm_buffer *response)
{
    return TCM_GetCapability_Internal(caparea, scap, response,      0);
}


#if 0
/****************************************************************************/
/*                                                                          */
/*  GetCapabilitySigned                                                     */
/*                                                                          */
/****************************************************************************/
uint32_t TCM_GetCapabilitySigned(uint32_t keyhandle,
                                 unsigned char *keypass,
                                 unsigned char *antiReplay,
                                 uint32_t caparea,
                                 struct tcm_buffer *scap,
                                 struct tcm_buffer *resp,
                                 unsigned char *sig , uint32_t *siglen)
{
    uint32_t ret;
    uint32_t rlen;
    STACK_TCM_BUFFER(tcmdata)       /* request/response buffer */
    uint32_t ordinal_no = htonl(TCM_ORD_GetCapabilitySigned);
    uint32_t keyhandle_no = htonl(keyhandle);
    uint32_t caparea_no = htonl(caparea);
    unsigned char c = 0;
    unsigned char authdata[TCM_HASH_SIZE];
    uint32_t ssize;
    unsigned char *buffer = NULL;
    uint32_t subcaplen = 0;
    uint32_t subcaplen_no;

    /* check arguments */
    if (scap) {
        subcaplen = scap->used;
        buffer = scap->buffer;
    }
    subcaplen_no = htonl(subcaplen);

    ret = needKeysRoom(keyhandle, 0, 0, 0);
    if (ret != 0) {
        return ret;
    }

    if (resp == NULL) return ERR_NULL_ARG;

    if (NULL != keypass) {
        unsigned char nonceodd[TCM_HASH_SIZE];
        session sess;

        ret  = TSS_gennonce(nonceodd);
        if (0 == ret)
            return ERR_CRYPT_ERR;

        ret = TSS_SessionOpen(SESSION_OSAP | SESSION_OIAP,
                              &sess,
                              keypass, TCM_ET_KEYHANDLE, keyhandle);
        if (0 != ret) {
            return ret;
        }

        /* move Network byte order data to variable for hmac calculation */
        ret = TSS_authhmac(authdata, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE, TSS_Session_GetENonce(&sess), nonceodd, c,
                           TCM_U32_SIZE, &ordinal_no,
                           TCM_NONCE_SIZE, antiReplay,
                           TCM_U32_SIZE, &caparea_no,
                           TCM_U32_SIZE, &subcaplen_no,
                           subcaplen   , buffer,
                           0, 0);
        if (0 != ret) {
            TSS_SessionClose(&sess);
            return ret;
        }

        ret = TSS_buildbuff("00 c2 T l l % l @ L % o %", &tcmdata,
                            ordinal_no,
                            keyhandle_no,
                            TCM_NONCE_SIZE, antiReplay,
                            caparea_no,
                            subcaplen, buffer,
                            TSS_Session_GetHandle(&sess),
                            TCM_NONCE_SIZE, nonceodd,
                            c,
                            TCM_HASH_SIZE, authdata);

        if ((ret & ERR_MASK) != 0) {
            TSS_SessionClose(&sess);
            return ret;
        }
        /* transmit the request buffer to the TCM device and read the reply */
        ret = TCM_Transmit(&tcmdata, "GetCapability - AUTH1");
        TSS_SessionClose(&sess);
        if (ret != 0)
            return ret;

        ret = tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET + TCM_U32_SIZE, &rlen);
        if ((ret & ERR_MASK)) {
            return ret;
        }
        ret = tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET + TCM_U32_SIZE + TCM_U32_SIZE + rlen, &ssize);
        if ((ret & ERR_MASK)) {
            return ret;
        }

        ret = TSS_checkhmac1(&tcmdata, ordinal_no, nonceodd, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                             TCM_U32_SIZE + TCM_U32_SIZE + rlen + TCM_U32_SIZE + ssize, TCM_DATA_OFFSET,
                             0, 0);
        if (ret != 0)
            return ret;
    } else {
        ret = TSS_buildbuff("00 c1 T l l % l @", &tcmdata,
                            ordinal_no,
                            keyhandle_no,
                            TCM_NONCE_SIZE, antiReplay,
                            caparea_no,
                            subcaplen, buffer);

        if ((ret & ERR_MASK) != 0) {
            return ret;
        }
        /* transmit the request buffer to the TCM device and read the reply */
        ret = TCM_Transmit(&tcmdata, "GetCapability - NO AUTH");
        if (ret != 0)
            return ret;

        ret = tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET + TCM_U32_SIZE, &rlen);
        if ((ret & ERR_MASK)) {
            return ret;
        }
        ret = tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET + TCM_U32_SIZE + TCM_U32_SIZE + rlen, &ssize);
        if ((ret & ERR_MASK)) {
            return ret;
        }
    }
    if (NULL != resp) {
        SET_TCM_BUFFER(resp,
                       &tcmdata.buffer[TCM_DATA_OFFSET + TCM_U32_SIZE + TCM_U32_SIZE],
                       rlen);
    }

    if (NULL != sig ) {
        *siglen = MIN(*siglen, ssize);
        memcpy(sig,
               &tcmdata.buffer[TCM_DATA_OFFSET + TCM_U32_SIZE + TCM_U32_SIZE + rlen + TCM_U32_SIZE],
               *siglen);
    }

    return ret;
}
#endif

/****************************************************************************/
/*                                                                          */
/*  Convert Error code to message                                           */
/*                                                                          */
/****************************************************************************/
static char *msgs[] = {
    "Unknown error"                                      ,
    "Authentication failed (Incorrect Password)"         ,
    "Illegal index"                                      ,
    "Bad parameter"                                      ,
    "Auditing failure"                                   ,
    "Clear disabled"                                     ,
    "TCM offlined"                                    ,
    "TCM onlined"                                       ,
    "Target command disabled"                            ,
    "Operation failed"                                   ,
    "Ordinal unknown"                                    ,
    "Owner installation disabled"                        ,
    "Invalid key handle"                                 ,
    "Target key not found"                               ,
    "Unacceptable encryption scheme"                     ,
    "Migration authorization failed"                     ,
    "PCR information incorrect"                          ,
    "No room to load key"                                ,
    "No SMK set"                                         ,
    "Encrypted blob invalid"                             ,
    "TCM already has owner"                              ,
    "TCM out of resources"                               ,
    "Random string too short"                            ,
    "TCM out of space"                                   ,
    "PCR mismatch"                                       ,
    "Paramsize mismatch"                                 ,
    "No existing SM3 thread"                           ,
    "SM3 thread error"                                 ,
    "TCM self test failed - TCM shutdown"                ,
    "Authorization failure for 2nd key"                  ,
    "Invalid tag value"                                  ,
    "TCM I/O error"                                      ,
    "Encryption error"                                   ,
    "Decryption failure"                                 ,
    "Invalid handle"                                     ,
    "TCM has no endorsement key"                         ,
    "Invalid key usage"                                  ,
    "Invalid entity type"                                ,
    "Incorrect command sequence"                         ,
    "Inappropriate signature data"                       ,
    "Unsupported key properties"                         ,
    "Incorrect migration properties"                     ,
    "Incorrect signature or encryption scheme"           ,
    "Incorrect data size"                                ,
    "Incorrect mode parameter"                           ,
    "Invalid presence values"                            ,
    "Incorrect version"                                  ,
    "No support for wrapped transports"                  ,
    "Audit construction failed, command unsuccessful"    ,
    "Audit construction failed, command successful"      ,
    "Not resetable"                                      ,
    "Missing locality information"                       ,
    "Incorrect type"                                     ,
    "Invalid resource"                                   ,
    "Not in FIPS mode"                                   ,
    "Invalid family"                                     ,
    "No NV permission"                                   ,
    "Requires signed command"                            ,
    "Key not supported"                                  ,
    "Authentication conflict"                            ,
    "NV area is locked"                                  ,
    "Bad locality"                                       ,
    "NV area is read-only"                               ,
    "No protection on write into NV area"                ,
    "Family count value does not match"                  ,
    "NV area is write locked"                            ,
    "Bad NV area attributes"                             ,
    "Invalid structure"                                  ,
    "Key under control by owner"                         ,
    "Bad counter handle"                                 ,
    "Not full write"                                     ,
    "Context GAP"                                        ,
    "Exceeded max NV writes without owner"               ,
    "No operator authorization value set"                ,
    "Resource missing"                                    ,
    "Delegate administration is locked"                  ,
    "Wrong delegate family"                              ,
    "Delegation management not enabled"                  ,
    "Command executed outside transport session"         ,
    "Key is under control of owner"                      ,
    "No DAA resources available"                         ,
    "InputData0 is inconsistent"                         ,
    "InputData1 is inconsistent"                         ,
    "DAA: Issuer settings are not consistent"            ,
    "DAA: TCM settings are not consistent"               ,
    "DAA stage failure"                                  ,
    "DAA: Issuer validity check detected inconsistency"  ,
    "DAA: Wrong 'w'"                                     ,
    "Bad handle"                                         ,
    "No room for context"                                ,
    "Bad context"                                        ,
    "Too many contexts"                                  ,
    "Migration authority signature failure"              ,
    "Migration destination not authenticated"            ,
    "Migration source incorrect"                         ,
    "Migration authority incorrect"			,
    "No error description"				,
    "Attempt to revoke the EK and the EK is not revocable",
    "Bad signature of CMK ticket"			,
    "There is no room in the context list for additional contexts",
    "The user's ID is invalid",
    "The user has no privilege using the required resource",
    "The algorithm is not supported yet",
    "The migrationAuth has expired",
    "The plus one operation is failed",
    "The user is inactive",
    "The length of authorization data is invalid",
    "The size of random number is wrong"
};

static char *msgs_nonfatal[] = {
    "Retry"						,
    "Needs self test"					,
    "Doing self test"					,
    "Defend lock running"
};

static char *msgs2[] = {
    "HMAC authorization verification failed"             ,
    "NULL argument"                                      ,
    "Invalid argument"                                   ,
    "Error from OpenSSL library"                         ,
    "I/O error"                                          ,
    "Memory allocation error"                            ,
    "File error"                                         ,
    "Data in stream are bad"                             ,
    "Too many data"                                      ,
    "Buffer too small"                                   ,
    "Incorrect structure type"                           ,
    "Searched item could not be found"                   ,
    "Environment variable not set"                       ,
    "No transport allowed for this ordinal"              ,
    "Bad tag in response message"                        ,
    "Incorrect signature"                                ,
    "PCR value list does not correspond to IMA value list",
    "Checksum verification failed"                       ,
    "Format error in TCM response"                       ,
    "Choice of session type is bad"                      ,
    "Failure during close()/fclose()"                    ,
    "File write error"                                   ,
    "File read error"                                    ,
};

static char *privilege_msg[TCM_PRI_ERR_MAX - TCM_PRI_BASE] = {
    "Invalid privCode",
    "The user has no privilege using NV",
    "The user has no privilege using SM2",
    "The user has no privilege using SM4",
    "The user has no privilege using PCR0",
    "The user has no privilege using PCR1",
    "The user has no privilege using PCR2",
    "The user has no privilege using PCR3",
    "The user has no privilege using PCR4",
    "The user has no privilege using PCR5",
    "The user has no privilege using PCR6",
    "The user has no privilege using PCR7",
    "The user has no privilege using PCR8",
    "The user has no privilege using PCR9",
    "The user has no privilege using PCR10",
    "The user has no privilege using PCR11",
    "The user has no privilege using PCR12",
    "The user has no privilege using PCR13",
    "The user has no privilege using PCR14",
    "The user has no privilege using PCR15",
    "The user has no privilege using PCR16",
    "The user has no privilege using PCR17",
    "The user has no privilege using PCR18",
    "The user has no privilege using PCR19",
    "The user has no privilege using PCR20",
    "The user has no privilege using PCR21",
    "The user has no privilege using PCR22",
    "The user has no privilege using PCR23",
    "The user has no privilege using PCR24",
    "The user has no privilege using PCR25",
    "The user has no privilege using PCR26",
};


char *TCM_GetErrMsg(uint32_t code)
{
    if (code  >= ERR_HMAC_FAIL &&
            code  <  ERR_LAST) {
        return msgs2[code - ERR_HMAC_FAIL];
    }

    if (code < TCM_BAD_MAX) {
        return msgs[code];
    }

    if (code > TCM_PRI_BASE && code <= TCM_PRI_PCR_26) {
        return privilege_msg[code - TCM_PRI_BASE];
    }

    if ((code >= TCM_NON_FATAL) &&
            (code < (TCM_NON_FATAL + 4))) {
        if ((code & 0xff) == 0) {
            printf("\n\n\nRETRY error code\n\n\n");
        }
        return msgs_nonfatal[code - TCM_NON_FATAL];
    }
    return msgs[0];
}

/*
 * Allocate a TCM buffer that can be used to communicate
 * with the TCM. It will be of the size that the TCM
 * supports.
 */
struct tcm_buffer *TSS_AllocTCMBuffer(int len )
{
    struct tcm_buffer *buf = NULL;
    STACK_TCM_BUFFER(scap)
    STORE32(scap.buffer, 0, TCM_CAP_PROP_INPUT_BUFFER);
    scap.used = 4;
    if (len <= 0) {
        STACK_TCM_BUFFER(response)
        static int buf_len = -1;
        if (buf_len == -1) {
            uint32_t ret = -1;
            /* MUST check if GetCapability is audited... */
            _TCM_IsAuditedOrdinal(TCM_ORD_GetCapability, &ret);
            if (0 == ret) {
                /* Only do this once through usage of the static var. */
                ret = TCM_GetCapability(TCM_CAP_PROPERTY,
                                        &scap,
                                        &response);
            }
            if ( 0 != ret ) {
                buf_len = 4 * 1024;
            } else {
                buf_len = LOAD32(response.buffer, 0);
            }
        }
		len = buf_len;
    }
    //lyf
#if 0
    if (len > 16 * 1024) {
        len = 16 * 1024;
    } else if (len < 1024) {
        len = 2 * 1024;
    }
#endif
    if (len + 20 > HASHMAXSIZE) {
        len = HASHMAXSIZE + 20;
    } else if (len < 1024) {
        len = 4 * 1024;
    }

    //lyf
    /*malloc (len+20), len for buffer storing data, 20 for buffer parameters*/
    buf = (struct tcm_buffer *)malloc(len + 20/*(size_t)&buf->buffer[len]*/);
    if (NULL != buf) {
        buf->size = len;
        buf->used = 0;
    }
    return buf;
}

void TSS_FreeTCMBuffer(struct tcm_buffer *buf)
{
    free(buf);
}


uint32_t TSS_SetTCMBuffer(struct tcm_buffer *tb,
                          const unsigned char *buffer,
                          uint32_t buflen)
{
    uint32_t len = MIN(buflen, tb->size);
    memcpy(tb->buffer, buffer, len);
    tb->used = len;
    return len;
}


