/********************************************************************************/
/*										*/
/*			     	TCM NV Storage Routines				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*        $Id: nv.c 4106 2010-07-09 18:58:31Z kgoldman $			*/
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
#include <tcmfunc.h>
#include <tcmutil.h>
#include <oiaposap.h>
#include <hmac.h>
#include <tcm_types.h>
#include <tcm_constants.h>

/****************************************************************************/
/*                                                                          */
/* Define an area in NV RAM space                                           */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* ownauth   The sha'ed owner password of the TCM                           */
/* pubInfo   The serialized TCM_NV_DATA_PUBLIC structure with the following */
/*           fields filled out to define the space:                         */
/*           - index                                                        */
/*           - dataSize                                                     */
/*           - permission.attributes                                        */
/*           The pubInfo should be serialized using the TCM_CreatePubInfo   */
/*           function with the buffer size for the serialized structure     */
/*           of exactly TCM_PUBINFO_SERIAL_SIZE bytes.                      */
/* areaauth  The sha'ed area password for access to the defined space       */
/*                                                                          */
/****************************************************************************/
uint32_t TCM_NV_DefineSpace(unsigned char *ownauth,  // HMAC key
                            unsigned char *pubInfo, uint32_t pubInfoSize,
                            unsigned char *areaauth   // used to create  encAuth
                           )
{
    STACK_TCM_BUFFER(tcmdata)
    unsigned char authdata[TCM_NONCE_SIZE];
    unsigned char encauth[TCM_HASH_SIZE];
    unsigned char dummy[TCM_HASH_SIZE];
    unsigned char c = 0;
    uint32_t ordinal_no = htonl(TCM_ORD_NV_DefineSpace);
    uint32_t ret;
    unsigned char *passptr1;
    session sess;
    memset(dummy, 0x0, sizeof(dummy));

    /* check input arguments */
    if (NULL == pubInfo) return ERR_NULL_ARG;

    if (NULL != areaauth)
        passptr1 = areaauth;
    else
        passptr1 = dummy;

    if (NULL != ownauth) {

        /* Open OSAP Session */
        ret = TSS_SessionOpen(SESSION_OSAP, &sess, ownauth, TCM_ET_OWNER, 0);
        if (ret != 0) return ret;
        /* calculate encrypted authorization value */
        ret = TCM_CreateEncAuth(&sess, passptr1, encauth);
		if(ret != 0){
			TSS_SessionClose(&sess);
			return ret;
		}

        ret = TSS_authhmac1(authdata, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE, TSS_Session_GetSeq(&sess), c,
                            TCM_U32_SIZE, &ordinal_no,
                            pubInfoSize, pubInfo,
                            TCM_HASH_SIZE, encauth,
                            0, 0);
        if (0 != ret) {
            TSS_SessionClose(&sess);
            return ret;
        }
        /* build the request buffer */

        ret = TSS_buildbuff("00 c2 T l  % % L %", &tcmdata,
                            ordinal_no,
                            pubInfoSize, pubInfo,
                            TCM_HASH_SIZE, encauth,
                            TSS_Session_GetHandle(&sess),
                            TCM_HASH_SIZE, authdata);
        if ((ret & ERR_MASK)) {
            TSS_SessionClose(&sess);
            return ret;
        }
        /* transmit the request buffer to the TCM device and read the reply */
        ret = TCM_Transmit(&tcmdata, "NV_DefineSpace - AUTH1");
        //TSS_SessionClose(&sess);
        if (ret != 0) {
            TSS_SessionClose(&sess);
            return ret;
        }
        /* check the HMAC in the response */

        ret = TSS_checkhmac1(&tcmdata, ordinal_no,    TSS_Session_GetSeq(&sess), TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                             0, 0);
        TSS_SessionClose(&sess);
    } else {


        ret = TSS_buildbuff("00 c1 T  l % %", &tcmdata,
                            ordinal_no,
                            pubInfoSize, pubInfo,
                            TCM_HASH_SIZE, passptr1);
        if (0 != (ret & ERR_MASK)) {
            return ret;
        }

        /* transmit the request buffer to the TCM device and read the reply */
        ret = TCM_Transmit(&tcmdata, "NV_DefineSpace");
        if (0 != ret ) {
            return ret;
        }
    }

    return ret;

}


/****************************************************************************/
/*                                                                          */
/* Define an area in NV RAM space                                           */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* ownauth   The sha'ed owner password of the TCM                           */
/* index     The index of the area to define                                */
/* dataSize  The size of the area to define                                 */
/* permissions  The permission flags for the area                           */
/* areaauth  The sha'ed area password for access to the defined space       */
/*                                                                          */
/****************************************************************************/
uint32_t TCM_NV_DefineSpace2(unsigned char *ownauth,  // HMAC key
                             uint32_t index,
                             uint32_t size,
                             uint32_t permissions,
                             unsigned char *areaauth,   // used to create  encAuth
                             TCM_PCR_INFO_SHORT *pcrInfoRead,
                             TCM_PCR_INFO_SHORT *pcrInfoWrite)
{
    uint32_t ret;
    uint32_t serDataPublicSize = 0;
    STACK_TCM_BUFFER(pubInfo)
    TCM_NV_DATA_PUBLIC public;
    memset(&public, 0x0, sizeof(public));

    public.tag = TCM_TAG_NV_DATA_PUBLIC;
    public.nvIndex = index;

    if (pcrInfoRead != NULL) {
        public.pcrInfoRead.localityAtRelease = pcrInfoRead->localityAtRelease;
        public.pcrInfoRead.pcrSelection.sizeOfSelect = pcrInfoRead->pcrSelection.sizeOfSelect;
        memcpy(public.pcrInfoRead.pcrSelection.pcrSelect, pcrInfoRead->pcrSelection.pcrSelect,
               pcrInfoRead->pcrSelection.sizeOfSelect);
        memcpy(public.pcrInfoRead.digestAtRelease, pcrInfoRead->digestAtRelease,
               TCM_HASH_SIZE);
    } else {
        public.pcrInfoRead.pcrSelection.sizeOfSelect = 4;
        public.pcrInfoRead.localityAtRelease = TCM_LOC_ZERO;
        /* other fields remain 0 */
    }

    if (pcrInfoWrite != NULL) {
        public.pcrInfoWrite.localityAtRelease = pcrInfoWrite->localityAtRelease;
        public.pcrInfoWrite.pcrSelection.sizeOfSelect = pcrInfoWrite->pcrSelection.sizeOfSelect;
        memcpy(public.pcrInfoWrite.pcrSelection.pcrSelect, pcrInfoWrite->pcrSelection.pcrSelect,
               pcrInfoWrite->pcrSelection.sizeOfSelect);
        memcpy(public.pcrInfoWrite.digestAtRelease, pcrInfoWrite->digestAtRelease,
               TCM_HASH_SIZE);

    } else {
        public.pcrInfoWrite.pcrSelection.sizeOfSelect = 4;
        public.pcrInfoWrite.localityAtRelease = TCM_LOC_ZERO;
        /* other fields remain 0 */
    }
    public.permission.tag = TCM_TAG_NV_ATTRIBUTES;
    public.permission.attributes = permissions;
    public.dataSize = size;

    ret = TCM_WritePubInfo(&public, &pubInfo);
    if ( (ret & ERR_MASK) != 0 ) {
        return ret;
    }
    serDataPublicSize = ret;
    return TCM_NV_DefineSpace(
               ownauth,
               pubInfo.buffer, serDataPublicSize,
               areaauth);
}



/****************************************************************************/
/*                                                                          */
/* Write a value into password protected NV RAM space                       */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* nvIndex     The index of a previously defined area                       */
/* offset      The offset into the area where to start writing              */
/* data        Pointer to the data to write to the area                     */
/* datalen     The length of the data to write                              */
/* areaauth    The sha'ed storage area password                             */
/*                                                                          */
/****************************************************************************/
uint32_t TCM_NV_WriteValueAuth(
    uint32_t nvIndex,
    uint32_t offset,
    unsigned char *data, uint32_t datalen,
    unsigned char *areaauth   // key for area
)
{
    STACK_TCM_BUFFER(tcmdata)
    unsigned char authdata[TCM_NONCE_SIZE];
    unsigned char c = 0;
    uint32_t ordinal_no = htonl(TCM_ORD_NV_WriteValueAuth);
    uint32_t ret;
    uint32_t datalen_no = htonl(datalen);
    uint32_t nvIndex_no = htonl(nvIndex);
    uint32_t offset_no  = htonl(offset);
    session sess;

    /* check input arguments */
    if (areaauth == NULL) return ERR_NULL_ARG;

    /* Open OIAP Session */
    ret = TSS_SessionOpen(SESSION_OSAP | SESSION_OIAP,
                          &sess,
                          areaauth, TCM_ET_NV, nvIndex);

    if (ret != 0)
        return ret;
    /* move Network byte order data to variable for hmac calculation */
    ret = TSS_authhmac1(authdata, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE, TSS_Session_GetSeq(&sess), c,
                        TCM_U32_SIZE, &ordinal_no,
                        TCM_U32_SIZE, &nvIndex_no,
                        TCM_U32_SIZE, &offset_no,
                        TCM_U32_SIZE, &datalen_no,
                        datalen     , data,
                        0, 0);
    if (0 != ret) {
        TSS_SessionClose(&sess);
        return ret;
    }

    /* build the request buffer */

    ret = TSS_buildbuff("00 c2 T l l l @ L %", &tcmdata,
                        ordinal_no,
                        nvIndex_no,
                        offset_no,
                        datalen, data,
                        TSS_Session_GetHandle(&sess),
                        TCM_HASH_SIZE, authdata);

    if ((ret & ERR_MASK)) {
        TSS_SessionClose(&sess);
        return ret;
    }

    ret = TCM_Transmit(&tcmdata, "NV_WriteValueAuth - AUTH1");

    //TSS_SessionClose(&sess);
    if (0 != ret) {
        TSS_SessionClose(&sess);
        return ret;
    }

    ret = TSS_checkhmac1(&tcmdata, ordinal_no,
                         TSS_Session_GetSeq(&sess), TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                         0, 0);
    TSS_SessionClose(&sess);
    return ret;
}



/****************************************************************************/
/*                                                                          */
/* Read a value from password protected NV RAM space                        */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* nvIndex     The index of a previously defined area                       */
/* offset      The offset into the area where to start reading              */
/* datasize    The number of bytes to read from  the area                   */
/* buffer      The buffer to hold the data                                  */
/* buffersize  On input: contains the size of the buffer and on output will */
/*             hold the actual number of bytes that have been read          */
/* areaauth    The sha'ed password that gives access to the area            */
/*                                                                          */
/****************************************************************************/
uint32_t TCM_NV_ReadValueAuth(
    uint32_t nvIndex,
    uint32_t offset,
    uint32_t datasize,
    unsigned char *buffer, uint32_t *buffersize,
    unsigned char *areaauth    // key for area
)
{
    STACK_TCM_BUFFER(tcmdata)
    unsigned char authdata[TCM_NONCE_SIZE];
    unsigned char c = 0;
    uint32_t ordinal_no = htonl(TCM_ORD_NV_ReadValueAuth);
    uint32_t ret;
    uint32_t len;
    uint32_t datasize_no = htonl(datasize);
    uint32_t nvIndex_no = htonl(nvIndex);
    uint32_t offset_no  = htonl(offset);
    session sess;


    /* check input arguments */
    if (buffer == NULL || areaauth == NULL) return ERR_NULL_ARG;

    /* Open OIAP Session */
    ret = TSS_SessionOpen(SESSION_OSAP | SESSION_OIAP,
                          &sess,
                          areaauth, TCM_ET_NV, nvIndex);
    if (ret != 0)
        return ret;
    /* move Network byte order data to variable for hmac calculation */
    ret = TSS_authhmac1(authdata, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE, TSS_Session_GetSeq(&sess), c,
                        TCM_U32_SIZE, &ordinal_no,
                        TCM_U32_SIZE, &nvIndex_no,
                        TCM_U32_SIZE, &offset_no,
                        TCM_U32_SIZE, &datasize_no,
                        0, 0);
    if (0 != ret) {
        TSS_SessionClose(&sess);
        return ret;
    }

    /* build the request buffer */
    ret = TSS_buildbuff("00 c2 T l l l l L %", &tcmdata,
                        ordinal_no,

                        nvIndex_no,
                        offset_no,
                        datasize_no,
                        TSS_Session_GetHandle(&sess),
                        TCM_HASH_SIZE, authdata);

    if ((ret & ERR_MASK)) {
        TSS_SessionClose(&sess);
        return ret;
    }

    ret = TCM_Transmit(&tcmdata, "NV_ReadValueAuth");

    //	TSS_SessionClose(&sess);
    if (0 != ret) {
        TSS_SessionClose(&sess);
        return ret;
    }

    ret = tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET, &len);
    if ((ret & ERR_MASK)) {
        TSS_SessionClose(&sess);
        return ret;
    }

    ret = TSS_checkhmac1(&tcmdata, ordinal_no,    TSS_Session_GetSeq(&sess),
                         TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                         TCM_U32_SIZE + len, TCM_DATA_OFFSET,
                         0, 0);

    TSS_SessionClose(&sess);
    if (0 != ret) {
        return ret;
    }

    *buffersize = MIN(*buffersize, len);
    memcpy(buffer, &tcmdata.buffer[TCM_DATA_OFFSET + TCM_U32_SIZE], *buffersize);
    return ret;
}

