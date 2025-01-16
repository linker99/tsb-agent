/********************************************************************************/
/*										*/
/*			     	TCM HMAC routines				*/
/*			     Written by J. Kravitz				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: hmac.c 4073 2010-04-30 14:44:14Z kgoldman $			*/
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

#ifdef TCM_POSIX
#include <netinet/in.h>
#endif
#ifdef TCM_WINDOWS
#include <winsock2.h>
#endif
#include <tcm.h>
#include <tcmutil.h>
#include <oiaposap.h>
#include <hmac.h>
#include <tcmfunc.h>

#define TCM_TAG_RSP_COMMAND       0x00C4
#define TCM_TAG_RSP_PROTECT_COMMAND 0x00C5
#define TCM_TAG_RSP_PROTECT_COMMAND_forTCM       0x00C6  //yhw add

#define TCM_HMAC_BLOCK_SIZE 64

static TCM_RESULT TCM_HMAC_Generatevalist(TCM_HMAC tcm_hmac,
        const TCM_SECRET key,
        va_list ap);


/****************************************************************************/
/*                                                                          */
/* Validate the HMAC in an AUTH1 response                                   */
/*                                                                          */
/* This function validates the Authorization Digest for all AUTH1           */
/* responses.                                                               */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* buffer - a pointer to response buffer                                    */
/* command - the command code from the original request , must be network byter order!          */
/* seq - a pointer to a 32 byte array containing the sequenceNO, which has been updated!  */
/* key    - a pointer to the key used in the request HMAC                   */
/* keylen - the size of the key                                             */
/* followed by a variable length set of arguments, which must come in       */
/* pairs.                                                                   */
/* The first value in each pair is the length of the data in the second     */
/*   argument of the pair                                                   */
/* The second value in each pair is an offset in the buffer to the data     */
/*   to be included in the hash for the paramdigest                         */
/* There should NOT be pairs for the TCM_RESULT or TCM_COMMAND_CODE         */
/* The last pair must be followed by a pair containing 0,0                  */


/*  The input must be network byte order!!!!                                     */
/****************************************************************************/
uint32_t TSS_checkhmac1(const struct tcm_buffer *tb, uint32_t command,
                        unsigned char *seq, unsigned char *key, unsigned int keylen, ...)
{
    uint32_t bufsize;
    uint16_t tag;
    uint32_t ordinal;
    uint32_t result;
    const unsigned char *continueflag;
    const unsigned char *authdata;
    unsigned char testhmac[TCM_HASH_SIZE];
    unsigned char paramdigest[TCM_HASH_SIZE];
    sm3_context  sha;
    unsigned int dlen;
    unsigned int dpos;
    va_list argp;
    const unsigned char *buffer = tb->buffer;
    uint32_t ret;

    unsigned char flag[1] = {0x00};
    ret = tcm_buffer_load32(tb, TCM_U16_SIZE, &bufsize);
    if ((ret & ERR_MASK)) {
        return ret;
    }
    tag =     LOAD16(buffer, 0);
    ordinal = command;
    ret  = tcm_buffer_load32N(tb, TCM_RETURN_OFFSET, &result);
    if ((ret & ERR_MASK)) {
        return ret;
    }
    if (tag == TCM_TAG_RSP_COMMAND) return 0;
    if (tag != TCM_TAG_RSP_PROTECT_COMMAND) return ERR_HMAC_FAIL;
    authdata     = buffer + bufsize - TCM_HASH_SIZE;
    continueflag = authdata - 1;

    continueflag = flag;
    sm3_init(&sha);
    sm3_update(&sha, (const unsigned char *)&result, 4);
    sm3_update(&sha, (const unsigned char *)&ordinal, 4);

    va_start(argp, keylen);
    for (;;) {
        dlen = (unsigned int)va_arg(argp, unsigned int);
        if (dlen == 0) break;
        dpos = (unsigned int)va_arg(argp, unsigned int);
        if (dpos + dlen > tb->used) {
            return ERR_BUFFER;
        }
        sm3_update(&sha, buffer + dpos, dlen);

    }
    va_end(argp);
    sm3_finish(&sha, paramdigest);


    TCM_session_seqAddOne(seq);
    //   TCM_dump_data("  TCM_Authdata_Generate: seq", seq,TCM_SEQ_SIZE);

    TSS_rawhmac(testhmac, key, keylen, TCM_HASH_SIZE, paramdigest,
                TCM_SEQ_SIZE, seq,
                0, 0);
    //   printfHex("testhmacout:",testhmac,32);

    /*	printf(" paramdigest %x %x %x %x \n", paramdigest[0], paramdigest[1], paramdigest[2], paramdigest[3]);
    	printf(" usageSecret %x %x %x %x \n", key[0], key[1], key[2], key[3]);
    	printf(" seq %x %x %x %x \n", seq[0], seq[1], seq[2], seq[3]);
    	printf(" continueflag: %02x\n", *continueflag);*/
    if (memcmp(testhmac, authdata, TCM_HASH_SIZE) != 0) return ERR_HMAC_FAIL;
    return 0;
}

/*
The parameters are the same with TSS_checkhmac1,
authdata:  the secret of another entity
*/
uint32_t TSS_checkhmac2(const struct tcm_buffer *tb, uint32_t command,
                        unsigned char *seq, unsigned char *entityauth, unsigned char *key, unsigned int keylen, ...)
{
    uint32_t bufsize;
    uint16_t tag;
    uint32_t ordinal;
    uint32_t result;
    uint32_t privCode;
    const unsigned char *continueflag;
    const unsigned char *authdata;
    unsigned char testhmac[32];
    unsigned char paramdigest[32];
    sm3_context  sha;
    unsigned int dlen;
    unsigned int dpos;
    va_list argp;
    const unsigned char *buffer = tb->buffer;
    uint32_t ret;
    unsigned char flag[1] = {0x00}; //lyf
    ret = tcm_buffer_load32(tb, TCM_U16_SIZE, &bufsize);
    if ((ret & ERR_MASK)) {
        return ret;
    }
    tag =     LOAD16(buffer, 0);
    ordinal = command;
    ret  = tcm_buffer_load32N(tb, TCM_RETURN_OFFSET, &result);
    if ((ret & ERR_MASK)) {
        return ret;
    }
    //    printf("[debug] %s :starting++++++++++",__func__);
    if (tag == TCM_TAG_RSP_COMMAND) return 0;
    if ((tag != TCM_TAG_RSP_PROTECT_COMMAND) && (tag != TCM_TAG_RSP_PROTECT_COMMAND_forTCM)) return ERR_HMAC_FAIL;
    authdata     = buffer + bufsize - TCM_HASH_SIZE;
    continueflag = authdata - 1;
    continueflag = flag;
    sm3_init(&sha);
    sm3_update(&sha, (const unsigned char *)&result, 4);
    sm3_update(&sha, (const unsigned char *)&ordinal, 4);


    va_start(argp, keylen);
    for (;;) {
        dlen = (unsigned int)va_arg(argp, unsigned int);
        if (dlen == 0) break;
        dpos = (unsigned int)va_arg(argp, unsigned int);
        if (dpos + dlen > tb->used) {
            return ERR_BUFFER;
        }
        sm3_update(&sha, buffer + dpos, dlen);
    }
    va_end(argp);
    sm3_finish(&sha, paramdigest);

    TCM_session_seqAddOne(seq);


    TSS_rawhmac(testhmac, key, keylen, TCM_HASH_SIZE, paramdigest,
                TCM_SECRET_SIZE, entityauth,
                TCM_SEQ_SIZE, (seq),
                0, 0);
    if (memcmp(testhmac, authdata, TCM_HASH_SIZE) != 0) return ERR_HMAC_FAIL;
    return 0;
}


/*
The parameters are the same with TSS_checkhmac1,
authdata:  the secret of another entity
*/
uint32_t TSS_checkhmac3(const struct tcm_buffer *tb, uint32_t command,
                        unsigned char *seq, unsigned char *entityauth, unsigned char *key, unsigned int keylen, ...)
{
    uint32_t bufsize;
    uint16_t tag;
    uint32_t ordinal;
    uint32_t result;
    uint32_t privCode;
    const unsigned char *continueflag;
    const unsigned char *authdata;
    unsigned char testhmac[32];
    unsigned char paramdigest[32];
    sm3_context  sha;
    unsigned int dlen;
    unsigned int dpos;
    va_list argp;
    const unsigned char *buffer = tb->buffer;
    uint32_t ret;
    unsigned char flag[1] = {0x00};



    ret = tcm_buffer_load32(tb, TCM_U16_SIZE, &bufsize);
    if ((ret & ERR_MASK)) {
        return ret;
    }
    tag =     LOAD16(buffer, 0);
    ordinal = command;
    ret  = tcm_buffer_load32N(tb, TCM_RETURN_OFFSET, &result);
    if ((ret & ERR_MASK)) {
        return ret;
    }
    if (tag == TCM_TAG_RSP_COMMAND) return 0;
    if (tag != TCM_TAG_RSP_PROTECT_COMMAND_forTCM) return ERR_HMAC_FAIL;
    authdata  = buffer + bufsize - TCM_HASH_SIZE - TCM_HASH_SIZE;

    sm3_init(&sha);
    sm3_update(&sha, (const unsigned char *)&result, 4);
    sm3_update(&sha, (const unsigned char *)&ordinal, 4);


    va_start(argp, keylen);
    for (;;) {
        dlen = (unsigned int)va_arg(argp, unsigned int);
        if (dlen == 0) break;
        dpos = (unsigned int)va_arg(argp, unsigned int);
        if (dpos + dlen > tb->used) {
            return ERR_BUFFER;
        }
        sm3_update(&sha, buffer + dpos, dlen);
    }
    va_end(argp);
    sm3_finish(&sha, paramdigest);

    TCM_session_seqAddOne(seq);

    //   TCM_dump_data("paramdigest",paramdigest,32);
    //   TCM_dump_data("key",key,keylen);
    //   TCM_dump_data("entityauth",entityauth,TCM_SECRET_SIZE);
    //   TCM_dump_data("seq",seq,TCM_SEQ_SIZE);


    TSS_rawhmac(testhmac, key, keylen, TCM_HASH_SIZE, paramdigest,
                TCM_SEQ_SIZE, (seq),
                0, 0);

    //   TCM_dump_data("compute result",testhmac,32);
    //   TCM_dump_data("return result",authdata,32);
    if (memcmp(testhmac, authdata, TCM_HASH_SIZE) != 0) return ERR_HMAC_FAIL;
    return 0;
}



/*TSS_checkhmac1New is same with TSS_checkhmac1, except the seq keeps the same!!!!
Used by transport session.
*/
uint32_t TSS_checkhmac1New(const struct tcm_buffer *tb, uint32_t command,
                           unsigned char *seq, unsigned char *key, unsigned int keylen, ...)
{
    uint32_t bufsize;
    uint16_t tag;
    uint32_t ordinal;
    uint32_t result;
    const unsigned char *authdata;
    unsigned char testhmac[TCM_HASH_SIZE];
    unsigned char paramdigest[TCM_HASH_SIZE];
    sm3_context  sha;
    unsigned int dlen;
    unsigned int dpos;
    va_list argp;
    const unsigned char *buffer = tb->buffer;
    uint32_t ret;

    ret = tcm_buffer_load32(tb, TCM_U16_SIZE, &bufsize);
    if ((ret & ERR_MASK)) {
        return ret;
    }
    tag =     LOAD16(buffer, 0);
    ordinal = command;
    ret  = tcm_buffer_load32N(tb, TCM_RETURN_OFFSET, &result);
    if ((ret & ERR_MASK)) {
        return ret;
    }



    if (tag == TCM_TAG_RSP_COMMAND) return 0;
    if (tag != TCM_TAG_RSP_PROTECT_COMMAND) return ERR_HMAC_FAIL;
    authdata     = buffer + bufsize - TCM_HASH_SIZE;
    sm3_init(&sha);
    sm3_update(&sha, (const unsigned char *)&result, 4);
    sm3_update(&sha, (const unsigned char *)&ordinal, 4);
    va_start(argp, keylen);
    for (;;) {
        dlen = (unsigned int)va_arg(argp, unsigned int);
        if (dlen == 0) break;
        dpos = (unsigned int)va_arg(argp, unsigned int);
        if (dpos + dlen > tb->used) {
            return ERR_BUFFER;
        }
        sm3_update(&sha, buffer + dpos, dlen);
    }
    va_end(argp);
    sm3_finish(&sha, paramdigest);

    TSS_rawhmac(testhmac, key, keylen, TCM_HASH_SIZE, paramdigest,
                TCM_SEQ_SIZE, (seq),
                0, 0);

    if (memcmp(testhmac, authdata, TCM_HASH_SIZE) != 0) return ERR_HMAC_FAIL;
    return 0;
}



uint32_t TSS_AuthHMAC3(unsigned char *digest, const unsigned char *key, unsigned int keylen,
                       unsigned int h1len, unsigned char *h1, ...)
{
    unsigned char paramdigest[TCM_HASH_SIZE];
    sm3_context  sha;
    unsigned int dlen;
    unsigned char *data = NULL;
    va_list argp;

    sm3_init(&sha);
    if (h1 == NULL) return ERR_NULL_ARG;
    va_start(argp, h1);
    for (;;) {
        dlen = (unsigned int)va_arg(argp, unsigned int);
        if (dlen == 0) break;
        data = (unsigned char *)va_arg(argp, unsigned char *);
        if (data == NULL) return ERR_NULL_ARG;
        sm3_update(&sha, data, dlen);
    }
    va_end(argp);
    sm3_finish(&sha, paramdigest);
    TSS_rawhmac(digest, key, keylen, TCM_HASH_SIZE, paramdigest,
                h1len, h1,
                0, 0);
    return 0;
}



TCM_RESULT TSS_CheckHMAC3(TCM_BOOL *valid,
                          TCM_HMAC expect,
                          const TCM_SECRET key,
                          unsigned int h1len, unsigned char *h1, ...)
{
    TCM_RESULT		rc = 0;
    va_list 	ap;
    TCM_HMAC		actual;
    TCM_DIGEST md;
    int 		result;

    //printf(" TSS_HMAC_Check3:\n");
    va_start(ap, h1);
    SM3_valist(md, 0, NULL, ap);
    va_end(ap);

    if (rc == 0) {
        rc = TSS_rawhmac(actual, key, TCM_SECRET_SIZE, TCM_DIGEST_SIZE, md, h1len, h1, 0, NULL);
    }
    if (rc == 0) {
        result = memcmp(expect, actual, TCM_DIGEST_SIZE);
        if (result == 0) {
            *valid = TRUE;
        } else {
            *valid = FALSE;
        }
    }

    return rc;
}




/****************************************************************************/
/*                                                                          */
/* Calculate HMAC value for an AUTH1 command                                */
/*                                                                          */
/* This function calculates the Authorization Digest for all OIAP           */
/* commands.                                                                */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* digest - a pointer to a 32 byte array that will receive the result       */
/* key    - a pointer to the key to be used in the HMAC calculation         */
/* keylen - the size of the key in bytes                                    */
/* h1     - a pointer to a 32 byte array containing the session Sequence           */
/* h2	   - an unsigned character containing the continueAuthSession value  */
/* followed by a variable length set of arguments, which must come in       */
/* pairs.                                                                   */
/* The first value in each pair is the length of the data in the second     */
/*   argument of the pair                                                   */
/* The second value in each pair is a pointer to the data to be hashed      */
/*   into the paramdigest.                                                  */
/* The last pair must be followed by a pair containing 0,0                  */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_authhmac1(unsigned char *digest, unsigned char *key, unsigned int keylen,
                       unsigned char *h1, unsigned char h2, ...)
{
    unsigned char paramdigest[TCM_HASH_SIZE];
    sm3_context  sha;
    unsigned int dlen;
    unsigned char *data;
    unsigned char c;

    va_list argp;

    sm3_init(&sha);
    if (h1 == NULL) return ERR_NULL_ARG;
    c = h2;
    va_start(argp, h2);
    for (;;) {
        dlen = (unsigned int)va_arg(argp, unsigned int);
        if (dlen == 0) break;
        data = (unsigned char *)va_arg(argp, unsigned char *);
        if (data == NULL) return ERR_NULL_ARG;

        sm3_update(&sha, data, dlen);
    }
    va_end(argp);
    sm3_finish(&sha, paramdigest);

    TSS_rawhmac(digest, key, keylen, TCM_HASH_SIZE, paramdigest,
                TCM_SEQ_SIZE, h1,
                0, 0);

    //    TCM_dump_data("paramdigest=>",paramdigest,TCM_HASH_SIZE);
    //    TCM_dump_data("usageSecret=>",key,keylen);
    //    TCM_dump_data("seq=>",h1,TCM_SEQ_SIZE);

    return 0;
}

/*entityauth: secret of another entity*/
uint32_t TSS_authhmac2(unsigned char *digest, unsigned char *key, unsigned int keylen,
                       unsigned char *entityauth, unsigned char *h1, unsigned char h2, ...)
{
    unsigned char paramdigest[TCM_HASH_SIZE];
    sm3_context  sha;
    unsigned int dlen;
    unsigned char *data;
    unsigned char c;

    va_list argp;

    sm3_init(&sha);
    if (h1 == NULL || entityauth == NULL) return ERR_NULL_ARG;
    c = h2;
    va_start(argp, h2);
    for (;;) {
        dlen = (unsigned int)va_arg(argp, unsigned int);
        if (dlen == 0) break;
        data = (unsigned char *)va_arg(argp, unsigned char *);
        if (data == NULL) return ERR_NULL_ARG;

        sm3_update(&sha, data, dlen);
    }
    va_end(argp);
    sm3_finish(&sha, paramdigest);

    TSS_rawhmac(digest, key, keylen, TCM_HASH_SIZE, paramdigest,
                TCM_SECRET_SIZE, entityauth,
                TCM_SEQ_SIZE, h1,
                0, 0);
    return 0;
}




/****************************************************************************/
/*                                                                          */
/* Calculate Raw HMAC value                                                 */
/*                                                                          */
/* This function calculates an HMAC digest                                  */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* digest - a pointer to a 32 byte array that will receive the result       */
/* key    - a pointer to the key to be used in the HMAC calculation         */
/* keylen - the size of the key in bytes                                    */
/* followed by a variable length set of arguments, which must come in       */
/* pairs.                                                                   */
/* The first value in each pair is the length of the data in the second     */
/*   argument of the pair                                                   */
/* The second value in each pair is a pointer to the data to be hashed      */
/*   into the paramdigest.                                                  */
/* The last pair must be followed by a pair containing 0,0                  */
/*                                                                          */
/****************************************************************************/

uint32_t TSS_rawhmac(unsigned char *digest, const unsigned char *key, unsigned int keylen, ...)
{
    TCM_RESULT		rc = 0;
    va_list 	ap;

    //printf(" TSS_rawhmac:\n");
    va_start(ap, keylen);
    rc = TCM_HMAC_Generatevalist(digest, key, ap);
    va_end(ap);
    return rc;
}

static TCM_RESULT TCM_HMAC_Generatevalist(TCM_HMAC tcm_hmac,
        const TCM_SECRET key,
        va_list ap)
{
    TCM_RESULT	   rc = 0;
    unsigned char   ipad[TCM_HMAC_BLOCK_SIZE];
    unsigned char   opad[TCM_HMAC_BLOCK_SIZE];
    size_t	   i;
    TCM_DIGEST	   inner_hash;

    //printf(" TCM_HMAC_Generatevalist:\n");
    /* calculate key XOR ipad and key XOR opad */
    if (rc == 0) {
        /* first part, key XOR pad */
        for (i = 0 ; i < TCM_AUTHDATA_SIZE ; i++) {
            ipad[i] = key[i] ^ 0x36;    /* magic numbers from RFC 2104 */
            opad[i] = key[i] ^ 0x5c;
        }
        /* second part, 0x00 XOR pad */
        memset(ipad + TCM_AUTHDATA_SIZE, 0x36, TCM_HMAC_BLOCK_SIZE - TCM_AUTHDATA_SIZE);
        memset(opad + TCM_AUTHDATA_SIZE, 0x5c, TCM_HMAC_BLOCK_SIZE - TCM_AUTHDATA_SIZE);
        /* calculate the inner hash, hash the key XOR ipad and the text */
        rc = TCMC_SM3_valist(inner_hash,
                             TCM_HMAC_BLOCK_SIZE, ipad, ap);
    }
    /* hash the key XOR opad and the previous hash */
    if (rc == 0) {
        rc = TSS_SM3(tcm_hmac,
                     TCM_HMAC_BLOCK_SIZE, opad,
                     TCM_DIGEST_SIZE, inner_hash,
                     0, NULL);

    }
    if (rc == 0) {
        //  TCM_PrintFour(" TCM_HMAC_Generatevalist: HMAC", tcm_hmac);
    }
    return rc;
}



