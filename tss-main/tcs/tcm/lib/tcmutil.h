/********************************************************************************/
/*										*/
/*			     	TCM Utilities					*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tcmutil.h 4401 2011-02-08 16:56:50Z stefanb $		*/
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
#ifndef TCMUTIL_H
#define TCMUTIL_H

#include <stdarg.h>
#include <stdint.h>

#include <tcm_structures.h>

#include <oiaposap.h>

#include "./crypto/sm/sm3.h"
#include "./crypto/sm/sm4.h"
#include "tcmkeys.h"

#ifdef MIN
#undef MIN
#endif

#define MIN(x,y) (x) < (y) ? (x) : (y)
#define	TCM_COUNTER_COUNTVALUE_OFFSET 6
#define TCM_COUNTER_VALUE_SIZE 10

#define TCM_MAX_TRANSPORTS 10

/* AES requires data lengths that are a multiple of the block size */
#define TCM_SM4_BITS 128
/* The AES block size is always 16 bytes */
#define TCM_SM4_BLOCK_SIZE 16


struct tcm_buffer;

uint32_t TSS_getsize(unsigned char *rsp);
int      TSS_gennonce(unsigned char *nonce);
int      TSS_buildbuff(char *format, struct tcm_buffer *, ...);
int      TSS_parsebuff(char *format, const struct tcm_buffer *, uint32_t offset, ...);
uint32_t TCM_Transmit(struct tcm_buffer *, const char *msg);
uint32_t TCM_Transmit_NoTransport(struct tcm_buffer *, const char *msg);
uint32_t TCM_Send(struct tcm_buffer *, const char *);
int      TCM_setlog(int flag);
void     TSS_sm3(void *input, unsigned int len, unsigned char *output);
uint32_t TSS_SM3File(const char *filename, unsigned char *hash);
unsigned int SM3_valist(TCM_DIGEST md, uint32_t length0, unsigned char *buffer0, va_list ap);
void     showBuff(unsigned char *buff, char *string);


uint32_t _TCM_AuditInputstream(const struct tcm_buffer *req, int is_encrypted);
uint32_t _TCM_AuditOutputstream(const struct tcm_buffer *res, uint32_t ord,
                                int is_enc);


uint32_t _TCM_GetAuditType(uint32_t ord, uint32_t *auditType);

uint32_t _TCM_IsAuditedOrdinal(uint32_t ord,   uint32_t *rc);

uint32_t TCM_SetAuditingCounterValue(TCM_COUNTER_VALUE *cv);
uint32_t TCM_ResetAuditing(void);

uint32_t TCM_SetAuditedOrdinal(uint32_t ord);
uint32_t TCM_ClearAuditedOrdinal(uint32_t ord);



////////////////////





uint32_t getNumHandles(uint32_t ord);
uint32_t getNumRespHandles(uint32_t ord);

#if 0
uint32_t TCM_OpenClientSocket(int *sock_fd);
uint32_t TCM_CloseClientSocket(int sock_fd);
uint32_t TCM_TransmitSocket(int sock_fd, struct tcm_buffer *tb);
uint32_t TCM_ReceiveSocket(int sock_fd, struct tcm_buffer *tb);
uint32_t TCM_ReceiveBytes(int sock_fd,
                          unsigned char *buffer,
                          size_t nbytes);
#endif

uint32_t tcm_buffer_load32 (const struct tcm_buffer *tb, uint32_t offset, uint32_t *val);
uint32_t tcm_buffer_load32N(const struct tcm_buffer *tb, uint32_t offset, uint32_t *val);
uint32_t tcm_buffer_load16 (const struct tcm_buffer *tb, uint32_t offset, uint16_t *val);
uint32_t tcm_buffer_load16N(const struct tcm_buffer *tb, uint32_t offset, uint16_t *val);
uint32_t tcm_buffer_store32(struct tcm_buffer *tb, uint32_t val);
uint32_t tcm_buffer_store(struct tcm_buffer *dest, struct tcm_buffer *src, uint32_t soff, uint32_t slen);

uint32_t parseHash(char *string, unsigned char *hash);
TCM_RESULT TCM_SM4_ctr128_encrypt(unsigned char *data_out,
                                  const unsigned char *data_in,
                                  uint32_t data_size,
                                  unsigned char key[16],
                                  unsigned char ctr[TCM_SM4_BLOCK_SIZE]);
#if 0
TCM_RESULT TSS_MGF1(unsigned char       *mask,
                    uint32_t             maskLen,
                    const unsigned char *mgfSeed,
                    uint32_t             mgfSeedlen);
#endif

TCM_RESULT TSS_KDF1(unsigned char       *mask,
                    uint32_t             maskLen,
                    const unsigned char *mgfSeed,
                    uint32_t             mgfSeedlen);


TCM_RESULT TSS_SM3(TCM_DIGEST md, ...);
TCM_RESULT TCMC_SM3_valist(TCM_DIGEST md,
                           uint32_t length0, unsigned char *buffer0,
                           va_list ap);

TCM_RESULT TCM_SM4Encrypt(unsigned char **output,
                          unsigned int *olen,
                          unsigned char key[16],
                          unsigned char iv[16],
                          //int mode,
                          unsigned char *message,
                          unsigned int len);

TCM_RESULT TCM_SM4Decrypt(unsigned char **output,
                          unsigned int *olen,
                          unsigned char key[16],
                          unsigned char iv[16],
                          //int mode,
                          unsigned char *message,
                          unsigned int len);

TCM_RESULT TCM_SymmetricKeyData_StreamCrypt(unsigned char *data_out,		/* output */
        const unsigned char *data_in,	/* input */
        uint32_t data_size,			/* input */
        TCM_ALGORITHM_ID algId,		/* algorithm */
        TCM_ENC_SCHEME mode,		/* mode */
        unsigned char *symmetric_key, /* input */
        uint32_t symmetric_key_size,	/* input */
        unsigned char *pad_in,		/* input */
        uint32_t pad_in_size);		/* input */

TCM_RESULT TCM_SymmetricKeyData_CtrCrypt(unsigned char *data_out,               /* output */
        const unsigned char *data_in,          /* input */
        uint32_t data_size,			/* input */
        unsigned char *symmetric_key,    /* input */
        uint32_t symmetric_key_size,		/* input */
        const unsigned char *ctr_in,		/* input */
        uint32_t ctr_in_size);			/* input */


TCM_RESULT TCM_SymmetricKeyData_OfbCrypt(unsigned char *data_out,
        const unsigned char *data_in,
        uint32_t data_size,
        unsigned char *symmetric_key,
        uint32_t symmetric_key_size,
        unsigned char *ivec_in,
        uint32_t ivec_in_size);

uint32_t TCM_encrypt(struct tcm_buffer *bufferout, struct tcm_buffer *bufferin, pubkeydata *k);


#if 0
void TCM_XOR(unsigned char *out,
             const unsigned char *in1,
             const unsigned char *in2,
             size_t length);
#endif

int allowsTransport(uint32_t ord);

void _TCM_getTransportAlgIdEncScheme(TCM_ALGORITHM_ID *algId,
                                     TCM_ENC_SCHEME *encScheme, uint32_t *blockSize);
void TCM_DetermineSessionEncryption(const session *, int *);

uint32_t needKeysRoom(uint32_t key1, uint32_t key2, uint32_t key3,
                      int room      );
uint32_t needKeysRoom_Stacked(uint32_t key1, uint32_t *orig_key1      );
uint32_t needKeysRoom_Stacked_Undo(uint32_t swapout_key, uint32_t swapin_key      );



#endif
