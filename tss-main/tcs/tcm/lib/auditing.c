/********************************************************************************/
/*										*/
/*			     	TCM Auditing Routines				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: auditing.c 4637 2011-10-11 01:02:07Z stefanb $		*/
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
#include <tcm_error.h>


#define TCM_ORDINALS_MASK      0x000000FF
#define TCM_ORDINALS_MASK_1    0x400000FF
#define TCM_ORDINALS_MASK_2    0x40000000
#define TCM_ORDINALS_UNMASK    0x00008000



static uint32_t _TCM_SetAuditingCounterValue(TCM_COUNTER_VALUE *cv);
static uint32_t _TCM_SetAuditDigest(TCM_DIGEST *digest);
static uint32_t _TCM_InitAuditing(void);





static char *getAuditingFile()
{
    char *filename=NULL;
    char *inst = getenv("TCM_INSTANCE");
    if (NULL == inst) {
        inst = "0";
    }
    if(filename = malloc(strlen(inst) + strlen(".auditing-") + 2)){
        sprintf(filename, ".auditing-%s", inst);
    }
    return filename;
}

struct auditing {
    uint8_t ordinalbitmap[256 / 8];
    TCM_DIGEST inDigest;
    TCM_DIGEST auditDigest;
    TCM_DIGEST calcAuditDigest;
    TCM_COUNTER_VALUE auditCounter;
};


static
uint32_t _TCM_SM3_NoAuthParms(const struct tcm_buffer *buf,
                              uint32_t handles,
                              uint32_t size,
                              TCM_DIGEST *digest,
                              int is_enc)
{
    uint32_t ret = 0;
    uint32_t offset = handles * 4;
    if (is_enc) {
        unsigned char buffer[8];
        memcpy(&buffer[0], &buf->buffer[6], 8);
        //print_array("buffer to hash:",buffer,4);
        TSS_sm3(buffer, 8, (unsigned char *)digest);
        //print_array("inparam digest (ENC):", (unsigned char *)digest, 20);
    } else {
        if (size > 0) {
            unsigned char *buffer = malloc(size);
            if (buffer) {
                uint32_t sz = (size < 8) ? size : 8;
                memcpy(&buffer[0], &buf->buffer[6], sz);
                if (size > 8) {
                    memcpy(&buffer[sz], &buf->buffer[14 + offset], size - 8);
                }
                //print_array("buffer to hash:",buffer,size);
                TSS_sm3(buffer, size, (unsigned char *)digest);
                //print_array("inparam digest:", (unsigned char *)digest, 32);
                free(buffer);
            } else {
                ret = ERR_MEM_ERR;
            }
        } else {
            //printf("*** %s: size=%d\n",__FUNCTION__,size);
        }
    }
    return ret;
}

static
uint32_t _TCM_SM3_NoAuthParmsResp(const struct tcm_buffer *buf,
                                  uint32_t handles,
                                  uint32_t size,
                                  TCM_DIGEST *digest,
                                  uint32_t ordinal,
                                  int is_enc)
{
    uint32_t ret = 0;
    uint32_t offset = handles * 4;

    //	printf("%s:\n",__func__);
    if (is_enc) {
        if (size >= 4) {
            size = 4;
        }
    }
    if (size > 0) {
        unsigned char *buffer = malloc(size + sizeof(ordinal));
        if (buffer) {
            uint32_t ord_no = htonl(ordinal);
            uint32_t sz = (size < 4) ? size : 4;
            memcpy(&buffer[0], &ord_no, sizeof(ord_no));
            memcpy(&buffer[4] , &buf->buffer[6], sz);
            if (size > 4) {
                size -= (4 * handles);
                memcpy(&buffer[sz + 4],
                       &buf->buffer[10 + offset],
                       size - 4);
            }
            TSS_sm3(buffer,
                    size + sizeof(ordinal),
                    (unsigned char *)digest);

            free(buffer);
        } else {
            ret = ERR_MEM_ERR;
        }
    }
    return ret;
}

static uint32_t _TCM_ReadAuditingData(  struct auditing *au)
{
    uint32_t ret = 0;
    if (!au) return ERR_BAD_ARG;
    char *filename = getAuditingFile();
    FILE *f = fopen(filename, "r");

    if (f) {
        size_t n;
        memset(au, 0x0, sizeof(*au));
        n = fread(au, sizeof(*au), 1, f);

        if (fclose(f) != 0 && ret == 0)
            ret = ERR_BAD_FILE_CLOSE;
    } else {
        ret = _TCM_InitAuditing();
    }
	
	if(filename) free(filename);
    return ret;
}

static uint32_t _TCM_WriteAuditingData(  struct auditing *au)
{
    uint32_t ret = 0;
    if (!au) return ERR_BAD_ARG;
    char *filename = getAuditingFile();
    FILE *f = fopen(filename, "w");
    //	printf("%s:\n",__func__);
    if (f) {
        fwrite(au, sizeof(*au), 1, f);
        if (fclose(f) != 0)
            ret = ERR_BAD_FILE_CLOSE;
    }
	if(filename) free(filename);
    return ret;
}

uint32_t _TCM_AuditInputstream(const struct tcm_buffer *req, int is_enc)
{
    uint32_t ret = TCM_SUCCESS;
    uint16_t tag;
    int32_t size;
    uint32_t handles = 0;
    uint32_t ord;
    TCM_AUDIT_EVENT_IN aei;
    struct auditing au;
    if (!req) return ERR_BAD_ARG;


    ret = tcm_buffer_load16(req, 0, &tag);
    if (0 == ret) {
        ret = tcm_buffer_load32(req, 2, (uint32_t *)&size);
    }
    if (0 == ret) {
        ret = tcm_buffer_load32(req, 6, &ord);
    }


    if (0 == ret) {
        uint32_t rc = 0;
        _TCM_IsAuditedOrdinal(ord,  &rc);
        if (rc == 0) {
            return TCM_SUCCESS;
        }
    }

    if (0 == ret) {
        handles = getNumHandles(ord);
    }
    if (0 == ret) {
        if (tag == TCM_TAG_RQU_COMMAND) {
        } else if (tag == TCM_TAG_RQU_PROTECT_COMMAND) {
            size -= 37;
        } else if (tag == TCM_TAG_RQU_PROTECT_COMMAND_forTCM) {
            size -= 90;
        } else {
            //ret = ERR_BADREQTAG
        }

        if (ord == TCM_ORD_AP) {
            //size -= (6 + 8 + 2 + 4 + 1 + 32);   //Size would be 0, since TCM_ORD_AP does not need audition.
            return TCM_SUCCESS;
        }  else {
            size -= (6 + 4 * handles);
        }

        if (size < 0) {
            ret = ERR_BUFFER;
        }
    }

    if (ret == 0) {
        aei.tag = TCM_TAG_AUDIT_EVENT_IN;
        ret  = _TCM_SM3_NoAuthParms(req, handles, size,
                                    &aei.inputParms,
                                    is_enc);
    }

    if (ret == 0) {
        ret = _TCM_ReadAuditingData(     &au);
    }

    if (ret == 0) {
        uint32_t aei_len = 0;
        STACK_TCM_BUFFER(audit_event_ser);
        memcpy(&aei.auditCount,
               &au.auditCounter,
               sizeof(aei.auditCount));
        ret = TCM_WriteAuditEventIn(&audit_event_ser,
                                    &aei);

        if (! (ret & ERR_MASK)) {
            aei_len = ret;
            ret = 0;
        }

        if (ret == 0) {
            char *buffer = malloc(aei_len + TCM_DIGEST_SIZE);
            if (buffer) {
                memcpy(&buffer[0],
                       au.auditDigest,
                       TCM_DIGEST_SIZE);
                memcpy(&buffer[TCM_DIGEST_SIZE],
                       audit_event_ser.buffer,
                       aei_len);

                TSS_sm3(buffer,
                        aei_len + TCM_DIGEST_SIZE,
                        (unsigned char *)au.auditDigest);

                free(buffer);
            } else {
                ret = ERR_MEM_ERR;
            }
        }
    }

    if (ret == 0) {
        ret = _TCM_WriteAuditingData(&au);
    }

    return ret;
};


uint32_t _TCM_AuditOutputstream(const struct tcm_buffer *res, uint32_t ord,
                                int is_enc)
{
    uint32_t ret = TCM_SUCCESS;
    uint16_t tag;
    int32_t size;
    TCM_AUDIT_EVENT_OUT aeo;
    struct auditing au;
    uint32_t handles = 0;
    uint32_t result = 0;
    uint32_t privCode = 0;

    if (!res) return ERR_BAD_ARG;

    //	printf("%s:\n",__func__);
    ret = tcm_buffer_load16(res, 0, &tag);
    if (ret == 0) {
        ret = tcm_buffer_load32(res, 2, (uint32_t *)&size);
    }

    if (ret == 0) {
        ret = tcm_buffer_load32(res, 6, (uint32_t *)&result);
    }

    if (0 == ret) {
        uint32_t rc;
        _TCM_IsAuditedOrdinal(ord, &rc);
        if (rc == 0) {
            return TCM_SUCCESS;
        }
    }


    if (0 == ret) {
        handles = getNumRespHandles(ord);
    }

    if (ret == 0) {
        if (result == 0) {
            if (tag == TCM_TAG_RSP_COMMAND) {
            } else if (tag == TCM_TAG_RQU_PROTECT_COMMAND) {
                size -= 36;
            } else if (tag == TCM_TAG_RQU_PROTECT_COMMAND_forTCM) {
                size -= 72;
            }
            if (ord == TCM_ORD_AP) {
                return TCM_SUCCESS;
            } else {
                size -= 6;
            }
        } else {
            size -= 6;
        }

        if (size < 0) {
            ret = ERR_BUFFER;
        }
    }
    if (ret == 0) {
        aeo.tag = TCM_TAG_AUDIT_EVENT_OUT;
        ret  = _TCM_SM3_NoAuthParmsResp(res, handles, size,
                                        &aeo.outputParms,
                                        ord,
                                        is_enc);
    }

    if (ret == 0) {
        ret = _TCM_ReadAuditingData( &au);
    }

    if (ret == 0) {
        uint32_t aeo_len = 0;
        STACK_TCM_BUFFER(audit_event_ser);
        char *buffer;
        memcpy(&aeo.auditCount,
               &au.auditCounter,
               sizeof(aeo.auditCount));
        ret = TCM_WriteAuditEventOut(&audit_event_ser,
                                     &aeo);

        if (! (ret & ERR_MASK)) {
            aeo_len = ret;
            ret = 0;
        }
        if (ret == 0) {
            buffer = malloc(aeo_len + TCM_DIGEST_SIZE);
            if (buffer) {
                memcpy(&buffer[0],
                       au.auditDigest,
                       TCM_DIGEST_SIZE);
                memcpy(&buffer[TCM_DIGEST_SIZE],
                       audit_event_ser.buffer,
                       audit_event_ser.used);
                TSS_sm3(buffer,
                        aeo_len + TCM_DIGEST_SIZE,
                        (unsigned char *)&au.auditDigest);

                free(buffer);

            } else {
                ret = ERR_MEM_ERR;
            }
        }
    }

    if (ret == 0) {
        ret = _TCM_WriteAuditingData(  &au);
    }
    return ret;
};

static const uint32_t never_audit_ord[] = {
    TCM_ORD_GetAuditDigest,
    TCM_ORD_GetAuditDigestSigned,
    TCM_ORD_SetOrdinalAuditStatus,
    0
};

uint32_t TCM_SetAuditedOrdinal(uint32_t ord)
{
    struct auditing au;
    uint32_t ret;
    uint32_t ordinal;
    uint32_t ctr = 0;

    //	printf("%s:\n",__func__);
    while ( 0 != (ordinal = never_audit_ord[ctr])) {
        if (ordinal == ord) {
            return 0;
        }
        ctr++;
    }

    ret = _TCM_ReadAuditingData(&au);
    if (ret == 0) {
        uint8_t mask = 1 << (ord & 0x7);
        uint8_t idx = (ord & 0xff) >> 3;
        au.ordinalbitmap[idx] |= mask;
        ret = _TCM_WriteAuditingData(&au);
    }
    return ret;
}

uint32_t TCM_ClearAuditedOrdinal(uint32_t ord)
{
    struct auditing au;
    uint32_t ret = _TCM_ReadAuditingData(&au);
    //	printf("%s:\n",__func__);
    if (ret == 0) {
        uint8_t mask = (1 << (ord & 0x7)) ^ 0xff;
        uint8_t idx = (ord & 0xff) >> 3;
        au.ordinalbitmap[idx] &= mask;
        ret = _TCM_WriteAuditingData(&au);
    }
    return 0;
}
uint32_t _TCM_IsAuditedOrdinal(uint32_t ord, uint32_t *rc)
{
    uint32_t ret = 0;
    struct auditing au;
    if (!rc) return ERR_BAD_ARG;
    ret = _TCM_ReadAuditingData(&au);
    //	printf("%s:\n",__func__);
    *rc = 0;
    if (ret == 0) {
        if (ord & TCM_ORDINALS_MASK >= 256) {
            *rc = 0;
        } else {
            uint8_t mask = 1 << (ord & 0x7);
            uint8_t idx = (ord & 0xff) >> 3;
            if (mask & au.ordinalbitmap[idx]) {
                *rc = 1;
            }
        }
    }

    return ret;
}

static uint32_t _TCM_SetAuditingCounterValue(TCM_COUNTER_VALUE *cv)
{
    uint32_t ret = 0;
    struct auditing au;
    if (!cv) return ERR_BAD_ARG;
    ret = _TCM_ReadAuditingData(&au);
    //	printf("%s:\n",__func__);
    if (ret == 0) {
        au.auditCounter = *cv;
        ret = _TCM_WriteAuditingData(&au);
    }
    return ret;
}

static uint32_t _TCM_SetAuditDigest(  TCM_DIGEST *digest)
{
    uint32_t ret = 0;
    struct auditing au;
    if (!digest) return ERR_BAD_ARG;
    ret = _TCM_ReadAuditingData( &au);
    //	printf("%s:\n",__func__);
    if (ret != 0) {
        ret = _TCM_InitAuditing();
    }
    if (ret == 0) {
        memcpy(au.calcAuditDigest, au.auditDigest, TCM_DIGEST_SIZE);
#if 1
        print_array("my digest: ", (unsigned char *)au.auditDigest, TCM_DIGEST_SIZE);
#endif
        memcpy(au.auditDigest, digest, TCM_DIGEST_SIZE);
        ret = _TCM_WriteAuditingData(&au);
    }
    return ret;
}

static const uint32_t def_audit_ord[] = {
    TCM_ORD_ActivateIdentity ,
    TCM_ORD_AuthorizeMigrationKey,
    TCM_ORD_ActivatePEK ,
    TCM_ORD_ActivatePEKCert,
    TCM_ORD_CertifyKey,
    TCM_ORD_CreateEndorsementKeyPair,
    TCM_ORD_CreateRevocableEK ,
    TCM_ORD_ContinueSelfTest,
    TCM_ORD_TestActivatePEK ,
    TCM_ORD_PhysicalSetDeactivated ,
    TCM_ORD_SetOperatorAuth ,
    TCM_ORD_SetTempDeactivated  ,
    TCM_ORD_CreateMigrationBlob	,
    TCM_ORD_ChangeAuth  ,
    TCM_ORD_ChangeAuthOwner  ,
    TCM_ORD_ConvertMigrationBlob	,
    TCM_ORD_CreateWrapKey ,
    TCM_ORD_LoadKey  ,
    TCM_ORD_GetPubKey ,
    TCM_ORD_WrapKey ,
    TCM_ORD_CreateCounter  ,
    TCM_ORD_EstablishTransport ,
    TCM_ORD_ExecuteTransport  ,
    TCM_ORD_Extend,
    TCM_ORD_GetCapability ,
    TCM_ORD_GetTicks    ,
    TCM_ORD_NV_DefineSpace ,
    TCM_ORD_NV_ReadValue ,
    TCM_ORD_NV_ReadValueAuth ,
    TCM_ORD_NV_WriteValue ,
    TCM_ORD_NV_WriteValueAuth ,
    TCM_ORD_IncrementCounter ,
    TCM_ORD_Init ,
    TCM_ORD_OwnerClear  ,
    TCM_ORD_OwnerSetDisable ,
    TCM_ORD_DisableOwnerClear ,
    TCM_ORD_PhysicalDisable,
    TCM_ORD_DisableForceClear ,
    TCM_ORD_ForceClear ,
    TCM_ORD_PhysicalEnable ,
    TCM_ORD_SetOwnerInstall,
    TCM_ORD_RevokeTrust,
    TCM_ORD_ReadCounter ,
    TCM_ORD_PCRRead ,
    TCM_ORD_Quote ,
    TCM_ORD_ReadPubek ,
    TCM_ORD_PCR_Reset ,
    TCM_ORD_ReleaseCounter ,
    TCM_ORD_ReleaseCounterOwner ,
    TCM_ORD_ReleaseTransport ,
    TCM_ORD_SaveState ,
    TCM_ORD_SetCapability ,
    TCM_ORD_Startup ,
    TCM_ORD_SM3Update ,
    TCM_ORD_SM3Complete ,
    TCM_ORD_SM3CompleteExtend ,
    TCM_ORD_Sign ,
    TCM_ORD_TakeOwnership,
    TCM_ORD_FlushSpecific,
    TCM_ORD_TickStampBlob,
    TCM_ORD_SM3Start,
    TCM_ORD_GetRandom,
    TCM_ORD_SaveContext ,
    TCM_ORD_LoadContext ,
    TCM_ORD_GetTestResult,
    TCM_ORD_SelfTestFull,
    TCM_ORD_Seal,
    TCM_ORD_Unseal,
    TCM_ORD_MakeIdentity,
    TCM_ORD_SM4Encrypt ,
    TCM_ORD_SM4Decrypt,
    TCM_ORD_SM2Decrypt,
    TCM_ORD_OwnerReadInternalPub,
    TCM_ORD_CreateKeyExchange,
    TCM_ORD_GetKeyExchange,
    TCM_ORD_ReleaseExchangeSession,
    TSC_ORD_PhysicalPresence,
    TSC_ORD_ResetEstablishmentBit,
    0
};


static uint32_t _TCM_InitAuditing(void)
{
    struct auditing au;
    uint32_t ctr = 0;
    printf("*** Initializing auditing file.\n");
    memset(&au, 0x0, sizeof(au));
    while (def_audit_ord[ctr]) {
        uint32_t ord = def_audit_ord[ctr] & TCM_ORDINALS_MASK;
        uint8_t idx = ord >> 3;
        uint8_t mask = 1 << (ord & 0x7);
        au.ordinalbitmap[idx] |= mask;
        ctr++;
    }
    TCM_dump_data("_TCM_InitAuditing Data", &au, sizeof(au));
    return _TCM_WriteAuditingData(&au);
}



