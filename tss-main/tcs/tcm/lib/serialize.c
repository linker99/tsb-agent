/********************************************************************************/
/*										*/
/*			     	TCM Serializing Routines 			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: serialize.c 4636 2011-10-11 01:01:29Z stefanb $		*/
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
#include <sys/stat.h>
#include <unistd.h>

#include "tcm.h"
#include "tcmutil.h"
#include "tcm_structures.h"
#include "tcmkeys.h"
#include "tcmfunc.h"
#include "newserialize.h"

uint32_t TCM_WritePCRComposite(struct tcm_buffer *buffer, TCM_PCR_COMPOSITE *comp)
{
    uint32_t ret;
    if (0 == comp->select.sizeOfSelect) {
        comp->select.sizeOfSelect = sizeof(comp->select.pcrSelect);
        memset(comp->select.pcrSelect,
               0x0,
               comp->select.sizeOfSelect);
    }
    ret = TSS_buildbuff(FORMAT_TCM_PCR_COMPOSITE, buffer,
                        PARAMS_TCM_PCR_COMPOSITE_W(comp));

    return ret;
}





uint32_t TCM_WritePCRInfo(struct tcm_buffer *buffer, TCM_PCR_INFO *info)
{
    uint32_t ret;
    if (0 == info->PcrAtCreation.sizeOfSelect) {
        info->PcrAtCreation.sizeOfSelect = sizeof(info->PcrAtCreation.pcrSelect);
        memset(info->PcrAtCreation.pcrSelect,
               0x0,
               info->PcrAtCreation.sizeOfSelect);
    }
    if (0 == info->PcrAtRelease.sizeOfSelect) {
        info->PcrAtRelease.sizeOfSelect = sizeof(info->PcrAtRelease.pcrSelect);
        memset(info->PcrAtRelease.pcrSelect,
               0x0,
               info->PcrAtRelease.sizeOfSelect);
    }
    ret = TSS_buildbuff(FORMAT_TCM_PCR_INFO, buffer,
                        PARAMS_TCM_PCR_INFO_W(info));
    return ret;
}












uint32_t TCM_HashPCRComposite(TCM_PCR_COMPOSITE *comp, unsigned char *digest      )
{
    int len;
    struct tcm_buffer *buffer = TSS_AllocTCMBuffer(comp->pcrValue.size + sizeof(TCM_PCR_COMPOSITE)          );
    if (NULL != buffer) {
        len = TCM_WritePCRComposite(buffer, comp);
        TSS_sm3(buffer->buffer, len, digest);
        TSS_FreeTCMBuffer(buffer);
    } else {
        return ERR_MEM_ERR;
    }
    return 0;
}
uint32_t TCM_ReadFile(const char *filename, unsigned char **buffer, uint32_t *buffersize)
{
    uint32_t ret = 0;
    struct stat _stat;
    if (0 == stat(filename, &_stat)) {
        *buffer = (unsigned char *)malloc(_stat.st_size);
        *buffersize = (uint32_t)_stat.st_size;
        if (NULL != *buffer) {
            FILE *f = fopen(filename, "r");
            if (NULL != f) {
                if ((size_t)_stat.st_size != fread(*buffer, 1, _stat.st_size, f)) {
                    free(*buffer);
                    *buffer = NULL;
                    *buffersize = 0;
                    ret = ERR_BAD_FILE;
                }
                if (fclose(f) != 0)
                    ret = ERR_BAD_FILE_CLOSE;
            } else {
                free(*buffer);
                *buffersize = 0;
                ret = ERR_BAD_FILE;
            }
        } else {
            ret = ERR_MEM_ERR;
        }
    } else {
        ret = ERR_BAD_FILE;
    }

    return ret;
}

uint32_t TCM_WriteFile(const char *filename, unsigned char *buffer, uint32_t buffersize)
{
    uint32_t ret = 0;
    if (buffer == NULL) {
        return ERR_BUFFER;
    }
    FILE *f = fopen(filename, "w");
    if (NULL != f) {
        if (buffersize != fwrite(buffer, 1, buffersize, f)) {
            ret = ERR_BAD_FILE;
        }
        if (fclose(f) != 0)
            ret = ERR_BAD_FILE_CLOSE;
    } else {
        ret = ERR_BAD_FILE;
    }

    return ret;
}

uint32_t TCM_ReadKeyfile(const char *filename, keydata *k)
{
    unsigned char *buffer = NULL;
    uint32_t buffersize = 0;
    uint32_t ret = TCM_ReadFile(filename, &buffer, &buffersize);

    if ( (ret & ERR_MASK) == 0 ) {
        STACK_TCM_BUFFER( buf);
        SET_TCM_BUFFER(&buf, buffer, buffersize);
        memset(k, 0x0, sizeof(keydata));
        if (buffersize != TSS_KeyExtract(&buf, 0, k)) {
            ret = ERR_BAD_FILE;
        }
        free(buffer);
    }
    return ret;
}

uint32_t TCM_WritePubInfo(TCM_NV_DATA_PUBLIC *pub,
                          struct tcm_buffer *buffer)
{
    uint32_t ret;

    if (0 == pub->pcrInfoWrite.pcrSelection.sizeOfSelect) {
        pub->pcrInfoWrite.pcrSelection.sizeOfSelect = sizeof(pub->pcrInfoWrite.pcrSelection.pcrSelect);
        memset(pub->pcrInfoWrite.pcrSelection.pcrSelect,
               0x0,
               pub->pcrInfoWrite.pcrSelection.sizeOfSelect);
    }
    if (0 == pub->pcrInfoRead.pcrSelection.sizeOfSelect) {
        pub->pcrInfoRead.pcrSelection.sizeOfSelect = sizeof(pub->pcrInfoRead.pcrSelection.pcrSelect);
        memset(pub->pcrInfoRead.pcrSelection.pcrSelect,
               0x0,
               pub->pcrInfoRead.pcrSelection.sizeOfSelect);
    }
    ret = TSS_buildbuff(FORMAT_TCM_NV_DATA_PUBLIC, buffer,
                        PARAMS_TCM_NV_DATA_PUBLIC_W(pub));
    return ret;
}


/* the most recent permanent flags */



uint32_t TCM_ReadNVDataPublic(const struct tcm_buffer *tb,
                              uint32_t offset,
                              TCM_NV_DATA_PUBLIC *ndp)
{
    uint32_t ret;
    ret = TSS_parsebuff(FORMAT_TCM_NV_DATA_PUBLIC, tb, offset,
                        PARAMS_TCM_NV_DATA_PUBLIC_R(ndp));
    return ret;
}

/****************************************************************************/
/*                                                                          */
/* Create a buffer from a keydata structure                                 */
/*                                                                          */
/****************************************************************************/
//equal TCM_Key_Store   TCM_Key_StorePub   TCM_KeyPub_Store
uint32_t TCM_WriteKey(struct tcm_buffer *buffer, keydata *k)
{
    uint32_t ret;
    uint16_t filler = 0;


    switch (k->pub.algorithmParms.algorithmID) {
    case TCM_ALG_SM2:
        ret = TSS_buildbuff(FORMAT_TCM_KEY12_EMB_SM2, buffer,
                            PARAMS_TCM_KEY12_EMB_SM2_W(k) );
        break;

    case TCM_ALG_SM4:
        ret = TSS_buildbuff(FORMAT_TCM_KEY12_EMB_SM4, buffer,
                            PARAMS_TCM_KEY12_EMB_SM4_W(k) );

        break;

    default:
        ret = ERR_BAD_ARG;
        break;
    }



    return ret;
}

//equal TCM_KeyPub_Load
uint32_t TCM_ReadKey(const struct tcm_buffer *tb, uint32_t offset, keydata *k)
{
    uint32_t ret;
    uint16_t filler = 0;


    if(tb->buffer[offset + 14] == 0x0b) {
        ret = TSS_parsebuff(FORMAT_TCM_KEY12_EMB_SM2, tb, offset,
                            PARAMS_TCM_KEY12_EMB_SM2_R(k));
    } else if(tb->buffer[offset + 14] == 0x0c) {
        ret = TSS_parsebuff(FORMAT_TCM_KEY12_EMB_SM4, tb, offset,
                            PARAMS_TCM_KEY12_EMB_SM4_R(k));
    } else {
        printf("error key type\n ");
        ret = ERR_BAD_ARG;
    }



    return ret;

}
//equal TCM_KeyPubShort_Store   | use to store struct pubkeydata
uint32_t TCM_WritePubKeyData(struct tcm_buffer *buffer, keydata *k)
{
    uint32_t ret;

    ret = TCM_WriteKeyInfo(buffer, k); //store cipherScheme

    ret = TSS_buildbuff("@", buffer,
                        k->pub.pubKey.keyLength, k->pub.pubKey.modulus); //store pubkey
    return ret;
}

//equal TCM_CipherScheme_Store

uint32_t TCM_WriteKeyInfo(struct tcm_buffer *buffer, keydata *k)
{
    uint32_t ret = -1;

    switch (k->pub.algorithmParms.algorithmID) {
    case TCM_ALG_SM2:
        ret = TSS_buildbuff(FORMAT_TCM_KEY_PARMS_EMB_SM2, buffer,
                            PARAMS_TCM_KEY_PARMS_EMB_SM2_W(&k->pub.algorithmParms));
        break;

    case TCM_ALG_SM4:
        ret = TSS_buildbuff(FORMAT_TCM_KEY_PARMS_EMB_SYM, buffer,
                            PARAMS_TCM_KEY_PARMS_EMB_SYM_W(&k->pub.algorithmParms));

        break;

    default:
        ret = ERR_BAD_ARG;
        break;
    }

    return ret;
}

uint32_t TCM_WriteTransportPublic(struct tcm_buffer *tb,
                                  TCM_TRANSPORT_PUBLIC *ttp)
{
    uint32_t ret = 0;
    ret = TSS_buildbuff(FORMAT_TCM_TRANSPORT_PUBLIC, tb,
                        PARAMS_TCM_TRANSPORT_PUBLIC_W(ttp));
    return ret;
}

uint32_t TCM_WriteTransportAuth(struct tcm_buffer *tb,
                                TCM_TRANSPORT_AUTH *tta)
{
    uint32_t ret = 0;
    ret = TSS_buildbuff(FORMAT_TCM_TRANSPORT_AUTH, tb,
                        PARAMS_TCM_TRANSPORT_AUTH_W(tta));
    return ret;
}

uint32_t TCM_WriteAuditEventIn(struct tcm_buffer *buffer, TCM_AUDIT_EVENT_IN *aei)
{
    uint32_t ret;
    ret = TSS_buildbuff(FORMAT_TCM_AUDIT_EVENT_IN, buffer,
                        PARAMS_TCM_AUDIT_EVENT_IN_W(aei));
    return ret;
}

uint32_t TCM_WriteAuditEventOut(struct tcm_buffer *buffer, TCM_AUDIT_EVENT_OUT *aeo)
{
    uint32_t ret;
    ret = TSS_buildbuff(FORMAT_TCM_AUDIT_EVENT_OUT, buffer,
                        PARAMS_TCM_AUDIT_EVENT_OUT_W(aeo));
    return ret;
}


uint32_t TCM_WriteTransportLogIn(struct tcm_buffer *buffer,
                                 TCM_TRANSPORT_LOG_IN *ttli)
{
    return TSS_buildbuff(FORMAT_TCM_TRANSPORT_LOG_IN, buffer,
                         PARAMS_TCM_TRANSPORT_LOG_IN_W(ttli));
}

uint32_t TCM_WriteTransportLogOut(struct tcm_buffer *buffer,
                                  TCM_TRANSPORT_LOG_OUT *ttlo)
{
    return TSS_buildbuff(FORMAT_TCM_TRANSPORT_LOG_OUT, buffer,
                         PARAMS_TCM_TRANSPORT_LOG_OUT_W(ttlo));
}
uint32_t TCM_ReadCurrentTicks(struct tcm_buffer *buffer,
                              uint32_t offset,
                              TCM_CURRENT_TICKS *tct)
{
    return TSS_parsebuff(FORMAT_TCM_CURRENT_TICKS, buffer, offset,
                         PARAMS_TCM_CURRENT_TICKS_R(tct));
}


uint32_t TCM_WriteCurrentTicks_Short(struct tcm_buffer *buffer,
                                     TCM_UINT64 *currentTicks)
{
    return TSS_buildbuff(FORMAT_TCM_CURRENT_TICKS_SHORT, buffer,
                         PARAMS_TCM_CURRENT_TICKS_SHORT_W(currentTicks));
}

uint32_t TCM_ReadCurrentTicks_Short(struct tcm_buffer *buffer,
                                    uint32_t offset,
                                    TCM_UINT64 *currentTicks)
{
    return TSS_parsebuff(FORMAT_TCM_CURRENT_TICKS_SHORT, buffer, offset,
                         PARAMS_TCM_CURRENT_TICKS_SHORT_R(currentTicks));
}


/****************************************************************************/
/*                                                                          */
/* Walk down a Key blob extracting information                              */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_KeyExtract(const struct tcm_buffer *tb, uint32_t offset,
                        keydata *k)
{
    return TCM_ReadKey(tb, offset, k);
}

/****************************************************************************/
/*                                                                          */
/* Walk down a Public Key blob extracting information                       */
/*                                                                          */
/****************************************************************************/
//equal TCM_KeyPubShort_Load()
uint32_t TSS_PubKeyExtract(const struct tcm_buffer *tb, uint32_t offset,
                           pubkeydata *k)
{
    uint32_t ret;

    //TCM_dump_data("#####data",&(tb->buffer[offset]),tb->used);

    if(tb->buffer[offset + 3] == 0x0b) {
        ret = TSS_parsebuff(FORMAT_TCM_PUBKEY_EMB_SM2, tb, offset,
                            PARAMS_TCM_PUBKEY_EMB_SM2_R(k));
    } else if(tb->buffer[offset + 3] == 0x0c) {
        ret = TSS_parsebuff(FORMAT_TCM_PUBKEY_EMB_SYM, tb, offset,
                            PARAMS_TCM_PUBKEY_EMB_SYM_R(k));
    } else {
        printf("error key type\n ");
        ret = ERR_BAD_ARG;
    }


    return ret;
}

