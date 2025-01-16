/********************************************************************************/
/*										*/
/*			     	TCM Transport Routines				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: transport.c 4639 2011-10-11 01:21:33Z stefanb $		*/
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
#include "tcmutil.h"

uint32_t g_num_transports;
uint32_t (*g_transportFunction[TCM_MAX_TRANSPORTS])(struct tcm_buffer *tb, const char *msg);

static session *g_transSession[TCM_MAX_TRANSPORTS];

/****************************************************************************/
/*                                                                          */
/* Functions for handling the trans digest                                  */
/*                                                                          */
/****************************************************************************/

/**
 * Calculate the transdigest for the EstablishTransport function.
 * Perform calculations on TCM_TRANSPORT_LOG_IN structure and
 * return the transdigest as calculated in step 8) a) iii) (rev. 100)
 *
 */
static
uint32_t _calc_transdigest(TCM_COMMAND_CODE ordinal,

                           TCM_TRANSPORT_PUBLIC *ttp,
                           struct tcm_buffer *secret,
                           TCM_DIGEST *transdigest)
{
    TCM_TRANSPORT_LOG_IN ttli;
    uint32_t ret = 0;
    STACK_TCM_BUFFER(buffer);
    STACK_TCM_BUFFER(transPub);
    STACK_TCM_BUFFER(ser_ttli);
    TCM_DIGEST empty;

    ret = TCM_WriteTransportPublic(&transPub, ttp);
    if ((ret & ERR_MASK)) {
        return ret;
    }

    /* ordinal|| transPublic || SecretSize || secret */
    ret = TSS_buildbuff("L % @", &buffer,
                        ordinal,
                        transPub.used, transPub.buffer,
                        secret->used, secret->buffer);

    if ((ret & ERR_MASK)) {
        return ret;
    }
    /* L1 -> parameters is sm3( ... ) */
    TSS_sm3(buffer.buffer, buffer.used, ttli.parameters);
    /* pubkey hash to NULL */
    memset(ttli.pubKeyHash, 0x0, sizeof(ttli.pubKeyHash));
    /* fill other L1 parameters as defined */
    ttli.tag = TCM_TAG_TRANSPORT_LOG_IN;

    ret = TCM_WriteTransportLogIn(&ser_ttli, &ttli);
    if ((ret & ERR_MASK)) {
        return ret;
    }

    memset(empty, 0x0, sizeof(empty));

    RESET_TCM_BUFFER(&buffer);
    /* transdigest is 000000... */
    SET_TCM_BUFFER(&buffer, empty, sizeof(empty));
    /* L1 */
    tcm_buffer_store(&buffer, &ser_ttli, 0x0, ser_ttli.used);

    /* calculate T1->transDigest as sm3(T1->transDigest || L1) */
    TSS_sm3(buffer.buffer, buffer.used, (unsigned char *)transdigest);

#if 0
    print_array("_calc_transdigest: transdigest: ",
                (unsigned char *)transdigest, TCM_DIGEST_SIZE);
#endif

    ret = 0;

    return ret;
}

/**
 *  Get the appropriate filename for the transDigest to write out to
 *  for the TCM_INSTANCE that the library is currently using.
 **/
static
char *_get_transdigest_file(uint32_t handle)
{
    char *filename = malloc(50);
    char *instance = getenv("TCM_INSTANCE");
    int inst;
    if (instance == NULL) {
        instance = "0";
    }
    inst = atoi(instance);

    sprintf(filename, "/tmp/.transdigest-%08x-%d", handle, inst);
    return filename;
}


/*
 * Read the value of the transdigest for the TCM_INSTANCE that the
 * library is currently using.
 */
static
uint32_t _read_transdigest(uint32_t handle, unsigned char *digest)
{
    uint32_t ret = 0;
    char *filename = _get_transdigest_file(handle);
    if (filename) {
        FILE *file = fopen(filename, "r");
        if (file != NULL) {
            if (1 != fread(digest, TCM_DIGEST_SIZE, 1, file)) {
                ret = ERR_IO;
            }
            fclose(file);
        } else {
            ret = ERR_BAD_FILE;
        }
        free(filename);
    } else {
        ret = ERR_MEM_ERR;
    }
    return ret;
}


/*
 * Write the transdigest for the TCM_INSTANCE that the library
 * is currently using into a file.
 */
static
uint32_t _store_transdigest(uint32_t handle, unsigned char *digest)
{
    uint32_t ret = 0;
    char *filename = _get_transdigest_file(handle);
    if (filename) {
        FILE *file = fopen(filename, "w");
        if (file != NULL) {
            if (1 != fwrite(digest, TCM_DIGEST_SIZE, 1, file)) {
                ret = ERR_IO;
            }
            if (fclose(file) != 0)
                ret = ERR_BAD_FILE_CLOSE;
        } else {
            ret = ERR_BAD_FILE;
        }
        free(filename);
    } else {
        ret = ERR_MEM_ERR;
    }
    return ret;
}


/*
 * Extend the transdigest by reading its current value from the
 * file for the TCM_INSTANCE that the library is currently using
 * and calculate
 *  transdigest_new = sm3(transdigest || data)
 * and write the new transdigest back into the file.
 */
static
uint32_t _extend_transdigest(uint32_t handle, struct tcm_buffer *data)
{
    uint32_t ret = 0;
    char *filename = _get_transdigest_file(handle);
    if (filename) {
        FILE *file = fopen(filename, "r+");
        STACK_TCM_BUFFER(buffer);
        if (file != NULL) {
            if (1 != fread(buffer.buffer, TCM_DIGEST_SIZE, 1, file)) {
                ret = ERR_IO;
            } else {
                TCM_DIGEST digest;
#if 0
                print_array("_extend_transdigest: transdigest in: ", buffer.buffer, TCM_DIGEST_SIZE);
#endif
                buffer.used = TCM_DIGEST_SIZE;
                tcm_buffer_store(&buffer, data, 0, data->used);
                TSS_sm3(buffer.buffer, buffer.used, digest);
                //printf("20 %d \n",data->used);
#if 0
                print_array("_extend_transdigest: transdigest out: ", digest, 20);
#endif
                fseek(file, 0, SEEK_SET);
                if (1 != fwrite(digest, TCM_DIGEST_SIZE, 1, file)) {
                    ret = ERR_IO;
                }
            }
            fclose(file);
        } else {
            ret = ERR_BAD_FILE;
        }
        free(filename);
    } else {
        ret = ERR_MEM_ERR;
    }
    return ret;
}


/**
 *  Calculate the transdigest for the EstablishTransport function
 *  when it calculates the TCM_TRANSPORT_LOG_OUT function.
 *  Extend the TCM_INSTANCE's transdigest with the calculated value
 *  and write it back into the TCM_INSTANCE's file.
 */
static
uint32_t _calc_logout_esttrans(uint32_t returncode,
                               uint32_t privCode,
                               uint32_t ordinal,
                               uint32_t locality,
                               TCM_UINT64 *currentticks,
                               unsigned char *transSeq,
                               uint32_t handle  )
{
    uint32_t ret = 0;
    TCM_TRANSPORT_LOG_OUT ttlo;
    STACK_TCM_BUFFER(buffer);
    STACK_TCM_BUFFER(ser_ttlo);
    STACK_TCM_BUFFER(currentticks_ser);
    ret = TCM_WriteCurrentTicks_Short(&currentticks_ser, currentticks);
    if ((ret & ERR_MASK)) {
        return ret;
    }

    ret = TSS_buildbuff("L L L L L % %", &buffer,
                        ordinal,
                        returncode,
                        privCode,
                        locality,
                        currentticks_ser.used, currentticks_ser.buffer,
                        TCM_SEQ_SIZE, transSeq);

    ttlo.tag = TCM_TAG_TRANSPORT_LOG_OUT;
    TSS_sm3(buffer.buffer, buffer.used, ttlo.parameters);
    ttlo.locality = locality;
    ttlo.currentTicks.sec = currentticks->sec;
    ttlo.currentTicks.usec = currentticks->usec;
    ret = TCM_WriteTransportLogOut(&ser_ttlo, &ttlo);
    if ((ret & ERR_MASK)) {
        return ret;
    }
    ret = _extend_transdigest(handle, &ser_ttlo);

    return ret;
}


/*
 * Calculate the TCM_TRANSPORT_LOG_IN function that is calculated
 * as part of the TCM_ExecuteTransport ordinal. Extend the TCM_INSTANCE's
 * given transport session's transdigest with the resulting value.
 */
static
uint32_t _calc_login_exec(unsigned char *H1,
                          uint32_t handle)
{
    uint32_t ret = 0;
    TCM_TRANSPORT_LOG_IN ttli;
    STACK_TCM_BUFFER(ttli_ser);

    ttli.tag = TCM_TAG_TRANSPORT_LOG_IN;
    memcpy(ttli.parameters, H1, sizeof(ttli.parameters));


    //!!! Only supporting commands with NO handle since it's difficult
    //    to get by the public key
    memset(ttli.pubKeyHash, 0x0, sizeof(ttli.pubKeyHash));

    ret = TCM_WriteTransportLogIn(&ttli_ser, &ttli);
    if ((ret & ERR_MASK)) {
        return ret;
    }
    ret = _extend_transdigest(handle, &ttli_ser);
    return ret;
}

/*
 * Calculate the TCM_TRANSPORT_LOG_OUT function that is calculated
 * as part of the TCM_ExecuteTransport ordinal. Extend the TCM_INSTANCE's
 * given transport session's transdigest with the resulting value.
 */
static
uint32_t _calc_logout_exec(unsigned char *H2,
                           TCM_UINT64 *currentticks,
                           uint32_t locality,
                           uint32_t handle)
{
    uint32_t ret;
    TCM_TRANSPORT_LOG_OUT ttlo;
    STACK_TCM_BUFFER(ttlo_ser);

    ttlo.tag = TCM_TAG_TRANSPORT_LOG_OUT;
    memcpy(ttlo.parameters, H2, sizeof(ttlo.parameters));
    ttlo.currentTicks.sec = currentticks->sec;
    ttlo.currentTicks.usec = currentticks->usec;
    ttlo.locality = locality;

    ret = TCM_WriteTransportLogOut(&ttlo_ser, &ttlo);
    if ((ret & ERR_MASK)) {
        return ret;
    }

    ret = _extend_transdigest(handle, &ttlo_ser);
    return ret;
}



/*
 * Calculate the TCM_TRANSPORT_LOG_OUT function that is calculated
 * as part of the TCM_ReleaseTransportSigned ordinal. Extend the TCM_INSTANCE's
 * given transport session's transdigest with the resulting value.
 */
static
uint32_t _calc_logout_release(uint32_t ordinal,
                              uint32_t locality,
                              TCM_UINT64 *currentticks,
                              uint32_t handle)
{
    uint32_t ret = 0;
    TCM_TRANSPORT_LOG_OUT ttlo;
    STACK_TCM_BUFFER(ttlo_ser);
    STACK_TCM_BUFFER(buffer);

    ret = TSS_buildbuff("L ", &buffer,
                        ordinal);

    ttlo.tag = TCM_TAG_TRANSPORT_LOG_OUT;
    TSS_sm3(buffer.buffer, buffer.used, ttlo.parameters);
    ttlo.currentTicks.sec = currentticks->sec;
    ttlo.currentTicks.usec = currentticks->usec;
    ttlo.locality = locality;

    ret = TCM_WriteTransportLogOut(&ttlo_ser, &ttlo);
    if ((ret & ERR_MASK)) {
        return ret;
    }

    ret = _extend_transdigest(handle, &ttlo_ser);
    return ret;
}


/*
 * Permanently delete the TCM_INSTANCE's given transport session's
 * transdigest by removing its file.
 */
static
uint32_t _delete_transdigest(uint32_t handle)
{
    uint32_t ret = 0;
    char *filename = _get_transdigest_file(handle);
    if (filename) {
        unlink(filename);
        free(filename);
    }
    return ret;
}


/*
 * Get the filename of the TCM_INSTANCE's given transport session's
 * current ticks file.
 */
static
char *_get_currentticks_filename(uint32_t handle)
{
    char *filename = malloc(60);
    char *instance = getenv("TCM_INSTANCE");
    int inst;
    if (instance == NULL) {
        instance = "0";
    }
    inst = atoi(instance);
    sprintf(filename, "/tmp/.currentticks-%08x-%d", handle, inst);
    return filename;
}


/*
 * Save the current ticks into the TCM_INSTANCE's given transport
 * session's file
 */
static
uint32_t _save_currentticks(uint32_t handle, TCM_UINT64 *tct)
{
    uint32_t ret;
    STACK_TCM_BUFFER(tct_ser);
    FILE *file;
    char *filename = _get_currentticks_filename(handle);
    if (filename == NULL) {
        return ERR_BAD_FILE;
    }

    ret = TCM_WriteCurrentTicks_Short(&tct_ser, tct);
    if ((ret & ERR_MASK)) {
		free(filename);
        return ret;
    }

    file = fopen(filename, "w");
    if (file) {
        if (1 != fwrite(tct_ser.buffer, tct_ser.used, 1, file)) {
            ret = ERR_BAD_FILE;
        } else {
            ret = 0;
        }
        if (fclose(file) != 0) ret = ERR_BAD_FILE_CLOSE;
    } else {
        ret = ERR_BAD_FILE;
    }
    free(filename);
    return ret;
}


/*
 * Read the current ticks from the TCM_INSTANCE's given transport
 * session's file.
 */
static
uint32_t _read_currentticks(uint32_t handle, TCM_UINT64 *tct)
{
    uint32_t ret = 0;
    char *filename = _get_currentticks_filename(handle);
    FILE *file;
    if (filename == NULL) {
        return ERR_BAD_FILE;
    }

    file = fopen(filename, "r");
    if (file != NULL) {
        STACK_TCM_BUFFER(tct_ser);
        tct_ser.used = 8;
        if (1 != fread(tct_ser.buffer, tct_ser.used, 1, file)) {
            ret = ERR_BAD_FILE;
        } else {
            ret = TCM_ReadCurrentTicks_Short(&tct_ser, 0, tct);
            if ((ret & ERR_MASK)) {
                fclose(file);
				free(filename);
                return ret;
            }
            ret = 0;
        }
        fclose(file);
    } else {
        ret = ERR_BAD_FILE;
    }
    free(filename);
    return ret;
}

/*
 * Create the current ticks structure with 'second' and 'microsecond'
 * data taken from the given buffer at the given offset
 */
static
uint32_t _create_currentticks(uint32_t handle,
                              TCM_UINT64 *tct,
                              struct tcm_buffer *buffer, uint32_t offset)
{
    uint32_t ret;
    ret = _read_currentticks(handle, tct);
    if ((ret & ERR_MASK)) {
        return ret;
    }

    if (offset + sizeof(uint32_t) + sizeof(uint32_t) > buffer->used) {
        return ERR_BUFFER;
    }

    tct->sec  = LOAD32(buffer->buffer, offset);
    tct->usec = LOAD32(buffer->buffer, offset +
                       sizeof(uint32_t));

    ret = 0;
    return ret;
}


/*
 * Delete the TCM_INSTANCE's current ticks file associated with the
 * given transport session (handle).
 */
static
uint32_t _delete_currentticks(uint32_t handle)
{
    uint32_t ret = 0;
    char *filename = _get_currentticks_filename(handle);
    if (filename == NULL) {
        return ERR_BAD_FILE;
    }
    unlink(filename);
    free(filename);
    return ret;
}



/*
 * Add an additional transport function.
 * That function will be called first, unless another transport
 * function is pushed.
 */
void *TSS_PushTransportFunction(uint32_t (*function)(struct tcm_buffer *tb,
                                const char *msg),
                                uint32_t *idx)
{
    if(g_num_transports >= TCM_MAX_TRANSPORTS) {
        *idx = g_num_transports;
        return NULL;
    }

    g_transportFunction[g_num_transports] = function;
    *idx = g_num_transports;
    g_num_transports++;
    return NULL;
}

/*
 * Remove the last transport function from the stack
 * of transports.
 */
void *TSS_PopTransportFunction(uint32_t *idx)
{
    void *oldfunction = NULL;
    if (g_num_transports > 0) {
        g_num_transports--;
        oldfunction = g_transportFunction[g_num_transports];
        *idx = g_num_transports;
    } else {
        *idx = 0;
    }
    return oldfunction;
}



/*
 * Set the transport parameters for the transport function
 * that is described in the TCM specs (see below).
 */
uint32_t TSS_SetTransportParameters(session *transSession,
                                    uint32_t idx)
{
    if (idx >= TCM_MAX_TRANSPORTS) {
        return ERR_BAD_ARG;
    }
    g_transSession[idx] = transSession;
    return 0;
}

struct transport_data {
    uint8_t  handles: 4;
    uint8_t  rhandles: 4;
    uint8_t  flags;
};

enum {
    FLAG_NO_TRANSPORT = 1,
    FLAG_NO_ENCRYPTION = 2,
};



static const struct transport_data td[] = {
    [TCM_ORD_AuthorizeMigrationKey]    = { .handles = 0, },
    [TCM_ORD_CreateMigrationBlob]      = { .handles = 1, },
    [TCM_ORD_ConvertMigrationBlob] 	= { .handles = 2, },
    [TCM_ORD_AP]					  	= { .flags = FLAG_NO_ENCRYPTION },
    [TCM_ORD_APTerminate] 		= {
        .handles = 1,
        .flags = FLAG_NO_TRANSPORT
    },
    [TCM_ORD_Extend]				= { .handles = 0, },
    [TCM_ORD_PCRRead]					= { .handles = 0, },
    [TCM_ORD_Quote]			= { .handles = 1, },
    [TCM_ORD_PCR_Reset]					= { .handles = 0, },
    [TCM_ORD_NV_DefineSpace]			= { .handles = 0, },
    [TCM_ORD_NV_WriteValue]			= { .handles = 0, },
    [TCM_ORD_NV_WriteValueAuth]		= { .handles = 0, },
    [TCM_ORD_NV_ReadValue] 			= { .handles = 0, },
    [TCM_ORD_NV_ReadValueAuth] 		= { .handles = 0, },
    [TCM_ORD_EstablishTransport]		= {
        .handles = 1,
        .flags = FLAG_NO_TRANSPORT,
        .rhandles = 1,
    },
    [TCM_ORD_ExecuteTransport] 		= { .flags = FLAG_NO_TRANSPORT },
    [TCM_ORD_ReleaseTransport]   = {
        .handles = 1,
        .flags = FLAG_NO_TRANSPORT
    },

    [TCM_ORD_GetAuditDigest]			= {
        .handles = 0,
        .flags = FLAG_NO_TRANSPORT
    },
    [TCM_ORD_GetAuditDigestSigned] 	= {
        .handles = 1,
        .flags = FLAG_NO_TRANSPORT
    },
    [TCM_ORD_SetOrdinalAuditStatus]	= { .handles = 0, },
    [TCM_ORD_CreateCounter]			= { .handles = 0, },
    [TCM_ORD_IncrementCounter] 		= { .handles = 0, },
    [TCM_ORD_ReadCounter]				= { .handles = 0, },
    [TCM_ORD_ReleaseCounter]			= { .handles = 0, },
    [TCM_ORD_ReleaseCounterOwner]		= { .handles = 0, },
    [TCM_ORD_GetTicks] 				= { .handles = 0, },
    [TCM_ORD_TickStampBlob]			= { .handles = 1, },


    [TCM_ORD_Init]                     = { .flags = FLAG_NO_TRANSPORT },
    [TCM_ORD_Startup]                  = { .handles = 0, },
    [TCM_ORD_SaveState]                = { .handles = 0, },
    [TCM_ORD_SelfTestFull]             = { .handles = 0, },
    [TCM_ORD_GetTestResult]            = { .handles = 0, },
    [TCM_ORD_SetOwnerInstall]          = { .handles = 0, },
    [TCM_ORD_PhysicalEnable]   		   = { .handles = 0, },
    [TCM_ORD_OwnerSetDisable]			   = { .handles = 0, },
    [TCM_ORD_PhysicalDisable]       	= { .handles = 0, },
    [TCM_ORD_ResetLockValue]		= { .handles = 0, },
    [TCM_ORD_TakeOwnership]            = { .handles = 0, },
    [TCM_ORD_OwnerClear]            = { .handles = 0, },
    [TCM_ORD_ForceClear]       = { .handles = 0, },
    [TCM_ORD_DisableOwnerClear]       = { .handles = 0, },
    [TCM_ORD_DisableForceClear] = { .handles = 0, },
    [TCM_ORD_ReadPubek]				= { .handles = 0, },
    [TCM_ORD_GetCapability]            = { .handles = 0, },
    [TCM_ORD_SetCapability]            = { .handles = 0, },
    [TCM_ORD_ChangeAuth]			= { .handles = 1, },
    [TCM_ORD_ChangeAuthOwner] 	= { .handles = 0, },
    [TCM_ORD_CertifyKey]				= { .handles = 2, },
    [TCM_ORD_SM3Start]					= { .handles = 0, },
    [TCM_ORD_SM3Update]				= { .handles = 0, },
    [TCM_ORD_SM3Complete] 				= { .handles = 0, },
    [TCM_ORD_SM3CompleteExtend]		= { .handles = 0, },
    [TCM_ORD_Sign] 					= { .handles = 1, },
    [TCM_ORD_GetRandom]				= { .handles = 0, },
    [TCM_ORD_SaveContext]				= { .handles = 1, },
    [TCM_ORD_LoadContext]				= { .handles = 1, .rhandles = 1 },
    [TCM_ORD_LoadKey] 					= { .handles = 1, .rhandles = 1 },
    [TCM_ORD_CreateWrapKey]			= { .handles = 1, },
    [TCM_ORD_WrapKey]					= { .handles = 1, },
    [TCM_ORD_GetPubKey]			= { .handles = 1, },
    [TCM_ORD_Seal] 					= { .handles = 1, },
    [TCM_ORD_Unseal]					= { .handles = 1, },
    [TCM_ORD_FlushSpecific]			    = { .handles = 1, },
    [TCM_ORD_CreateEndorsementKeyPair] = { .handles = 0, },
    [TCM_ORD_RevokeTrust]				= { .handles = 0, },
    [TCM_ORD_MakeIdentity] 			= { .handles = 0, },
    [TCM_ORD_ActivateIdentity] 		= { .handles = 1, },
};


int allowsTransport(uint32_t ord)
{
    if (ord <= TCM_ORD_ReleaseTransport)
        return (0 == (td[ord].flags & FLAG_NO_TRANSPORT));
#if 0
    if (ord >= TCM_ORD_CreateInstance &&
            ord <= TCM_ORD_GetMigrationDigest)
        return (0 == (td2[ord].flags & FLAG_NO_TRANSPORT));
#endif
    return 0;
}

uint32_t getNumHandles(uint32_t ord)
{
    if (ord <= TCM_ORD_TickStampBlob)
        return td[ord].handles;
#if 0
    if (ord >= TCM_ORD_CreateInstance &&
            ord <= TCM_ORD_GetMigrationDigest)
        return td2[ord].handles;
#endif
    return 0;
}

uint32_t getNumRespHandles(uint32_t ord)
{
    //   printf("%s:\n",__func__);
    if (ord <= TCM_ORD_TickStampBlob)
        return td[ord].rhandles;
#if 0
    if (ord >= TCM_ORD_CreateInstance &&
            ord <= TCM_ORD_GetMigrationDigest)
        return td2[ord].rhandles;
#endif
    return 0;
}


static uint32_t TCM_EstablishTransport_Internal(uint32_t keyhandle,
        unsigned char *usageAuth,
        TCM_TRANSPORT_PUBLIC *ttp,
        unsigned char *transAuth,
        struct tcm_buffer *secret,
        TCM_CURRENT_TICKS *currentticks,
        session *transSess
                                               )
{
    STACK_TCM_BUFFER(tcmdata)
    unsigned char authdata[TCM_NONCE_SIZE];
    unsigned char transseq[TCM_SEQ_SIZE];
    unsigned char c = 0;
    uint32_t ordinal_no = htonl(TCM_ORD_EstablishTransport);
    uint32_t ret;
    uint32_t keyhandle_no = htonl(keyhandle);
    uint32_t encSecretSize_no;
    STACK_TCM_BUFFER(transPub)
    session sess;
    uint32_t transhandle;
    TCM_DIGEST transdigest;
    uint32_t locality;
    TCM_UINT64 currentTicks;
    uint32_t locty = 0;
    char *locality2 = getenv("TCM_USE_LOCALITY");

    if (NULL != locality2) {
        locty = (unsigned int)atoi(locality2);
        if (locty > 4)
            locty = 0;
    }
    if (NULL == usageAuth ||
            NULL == ttp ||
            NULL == secret ) {
        return ERR_NULL_ARG;
    }

    encSecretSize_no  = htonl(secret->used);

    if (keyhandle != TCM_KH_TRANSPORT) {



        /* Open OIAP Session */
        ret = TSS_SessionOpen(SESSION_OSAP | SESSION_OIAP,
                              &sess,
                              usageAuth, TCM_ET_KEYHANDLE, keyhandle);
        if (ret != 0) {
            return ret;
        }

        /* calculate encrypted authorization value */

        ret = TCM_WriteTransportPublic(&transPub, ttp);
        if ((ret & ERR_MASK)) {
            TSS_SessionClose(&sess);
            return ret;
        }

        /* move Network byte order data to variable for hmac calculation */
        ret = TSS_authhmac1(authdata, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE, TSS_Session_GetSeq(&sess), c,
                            TCM_U32_SIZE   , &ordinal_no,
                            transPub.used  , transPub.buffer,
                            TCM_U32_SIZE   , &encSecretSize_no,
                            secret->used   , secret->buffer,
                            0, 0);

        if (0 != ret) {
            TSS_SessionClose(&sess);
            return ret;
        }
        /* build the request buffer */
        ret = TSS_buildbuff("00 c2 T l l % @ L %", &tcmdata,
                            ordinal_no,
                            keyhandle_no,
                            transPub.used, transPub.buffer,
                            secret->used, secret->buffer,
                            TSS_Session_GetHandle(&sess),
                            TCM_HASH_SIZE, authdata);
        if ((ret & ERR_MASK) != 0) {
            TSS_SessionClose(&sess);
            return ret;
        }

        if ((ttp->transAttributes & TCM_TRANSPORT_LOG)) {
            _calc_transdigest(TCM_ORD_EstablishTransport,

                              ttp,
                              secret,
                              &transdigest);
        }

        /* transmit the request buffer to the TCM device and read the reply */
        ret = TCM_Transmit(&tcmdata, "TCM_EstablishTransport - AUTH1");

        if (ret != 0) {
            TSS_SessionClose(&sess);
            return ret;
        }
        /* check the HMAC in the response */
        ret = TSS_checkhmac1(&tcmdata, ordinal_no,
                             TSS_Session_GetSeq(&sess),
                             TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                             TCM_U32_SIZE + 8 + TCM_SEQ_SIZE, TCM_DATA_OFFSET + TCM_U32_SIZE,
                             0, 0);

        if ((ttp->transAttributes & TCM_TRANSPORT_EXCLUSIVE) == 0)
            TSS_SessionClose(&sess);

        if (0 != ret) {
			TSS_SessionClose(&sess);
            return ret;
        }
    } else {
        /* calculate encrypted authorization value */

        ret = TCM_WriteTransportPublic(&transPub, ttp);
        if ((ret & ERR_MASK)) {
            return ret;
        }

        /* build the request buffer */
        ret = TSS_buildbuff("00 c1 T l l % @", &tcmdata,
                            ordinal_no,
                            keyhandle_no,
                            transPub.used, transPub.buffer,
                            secret->used, secret->buffer);
        if ((ret & ERR_MASK) != 0) {
            return ret;
        }

        if ((ttp->transAttributes & TCM_TRANSPORT_LOG)) {
            _calc_transdigest(TCM_ORD_EstablishTransport,
                              ttp,
                              secret,
                              &transdigest);
        }

        /* transmit the request buffer to the TCM device and read the reply */
        ret = TCM_Transmit(&tcmdata, "TCM_EstablishTransport - AUTH0");

        if (ret != 0) {
            return ret;
        }

    }

    TCM_ReadCurrentTicks_Short(&tcmdata,
                               TCM_DATA_OFFSET + TCM_U32_SIZE + TCM_U32_SIZE,
                               &currentTicks);

    if (NULL != currentticks) {
        currentticks->currentTicks.sec = currentTicks.sec;
        currentticks->currentTicks.usec = currentTicks.usec;
    }

    ret = tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET, &transhandle);
    if ((ret & ERR_MASK)) {
        return ret;
    }
    ret = tcm_buffer_load32(&tcmdata,
                            TCM_DATA_OFFSET + TCM_U32_SIZE,
                            &locality);
    if ((ret & ERR_MASK)) {
        return ret;
    }
    memcpy(transseq,
           &tcmdata.buffer[TCM_DATA_OFFSET + TCM_U32_SIZE + TCM_U32_SIZE + 8],
           TCM_SEQ_SIZE);

    TSS_Session_CreateTransport(transSess,
                                transAuth, transhandle, transseq);

    if ((ttp->transAttributes & TCM_TRANSPORT_LOG)) {
        _store_transdigest(transhandle, transdigest);
        _calc_logout_esttrans(0,
                              TCM_PRI_SUCCESS,
                              TCM_ORD_EstablishTransport,
                              locality,
                              &currentTicks,
                              transseq,
                              transhandle
                             );
    }
    _save_currentticks(transhandle, &currentTicks);
    return 0;
}



uint32_t TCM_EstablishTransport_UseRoom(uint32_t keyhandle,
                                        unsigned char *usageAuth,
                                        TCM_TRANSPORT_PUBLIC *ttp,
                                        unsigned char *transAuth,
                                        struct tcm_buffer *secret,
                                        TCM_CURRENT_TICKS *currentticks,
                                        session *transSess )
{
    uint32_t ret = 0;
    uint32_t replaced_keyhandle = 0;

    // some commands may not call needKeysRoom themselves, so
    // we may replace a key here, which is fine. We just cannot
    // put the original key back in since then the transport
    // will not work.
    ret = needKeysRoom_Stacked(keyhandle, &replaced_keyhandle );
    if (ret != 0) {
        return ret;
    }

    return TCM_EstablishTransport_Internal(keyhandle,
                                           usageAuth,
                                           ttp,
                                           transAuth,
                                           secret,
                                           currentticks,
                                           transSess );
}




void _TCM_getTransportAlgIdEncScheme(TCM_ALGORITHM_ID *algId,
                                     TCM_ENC_SCHEME  *encScheme, uint32_t *blockSize)
{
    char *transpenc = getenv("TCM_TRANSPORT_ENC");
    //*algId = 0; 	//lyf
    //*encScheme = TCM_EM_NONE;//lyf
    *algId = TCM_ALG_KDF1;
    *encScheme = TCM_ES_NONE;
    *blockSize = 0;
    if (NULL == transpenc) {
    } else if (!strcasecmp(transpenc, "KDF1")) {
        *algId = TCM_ALG_KDF1;
        *encScheme = TCM_ES_NONE;
        *blockSize = 0;
    } else if (!strcasecmp(transpenc, "OFB")) {
        *algId = TCM_ALG_SM4;
        *encScheme = TCM_ES_SM4_OFB;
        *blockSize = 128 / 8;
    } else if (!strcasecmp(transpenc, "CTR")) {
        *algId = TCM_ALG_SM4;
        *encScheme = TCM_ES_SM4_CTR;
        *blockSize = 128 / 8;
    }
}


static uint32_t encWrappedCommand(struct tcm_buffer *tb,
                                  struct tcm_buffer *enc,
                                  session *sess,
                                  uint32_t *wrapped_ord,
                                  unsigned char *H1)
{
    uint32_t ret = 0;
    uint8_t handles;
    uint32_t enc_len;
    uint32_t enc_start;
    uint16_t tag;
    uint32_t i;
    STACK_TCM_BUFFER(seed)
    uint32_t tail = 0;
    STACK_TCM_BUFFER(buffer)
    unsigned char *x1 = NULL;

    //printf("1. encWrappedCommand!\n");
    ret = tcm_buffer_load32(tb, 6, wrapped_ord);

    if ((ret & ERR_MASK)) {
        return ret;
    }
    ret = tcm_buffer_load16(tb, 0, &tag);
    if ((ret & ERR_MASK)) {
        return ret;
    }


    // !!! need to check the range of wrapped_ord against array
    handles = td[*wrapped_ord].handles;
    enc_start = 2 + 4 + 4 + handles * 4;

    enc_len = tb->used;
    enc_len -= enc_start;

    switch (tag) {
    case TCM_TAG_RQU_COMMAND:
        break;

    case TCM_TAG_RQU_PROTECT_COMMAND:
        tail = sizeof(TCM_AUTHHANDLE)  + TCM_AUTHDATA_SIZE;
        break;

    }
    enc_len -= tail;

    if ((int)enc_len < 0) {
        return ERR_CRYPT_ERR;
    }


    if (enc_len > 0 &&
            0 == (td[*wrapped_ord].flags & FLAG_NO_ENCRYPTION)) {
        TCM_ALGORITHM_ID algId;
        TCM_ENC_SCHEME encScheme;
        uint32_t blockSize;
        _TCM_getTransportAlgIdEncScheme(&algId, &encScheme, &blockSize);

        if (algId == TCM_ALG_KDF1) {
            x1 = malloc(enc_len);
            if (NULL == x1) {
                return ERR_MEM_ERR;
            }
            /*
             * Encrypt MGF1
             */
            ret = TSS_buildbuff("% % %", &seed,
                                TCM_SEQ_SIZE, TSS_Session_GetSeq(sess),
                                sizeof("in") - 1, "in",
                                TCM_HASH_SIZE, TSS_Session_GetAuth(sess));

            if ((ret & ERR_MASK) != 0) {
                goto exit;
            }

            TSS_KDF1(x1,
                     enc_len,
                     seed.buffer,
                     seed.used);


            SET_TCM_BUFFER(enc, tb->buffer, tb->used);
            for (i = 0; i < enc_len; i++) {
                enc->buffer[enc_start + i] = x1[i] ^ tb->buffer[enc_start + i];
            }
        } else if (algId == TCM_ALG_SM4) {
            unsigned char iv[blockSize];
            ret = TSS_buildbuff("% %", &seed,
                                TCM_SEQ_SIZE, TSS_Session_GetSeq(sess),
                                sizeof("in") - 1, "in");
            if ((ret & ERR_MASK) != 0) {
                goto exit;
            }

            TSS_KDF1(iv,
                     blockSize,
                     seed.buffer,
                     seed.used);

            SET_TCM_BUFFER(enc, tb->buffer, tb->used);
            TCM_SymmetricKeyData_StreamCrypt(&enc->buffer[enc_start],
                                             &tb ->buffer[enc_start],
                                             enc_len,
                                             algId,
                                             encScheme,
                                             TSS_Session_GetAuth(sess),
                                             TCM_AUTHDATA_SIZE,
                                             iv,
                                             blockSize);

        } else {
            SET_TCM_BUFFER(enc, tb->buffer, tb->used);
        } /* if (algId == ... ) ... else ... */
        ret = TSS_buildbuff("L %", &buffer,
                            *wrapped_ord,
                            enc_len, &tb->buffer[enc_start]);
    } else {
        SET_TCM_BUFFER(enc, tb->buffer, tb->used);
        ret = TSS_buildbuff("L", &buffer,
                            *wrapped_ord);

    }

    if ((ret & ERR_MASK)) {
        goto exit;
    }

    TSS_sm3(buffer.buffer, buffer.used, H1);



    ret = 0;
exit:
    if (x1)
        free(x1);

    return ret;
}

/*
offset: where the wrappedCmdSize starts
wrapped_ord: wrapped ordinal
                     : wrapped
*/
static uint32_t decWrappedCommand(struct tcm_buffer *tb,
                                  uint32_t offset,
                                  struct tcm_buffer *res,
                                  session *sess,
                                  uint32_t wrapped_ord,
                                  unsigned char *H2)
{
    uint32_t ret = 0;
    uint32_t plain;
    uint32_t enc_len;
    unsigned char *x1 = NULL;
    uint32_t i;
    uint16_t tag;
    uint32_t enc_start;
    STACK_TCM_BUFFER(seed)
    uint8_t rhandles;
    STACK_TCM_BUFFER(buffer)
    uint32_t ret_inner = 0;    //return code of wrapped ordinal
    uint32_t privCode_inner = 0;
    uint32_t inner_len;        //wrappedcmdsize

    ret = tcm_buffer_load32(tb, offset, &inner_len);
    enc_len = inner_len;
    if ((ret & ERR_MASK)) {
        return ret;
    }
    offset += TCM_U32_SIZE;

    ret = tcm_buffer_load16(tb, offset, &tag);
    if ((ret & ERR_MASK)) {
        return ret;
    }

    ret = tcm_buffer_load32(tb, offset + TCM_U16_SIZE + TCM_U32_SIZE, &ret_inner);
    if ((ret & ERR_MASK)) {
        return ret;
    }


    if (ret_inner) {
        SET_TCM_BUFFER(res, &tb->buffer[offset], inner_len);
        ret = TSS_buildbuff("L L", &buffer,
                            ret_inner,
                            wrapped_ord);
        TSS_sm3(buffer.buffer, buffer.used, H2);
        tb->used += TCM_DIGEST_SIZE;

        return ret_inner;
    }

    switch (tag) {
    case TCM_TAG_RSP_COMMAND:
        break;

    case TCM_TAG_RSP_PROTECT_COMMAND:
        enc_len -= (TCM_AUTHDATA_SIZE);
        break;
    case TCM_TAG_RSP_PROTECT_COMMAND_forTCM:
        enc_len -= (2 * TCM_AUTHDATA_SIZE);
        break;

    default:
        ret = ERR_BUFFER;
        goto exit;
    }

    if ((int)enc_len < 0) {
        return ERR_CRYPT_ERR;
    }


    if (enc_len > 0 &&
            0 == (td[wrapped_ord].flags & FLAG_NO_ENCRYPTION)) {
        TCM_ALGORITHM_ID algId;
        TCM_ENC_SCHEME encScheme;
        uint32_t blockSize;
        _TCM_getTransportAlgIdEncScheme(&algId, &encScheme, &blockSize);

        rhandles = td[wrapped_ord].rhandles;

        plain = 2 + 4 + 4  + 4 * rhandles;
        enc_start = offset + plain;
        enc_len -= plain;

        if (algId == TCM_ALG_KDF1 && (int)enc_len > 0) {
            x1 = malloc(enc_len);
            if (NULL == x1) {
                return ERR_MEM_ERR;
            }
            /*
             * Encrypt MGF1
             */
            ret = TSS_buildbuff("% % %", &seed,
                                TCM_SEQ_SIZE, TSS_Session_GetSeq(sess),
                                sizeof("out") - 1, "out",
                                TCM_HASH_SIZE, TSS_Session_GetAuth(sess));
            if ((ret & ERR_MASK) != 0) {
                goto exit;
            }

            TSS_KDF1(x1,
                     enc_len,
                     seed.buffer,
                     seed.used);

            SET_TCM_BUFFER(res, &tb->buffer[offset], inner_len);
            for (i = 0 ; i < enc_len; i++) {
                res->buffer[plain + i] = x1[i] ^ tb->buffer[enc_start + i];
            }
        } else if (algId == TCM_ALG_SM4 && (int)enc_len > 0) {
            unsigned char iv[blockSize];
            ret = TSS_buildbuff("% %", &seed,
                                TCM_SEQ_SIZE, TSS_Session_GetSeq(sess),
                                sizeof("out") - 1, "out");
            if ((ret & ERR_MASK) != 0) {
                goto exit;
            }

            TSS_KDF1(iv,
                     blockSize,
                     seed.buffer,
                     seed.used);

            SET_TCM_BUFFER(res, &tb->buffer[offset], inner_len);

            TCM_SymmetricKeyData_StreamCrypt(&res->buffer[plain],
                                             &tb ->buffer[enc_start],
                                             enc_len,
                                             algId,
                                             encScheme,
                                             TSS_Session_GetAuth(sess),
                                             TCM_AUTHDATA_SIZE,
                                             iv,
                                             blockSize);

        } else {
            SET_TCM_BUFFER(res, &tb->buffer[offset], inner_len);
        }

        ret = TSS_buildbuff("L L %", &buffer,
                            ret_inner,
                            wrapped_ord,
                            enc_len, &res->buffer[plain]);
    } else {
        SET_TCM_BUFFER(res, &tb->buffer[offset], inner_len);
        ret = TSS_buildbuff("L L", &buffer,
                            ret_inner,
                            wrapped_ord);

    }

    if ((ret & ERR_MASK)) {
        goto exit;
    }
    TSS_sm3(buffer.buffer, buffer.used, H2);
    tb->used += TCM_DIGEST_SIZE;

    ret = 0;
exit:
    if (x1)
        free(x1);

    return ret;
}

static
uint32_t _TCM_ExecuteTransport(struct tcm_buffer *tb,
                               session *transSess,
                               unsigned char *currentTicks,
                               struct tcm_buffer *res,
                               const char *msg)
{
    /* allocate buffer big enough to hold the given data plus
       some additional 50 bytes */
    struct tcm_buffer *tcmdata = NULL;
    unsigned char authdata[TCM_NONCE_SIZE];
    unsigned char H1[TCM_NONCE_SIZE];
    unsigned char *H2;
    unsigned char c;
    uint32_t ordinal_no = htonl(TCM_ORD_ExecuteTransport);

    uint32_t ret, ret2, rc;
    uint32_t wrappedCommandRetSize_no = htonl(tb->used);
    uint32_t len;
    STACK_TCM_BUFFER(encbuffer);
    uint32_t wrappedOrd;
    char message[1024];
    uint32_t in_ordinal;
    uint32_t in_returncode;
    TCM_CURRENT_TICKS currentticks;
    uint32_t locality;

    if (NULL == tb  ||
            NULL == transSess ||
            NULL == res ) {
        ret = ERR_NULL_ARG;
        goto exit;
    }

    ret = tcm_buffer_load32(tb, 6, &in_ordinal);
    if ((ret & ERR_MASK)) {
        goto exit;;
    }


    /*alloc 50 bytes more*/
    tcmdata = TSS_AllocTCMBuffer(2 + 4 + 4 + 4 + tb->used + 50 + 4 + 32 );
    if(!tcmdata) {
        ret = ERR_MEM_ERR;
        goto exit;
    }

    sprintf(message, "TCM_ExecuteTransport(%s) - AUTH1", msg);

    ret = encWrappedCommand(tb,
                            &encbuffer,
                            transSess,
                            &wrappedOrd,
                            H1);
    if ((ret & ERR_MASK)) {
        goto exit;
    }

    //	_TCM_AuditInputstream(tb, 1);
    _calc_login_exec(H1, TSS_Session_GetHandle(transSess));

    /* move Network byte order data to variable for hmac calculation */
    c = 1;


    ret = TSS_authhmac1(authdata, TSS_Session_GetAuth(transSess), TCM_HASH_SIZE, TSS_Session_GetSeq(transSess), c,
                        TCM_U32_SIZE      , &ordinal_no,
                        TCM_U32_SIZE      , &wrappedCommandRetSize_no,
                        TCM_HASH_SIZE     , H1,
                        0, 0);

    if (0 != ret) {
        goto exit;
    }

    /* build the request buffer */
    ret = TSS_buildbuff("00 c2 T l @ L %", tcmdata,
                        ordinal_no,
                        encbuffer.used, encbuffer.buffer,
                        TSS_Session_GetHandle(transSess),
                        TCM_HASH_SIZE, authdata);
    if ((ret & ERR_MASK)) {
        goto exit;
    }
    /* transmit the request buffer to the TCM device and read the reply */
    ret = TCM_Transmit(tcmdata, message);
    if (ret != 0) {
        goto exit;
    }


    ret = tcm_buffer_load32(tcmdata, TCM_DATA_OFFSET, &locality);
    if ((ret & ERR_MASK)) {
        goto exit;
    }

    /* check the HMAC in the response */
    ret = tcm_buffer_load32(tcmdata, TCM_DATA_OFFSET + 8 + 4, &len);
    if ((ret & ERR_MASK)) {
        goto exit;
    }

    /*
     * need to update seq from the TCM
     */

    TSS_Session_UpdateSeq(transSess);

    ret = _create_currentticks(TSS_Session_GetHandle(transSess),
                               &currentticks.currentTicks, tcmdata, TCM_DATA_OFFSET + 4);
    if ((ret & ERR_MASK)) {
        goto exit;
    }
    /*
     * I am using an evil trick here for the H2 - I place it behind
     * the data of the ExecuteTransport command.
     * That way I don't have to write another checkhmac function.
     */
    H2 = &tcmdata->buffer[tcmdata->used];
    ret2 = decWrappedCommand(tcmdata,
                             TCM_DATA_OFFSET + 8 + 4, //after ticks and locality
                             res,
                             transSess,
                             wrappedOrd,
                             &tcmdata->buffer[tcmdata->used]);

    /*
    * Audit the inside ordinal
    */
    ret = tcm_buffer_load32(res, 6, &in_returncode);
    if (ret == 0 && (in_returncode == 0)) {
        _TCM_AuditInputstream(tb, 1);
        _TCM_AuditOutputstream(res, in_ordinal,  1);
    }


    ret = TSS_checkhmac1New(tcmdata, ordinal_no,      TSS_Session_GetSeq(transSess),
                            TSS_Session_GetAuth(transSess), TCM_HASH_SIZE,
                            8 + 4 + TCM_U32_SIZE  , TCM_DATA_OFFSET,  //ticks & locality & wrappedSize
                            TCM_HASH_SIZE         , TCM_DATA_OFFSET + 8 + 4 + TCM_U32_SIZE + len + 32 , // place of H2
                            0, 0);

    if (0 != ret || ret2 != 0) {
        goto exit;
    }

    if (NULL != currentTicks) {
#if 0
        memcpy(currentTicks,
               &tcmdata->buffer[TCM_DATA_OFFSET],
               TCM_CURRENT_TICKS_SIZE);
#endif
    }
    _calc_logout_exec(H2,
                      &currentticks.currentTicks,
                      locality,
                      TSS_Session_GetHandle(transSess));

    /*
     * I must get the return code of the inner command now.
     * The decrypted result is in 'res'.
     */
    rc = tcm_buffer_load32(res, TCM_RETURN_OFFSET, &ret);
    if ((rc & ERR_MASK)) {
        ret = rc;
    }

exit:
    FREE_TCM_BUFFER(tcmdata);
    return ret;
}

uint32_t TCM_ExecuteTransport(struct tcm_buffer *tb, const char *msg)
{
    uint32_t ret;
    STACK_TCM_BUFFER (result)
    ret = _TCM_ExecuteTransport(tb,
                                g_transSession[g_num_transports],
                                NULL,
                                &result,
                                msg);
    SET_TCM_BUFFER(tb, result.buffer, result.used);
    return ret;
}


uint32_t TCM_ReleaseTransport(session *transSess )
{
    uint32_t ret = 0;
    uint32_t ordinal_no = htonl(TCM_ORD_ReleaseTransport);
    unsigned char c = 0;
    uint32_t handle_no;
    uint32_t len;

    STACK_TCM_BUFFER(tcmdata)
    unsigned char authdata[TCM_NONCE_SIZE];
    uint32_t locality;
    TCM_CURRENT_TICKS tct;
    uint32_t orig_keyhandle = 0;

    if (NULL == transSess) {
        return ERR_NULL_ARG;
    }

    handle_no = ntohl(transSess->type.tran.handle);


    ret = TSS_authhmac1(authdata, TSS_Session_GetAuth(transSess), TCM_HASH_SIZE,
                        TSS_Session_GetSeq(transSess), c,
                        TCM_U32_SIZE , &ordinal_no,
                        0, 0);


    ret = TSS_buildbuff("00 c2 T l l L %", &tcmdata,
                        ordinal_no,
                        handle_no  ,
                        TSS_Session_GetHandle(transSess),
                        TCM_HASH_SIZE, authdata);

    if ((ret & ERR_MASK) != 0) {
        _delete_transdigest(TSS_Session_GetHandle(transSess));
        _delete_currentticks(TSS_Session_GetHandle(transSess));
        return ret;
    }

    ret = TCM_Transmit(&tcmdata, "ReleaseTransport - AUTH1");

    if (0 != ret) {
        _delete_transdigest(TSS_Session_GetHandle(transSess));
        _delete_currentticks(TSS_Session_GetHandle(transSess));
        return ret;
    }


    ret = TSS_checkhmac1(&tcmdata, ordinal_no,
                         TSS_Session_GetSeq(transSess),
                         TSS_Session_GetAuth(transSess), TCM_HASH_SIZE,
                         sizeof(TCM_MODIFIER_INDICATOR) + TCM_CURRENT_TICKS_SIZE  , TCM_DATA_OFFSET,
                         0, 0);

    ret = tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET, &locality);
    if ((ret & ERR_MASK)) {
        return ret;
    }

    TCM_ReadCurrentTicks(&tcmdata,
                         TCM_DATA_OFFSET + TCM_U32_SIZE,
                         &tct);



    _calc_logout_release(TCM_ORD_ReleaseTransport,
                         locality,
                         &tct.currentTicks,
                         TSS_Session_GetHandle(transSess));



    _delete_transdigest(TSS_Session_GetHandle(transSess));
    _delete_currentticks(TSS_Session_GetHandle(transSess));

    return ret;
}
