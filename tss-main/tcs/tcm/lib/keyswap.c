/********************************************************************************/
/*										*/
/*			     	TCM Key Swapping Routines			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: keyswap.c 4365 2011-02-04 01:20:00Z stefanb $		*/
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
#include <unistd.h>
#include <assert.h>

#include "tcm.h"
#include "tcmfunc.h"
#include "tcm_types.h"
#include "tcm_constants.h"
#include "tcmutil.h"
#include "tcm_error.h"
#include "tcm_lowlevel.h"

extern uint32_t g_num_transports;

static int IsKeyInTCM(struct tcm_buffer *capabilities, uint32_t shandle);


static char *createKeyFilename(uint32_t keyhandle)
{
    char buffer[200];
    char *inst = getenv("TCM_INSTANCE");
    sprintf(buffer, "/tmp/.key-%08X-%s", keyhandle, inst);
    return strdup(buffer);
}

static int isKeySwapable(uint32_t shandle)
{
    if (shandle == 0x00000000 ||
            (shandle >= TCM_KH_SMK &&
             shandle <= TCM_KH_EK) ||
            shandle == 0xffffffff) {
        return 0;
    }
    return 1;
}

static uint32_t swapOutKey(uint32_t handle      )
{
    unsigned char labelhash[TCM_HASH_SIZE];
    char *filename = createKeyFilename(handle);
    STACK_TCM_BUFFER(context);
    uint32_t ret = 0;

    if (NULL == filename) {
        ret = ERR_MEM_ERR;
    }

#if 0
    printf("Swapping OUT key with handle %08x\n", handle);
#endif

    TSS_sm3("KEY", 3, labelhash);


    if (ret == 0) {
        ret = TCM_SaveContext_UseRoom(handle,
                                      TCM_RT_KEY,
                                      (char *)labelhash,
                                      &context);

    }

    if (ret == 0) {
        FILE *f = fopen(filename, "w+");
        if (f) {
            fwrite(context.buffer, context.used, 1, f);
            if (fclose(f) != 0)
                ret = ERR_BAD_FILE_CLOSE;
        } else {

            ret = ERR_BAD_FILE;
        }
    }

    if (ret == 0) {
        /*ret =*/ TCM_EvictKey_UseRoom(handle          );
#if 0
        printf("Evicted key with handle 0x%08x\n", handle);
    } else {
        printf("DID NOT Evicted key with handle 0x%08x\n", handle);
#endif
    }

#if 0
    if (ret == 0) {
        printf("Swapped out key with handle %08x.\n", handle);
    } else {
        printf("Could NOT swap out key with handle %08x.\n", handle);
    }
#endif
    free(filename);

    return ret;
}


static uint32_t swapInKey(uint32_t handle)
{
    char *filename = createKeyFilename(handle);
    STACK_TCM_BUFFER(context);
    unsigned char *mycontext = NULL;
    uint32_t contextSize;
    uint32_t newhandle;
    uint32_t ret;

    if (NULL == filename) {
        ret = ERR_MEM_ERR;
    }

    ret = TCM_ReadFile(filename, &mycontext, &contextSize);
    if ((ret & ERR_MASK)) {
#if 0
        printf("level: %d\n", g_num_transports);
#endif
#if 0
        fprintf(stderr, "Could not read from keyfile %s.\n", filename);
#endif
        return ret;
    }
    SET_TCM_BUFFER(&context, mycontext, contextSize);
    free(mycontext);

    ret = TCM_LoadContext(handle,
                          1,
                          &context,
                          &newhandle);

    if (ret != 0) {
        printf("Got error '%s' while swapping in key 0x%08x.\n",
               TCM_GetErrMsg(ret),
               handle);
    }
    if (handle != newhandle) {
        printf("keyswap: "
               "new handle 0x%08x not the same as old one 0x%08x.\n",
               newhandle, handle);
    }
    if (ret == 0) {
        unlink(filename);
    }
    free(filename);
#if 0
    if (ret == 0) {
        fprintf(stderr, "SWAP IN Swapped in key with handle %08x.\n", handle);
    } else {
        fprintf(stderr, "Could NOT swap in key with handle %08x.\n", handle);
    }
#endif

    return ret;
}


static uint32_t swapOutKeys(uint32_t neededslots,
                            uint32_t key1, uint32_t key2, uint32_t key3,
                            struct tcm_buffer *capabilities,
                            uint32_t *orig_key1)
{
    uint32_t ret = 0;
    uint32_t ctr;
    uint32_t handle;

#if 0
    fprintf(stderr, "%s: neededslots: %d\n", __FUNCTION__, neededslots);
#endif
    if (orig_key1)
        *orig_key1 = 0;

#if 0
    fprintf(stderr, "must keep keys %08x %08x %08x   room=%d\n",
            key1, key2, key3, neededslots);
#endif
    ctr = 2;

    while (ctr < capabilities->used) {
        tcm_buffer_load32(capabilities,
                          ctr,
                          &handle);

        if (handle != key1 &&
                handle != key2 &&
                handle != key3) {
            ret = swapOutKey(handle          );
            if (ret == 0 && orig_key1 && *orig_key1 == 0) {
                *orig_key1 = handle;
            }
            if (ret == 0) {
                neededslots--;
                if (neededslots == 0)
                    break;
            }
#if 0
            if (ret == 0)
                fprintf(stderr, "SWAPPED OUT KEY = 0x%08x\n", handle);
            if (ret == TCM_OWNER_CONTROL)
                fprintf(stderr, "KEY UNDER OWNER CONTROL = 0x%08x\n", handle);
#endif
        }


        if (ret != 0 && ret != TCM_OWNER_CONTROL) {
            break;
        }

        ctr += sizeof(handle);
    }

    if (ret == TCM_OWNER_CONTROL)
        ret = 0;

    return ret;
}

/*
 * Check whether a key is in the TCM. Returns the index (>=0) at which
 * slot the key is, -1 otherwise.
 */
static int IsKeyInTCM(struct tcm_buffer *capabilities, uint32_t shandle)
{
    uint32_t ctr;
    int rc = 0;
    uint32_t handle;

    if (shandle == 0x00000000 ||
            (shandle >= TCM_KH_SMK &&
             shandle <= TCM_KH_EK) ||
            shandle == 0xffffffff) {
        return 1;
    }

    for (ctr = 2; ctr < capabilities->used; ctr += sizeof(handle)) {
        tcm_buffer_load32(capabilities,
                          ctr,
                          &handle);

        if (handle == shandle) {
            rc = 1;
            break;
        }
    }

#if 0
    if (rc == 1) {
        printf("key %08x is in TCM\n", shandle);
    } else {
        printf("key %08x is NOT in TCM\n", shandle);
    }
#endif
    return rc;
}



/*
 * make sure the given keys are in the TCM and there is
 * enough room for 'room' keys in the TCM
 */
static uint32_t
needKeysRoom_General(uint32_t key1, uint32_t key2, uint32_t key3,
                     uint32_t room,
                     uint32_t *orig_key1)
{
    uint32_t ret = 0;
    uint32_t scap_no;
    STACK_TCM_BUFFER(context);
    STACK_TCM_BUFFER(scap);
    STACK_TCM_BUFFER(capabilities);
    uint32_t tcmkeyroom;
    uint32_t keysintcm = 0;
    int intcm1, intcm2, intcm3;
    uint32_t neededslots;
    char *tmp1;
    char *tmp2;
    char *tmp3;

    tmp1 = getenv("TCM_AUDITING");
    tmp2 = getenv("TCM_TRANSPORT");
    tmp3 = getenv("TCM_NO_KEY_SWAP");

    if ((tmp1 && !strcmp(tmp1, "1") &&
            tmp2 && !strcmp(tmp2, "1")) ||
            (tmp3 && !strcmp(tmp3, "1")) ) {
        return 0;
    }

#if 0
    printf("level: %d\n", g_num_transports);
#endif
    /*
     * Support for 1.1 TCMs is not possible since the key handle
     * must be maintained and the old SaveKeyContext functions don't
     * do that.
     *
     * Strategy for 1.2 TCMs:
         *  Check the number of keys the TCM can handle.
         *  Check which keys are in the TCM and how many.
         *  If there's enough room for all keys that need to be loaded in,
         *   just load them in, otherwise swap an unneeded key out first.
         *  If necessary, swap as many keys out such that there's enough
         *  room for 'room' keys.
     */

    scap_no = htonl(TCM_CAP_PROP_MAX_KEYS);   // 0x110
    SET_TCM_BUFFER(&scap, &scap_no, sizeof(scap_no));
    ret = TCM_GetCapability_NoTransport(TCM_CAP_PROPERTY, // 0x5
                                        &scap,

                                        &capabilities);
    if (ret != 0) {
        /* call may fail at very beginning */
        return 0;
    } else {
        ret = tcm_buffer_load32(&capabilities, 0, &tcmkeyroom);
        if (ret != 0) {
            return ret;
        }
    }


    scap_no = htonl(TCM_RT_KEY);
    SET_TCM_BUFFER(&scap, &scap_no, sizeof(scap_no));
    ret = TCM_GetCapability_NoTransport(TCM_CAP_KEY_HANDLE,
                                        &scap,

                                        &capabilities);
    if (ret != 0) {
        printf("Error %s from TCM_GetCapability.\n",
               TCM_GetErrMsg(ret));
        return ret;
    }

    neededslots = room;

    intcm1 = IsKeyInTCM(&capabilities, key1);
    if (!intcm1)
        neededslots++;
    intcm2 = IsKeyInTCM(&capabilities, key2);
    if (!intcm2)
        neededslots++;
    intcm3 = IsKeyInTCM(&capabilities, key3);
    if (!intcm3)
        neededslots++;

#if 0
    uint32_t ctr, handle;
    for (ctr = 2; ctr < capabilities.used; ctr += sizeof(handle)) {
        ret = tcm_buffer_load32(&capabilities,
                                ctr,
                                &handle);
        if (ret != 0) {
            break;
        }
        printf("available key: %08x\n", handle);
    }
#endif

    keysintcm = (capabilities.used - 2 ) / 4;

#if 0
    fprintf(stderr, "TCM has room for %d keys, holds %d keys. need %d slots\n",
            tcmkeyroom, keysintcm, neededslots);
#endif

    assert(neededslots <= tcmkeyroom);

    if ((int)neededslots > ((int)tcmkeyroom - (int)keysintcm)) {
        ret = swapOutKeys((int)neededslots - ((int)tcmkeyroom - (int)keysintcm),
                          key1,
                          key2,
                          key3,
                          &capabilities,
                          orig_key1);
#if 0
    } else {
        printf("No need to swap out keys.\n");
#endif
    }

    if (ret == 0 && !intcm1) {
        ret = swapInKey(key1);
    }
    if (ret == 0 && !intcm2) {
        ret = swapInKey(key2);
    }
    if (ret == 0 && !intcm3) {
        ret = swapInKey(key3);
    }

    return ret;
}

/*
 * make sure the given keys are in the TCM and there is
 * enough room for 'room' keys in the TCM
 *
 * For all general functions, except for those that can be
 * stacked (transport-related, virtual TCM transport instance
 * related) I reserve '1' more key slots for every stacked layer.
 * This is necessary so that once for example the Transport functions
 * are called and want to swap their own keys in, that they don't
 * swap keys out that are currently needed.
 */
uint32_t needKeysRoom(uint32_t key1, uint32_t key2, uint32_t key3,
                      int room      )
{
    char *trans = getenv("TCM_TRANSPORT");
    uint32_t transport = 0;
    /* g_num_transport likely always 0 */
    uint32_t rm;

    if (trans && !strcmp("1", trans))
        transport = 1;

    rm = room + g_num_transports + 2 + transport;
    if (room < 0)
        rm = 0;
    else {
        if (key1)
            rm--;   //needKeysRoom_General will check wether the key is in TCM, and the room may be added by then.
        if (key2)
            rm--;
        if (key3)
            rm--;
    }
    return needKeysRoom_General(key1,
                                key2,
                                key3,
                                rm,
                                NULL);
}

uint32_t needKeysRoom_Stacked(uint32_t key1, uint32_t *orig_key1      )
{
    return needKeysRoom_General(key1,
                                0,
                                0,
                                0,
                                orig_key1 );
}

uint32_t needKeysRoom_Stacked_Undo(uint32_t swapout_key, uint32_t swapin_key      )
{
    uint32_t ret;
    int swapped = 0;
    char *tmp1;
    char *tmp2;
    char *tmp3;

    tmp1 = getenv("TCM_AUDITING");
    tmp2 = getenv("TCM_TRANSPORT");
    tmp3 = getenv("TCM_NO_KEY_SWAP");

    if ((tmp1 && !strcmp(tmp1, "1") &&
            tmp2 && !strcmp(tmp2, "1")) ||
            (tmp3 && !strcmp(tmp3, "1")) ) {
        return 0;
    }

    if (isKeySwapable(swapout_key)) {
        ret = swapOutKey(swapout_key          );
        if (ret != 0)
            return ret;
        swapped = 1;
    }

    return needKeysRoom_General(swapin_key,
                                0,
                                0,
                                (swapped) ? 0 : 1,
                                NULL);
}
