/********************************************************************************/
/*										*/
/*			     	TCM PCR Processing Functions			*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: pcrs.c 4089 2010-06-09 00:50:31Z kgoldman $			*/
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
#include <hmac.h>
#include <pcrs.h>
#include <tcm_constants.h>
#include <tcm_structures.h>
#include "tcmfunc.h"

/****************************************************************************/
/*                                                                          */
/*  Read PCR value                                                          */
/*                                                                          */
/****************************************************************************/
uint32_t TCM_PcrRead(  uint32_t pcrindex, unsigned char *pcrvalue)
{
    uint32_t ret;
    uint32_t ord_no = htonl(TCM_ORD_PCRRead);

    STACK_TCM_BUFFER(tcmdata)

    if (pcrvalue == NULL) return ERR_NULL_ARG;


    ret = TSS_buildbuff("00 c1 T l  L",
                        &tcmdata, ord_no,  pcrindex);
    if ((ret & ERR_MASK) != 0 ) return ret;
    ret = TCM_Transmit(&tcmdata, "PCRRead");
    if (ret != 0) return ret;
    memcpy(pcrvalue,
           &tcmdata.buffer[TCM_DATA_OFFSET ],
           TCM_HASH_SIZE);
    return 0;
}




