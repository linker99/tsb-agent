/********************************************************************************/
/*										*/
/*			     	TCM New Serialization Routines			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: newserialize.h 4183 2010-11-10 21:24:17Z stefanb $		*/
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

#ifndef TCM_SERIALIZE_H
#define TCM_SERIALIZE_H


#define FORMAT_ENTRY(idx, string) \
  [idx] = string

enum {
    FORIDX_TCM_STRUCT_VER = 0,
    FORIDX_TCM_VERSION,
    FORIDX_TCM_KEY_HANDLE_LIST,
    FORIDX_TCM_CHANGEAUTH_VALIDATE,
    FORIDX_TCM_STORE_PUBKEY,
    FORIDX_TCM_PUBKEY,
    FORIDX_TCM_PCR_COMPOSITE,
    FORIDX_TCM_PCR_INFO_LONG,
    FORIDX_TCM_PCR_INFO_SHORT,
    FORIDX_TCM_STCLEAR_FLAGS,
    FORIDX_TCM_CONTEXT_BLOB,
};

#define FORMAT_TCM_STRUCT_VER "oooo"
#define PARAMS_TCM_STRUCT_VER(pre,x) \
   pre(x)->major, \
   pre(x)->minor, \
   pre(x)->revMajor, \
   pre(x)->revMinor


#define FORMAT_TCM_VERSION "oooo"
#define PARAMS_TCM_VERSION(pre,x) \
   pre(x)->major, \
   pre(x)->minor, \
   pre(x)->revMajor, \
   pre(x)->revMinor

#define FORMAT_TCM_KEY_HANDLE_LIST "a"
#define PARAMS_TCM_KEY_HANDLE_LIST(pre,x) \
   pre(x)->loaded,      \
   4, pre(x)->handle[0]


#define FORMAT_TCM_CHANGEAUTH_VALIDATE "%%"
#define PARAMS_TCM_CHANGEAUTH_VALIDATE(pre,x) \
   TCM_AUTHDATA_SIZE, pre(x)->newAuthSecret, \
   TCM_NONCE_SIZE, pre(x)->n1


#define FORMAT_TCM_SIGN_INFO "S%%*"
#define PARAMS_TCM_SIGN_INFO(pre,x) \
   pre(x)->tag,        \
   4, pre(x)->fixed,   \
   TCM_NONCE_SIZE, pre(x)->replay, \
   pre(x)->data.size, pre(x)->data.buffer
#define PARAMS_TCM_SIGN_INFO_W(x) \
   PARAMS_TCM_SIGN_INFO(,x)
#define PARAMS_TCM_SIGN_INFO_R(x) \
   PARAMS_TCM_SIGN_INFO(&,x)


#define FORMAT_TCM_PCR_SELECTION "^"
#define PARAMS_TCM_PCR_SELECTION(pre,x) \
   pre(x)->sizeOfSelect, sizeof((x)->pcrSelect), pre(x)->pcrSelect
#define PARAMS_TCM_PCR_SELECTION_W(x) \
   PARAMS_TCM_PCR_SELECTION(,x)
#define PARAMS_TCM_PCR_SELECTION_R(x) \
   PARAMS_TCM_PCR_SELECTION(&,x)


#define FORMAT_TCM_PCR_COMPOSITE FORMAT_TCM_PCR_SELECTION "*"
#define PARAMS_TCM_PCR_COMPOSITE(pre,x) \
   PARAMS_TCM_PCR_SELECTION(pre, &(x)->select), \
   pre(x)->pcrValue.size, pre(x)->pcrValue.buffer
#define PARAMS_TCM_PCR_COMPOSITE_W(x) \
   PARAMS_TCM_PCR_COMPOSITE(,x)
#define PARAMS_TCM_PCR_COMPOSITE_R(x) \
   PARAMS_TCM_PCR_COMPOSITE(&,x)

#define FORMAT_TCM_PCR_INFO "Soo" FORMAT_TCM_PCR_SELECTION FORMAT_TCM_PCR_SELECTION "%%"
#define PARAMS_TCM_PCR_INFO(pre,x) \
   pre(x)->tag,                \
   pre(x)->localityAtCreation, \
   pre(x)->localityAtRelease,  \
   PARAMS_TCM_PCR_SELECTION(pre, &(x)->PcrAtCreation),\
   PARAMS_TCM_PCR_SELECTION(pre, &(x)->PcrAtRelease), \
   TCM_DIGEST_SIZE, pre(x)->digestAtCreation, \
   TCM_DIGEST_SIZE, pre(x)->digestAtRelease
#define PARAMS_TCM_PCR_INFO_W(x) \
   PARAMS_TCM_PCR_INFO(,x)
#define PARAMS_TCM_PCR_INFO_R(x) \
   PARAMS_TCM_PCR_INFO(&,x)


#define FORMAT_TCM_KEY_PARMS "LSS@"
#define PARAMS_TCM_KEY_PARMS(pre,x) \
   pre(x)->algorithmID, \
   pre(x)->encScheme,   \
   pre(x)->sigScheme,   \
   pre(x)->parms.size, pre(x)->parms.buffer
#define PARAMS_TCM_KEY_PARMS_W(x) \
  PARAMS_TCM_KEY_PARMS(,x)
#define PARAMS_TCM_KEY_PARMS_R(x) \
  PARAMS_TCM_KEY_PARMS(&,x)


#define FORMAT_TCM_STORE_PUBKEY "@"
#define PARAMS_TCM_STORE_PUBKEY(pre,x) \
   pre(x)->keyLength, pre(x)->key
#define PARAMS_TCM_STORE_PUBKEY_W(x)\
   PARAMS_TCM_STORE_PUBKEY(,x)
#define PARAMS_TCM_STORE_PUBKEY_R(x)\
   PARAMS_TCM_STORE_PUBKEY(&,x)

#define FORMAT_TCM_PUBKEY FORMAT_TCM_KEY_PARAMS FORMAT_TCM_STORE_PUBKEY
#define PARAMS_TCM_PUBKEY(pre,x) \
   PARAMS_TCM_KEY_PARMS(pre, &(x)->algorithmParams), \
   PARAMS_TCM_STORE_PUBKEY(pre, &(x)->pubKey)
#define PARAMS_TCM_PUBKEY_W(x)\
   PARAMS_TCM_PUBKEY(,x)
#define PARAMS_TCM_PUBKEY_R(x)\
   PARAMS_TCM_PUBKEY(&,x)

#define FORMAT_TCM_MIGRATIONKEYAUTH FORMAT_TCM_PUBKEY "S%"
#define PARAMS_TCM_MIGRATIONKEYAUTH(pre,x) \
   PARAMS_TCM_PUBKEY_W(x), \
   pre(x)->migrationScheme,   \
   TCM_DIGEST_SIZE, pre(x)->digest
#define PARAMS_TCM_MIGRATIONKEYAUTH_W(x)\
   PARAMS_TCM_MIGRATIONKEYAUTH(,x)
#define PARAMS_TCM_MIGRATIONKEYAUTH_R(x)\
   PARAMS_TCM_MIGRATIONKEYAUTH(&,x)

#define FORMAT_TCM_STCLEAR_FLAGS "Sooooo"
#define PARAMS_TCM_STCLEAR_FLAGS(pre,x) \
   pre(x)->tag, \
   pre(x)->deactivated, \
   pre(x)->disableForceClear, \
   pre(x)->physicalPresence,  \
   pre(x)->physicalPresenceLock, \
   pre(x)->bGlobalLock
#define PARAMS_TCM_STCLEAR_FLAGS_W(x) \
   PARAMS_TCM_STCLEAR_FLAGS(,x)
#define PARAMS_TCM_STCLEAR_FLAGS_R(x) \
   PARAMS_TCM_STCLEAR_FLAGS(&,x)


#define FORMAT_TCM_CONTEXT_BLOB "SLL%L%**"
#define PARAMS_TCM_CONTEXT_BLOB(pre,x) \
  pre(x)->tag, \
  pre(x)->resourceType, \
  pre(x)->handle, \
  TCM_CONTEXT_LABEL_SIZE, pre(x)->label, \
  pre(x)->contextCount, \
  TCM_HASH_SIZE, pre(x)->integrityDigest, \
  pre(x)->additionalData.size, pre(x)->additionalData.buffer, \
  pre(x)->sensitiveData.size, pre(x)->sensitiveData.buffer
#define PARAMS_TCM_CONTEXT_BLOB_W(x) \
   PARAMS_TCM_CONTEXT_BLOB(,x)
#define PARAMS_TCM_CONTEXT_BLOB_R(x) \
   PARAMS_TCM_CONTEXT_BLOB(&,x)

/* rev 62 */
#define FORMAT_TCM_PERMANENT_FLAGS "Sooooooooooooooo"
#define PARAMS_TCM_PERMANENT_FLAGS(pre,x) \
   pre(x)->tag, 			\
   pre(x)->disable, 			\
   pre(x)->ownership, 			\
   pre(x)->deactivated,			\
   pre(x)->readPubek,			\
   pre(x)->disableOwnerClear, 			\
   pre(x)->physicalPresenceLifetimeLock, \
   pre(x)->physicalPresenceHWEnable, 	\
   pre(x)->physicalPresenceCMDEnable, 	\
   pre(x)->CEKPUsed, 	\
   pre(x)->TCMpost, 	\
   pre(x)->TCMpostLock, 	\
   pre(x)->operator,				\
   pre(x)->enableRevokeEK, 			\
   pre(x)->nvLocked, 			\
   pre(x)->tcmEstablished
#define PARAMS_TCM_PERMANENT_FLAGS_W(x) \
   PARAMS_TCM_PERMANENT_FLAGS(,x)
#define PARAMS_TCM_PERMANENT_FLAGS_R(x) \
   PARAMS_TCM_PERMANENT_FLAGS(&,x)


#define FORMAT_TCM_PCR_INFO_SHORT FORMAT_TCM_PCR_SELECTION "o%"
#define PARAMS_TCM_PCR_INFO_SHORT(pre,x) \
   PARAMS_TCM_PCR_SELECTION(pre, &(x)->pcrSelection),\
   pre(x)->localityAtRelease, \
   TCM_HASH_SIZE, pre(x)->digestAtRelease
#define PARAMS_TCM_PCR_INFO_SHORT_W(x) \
  PARAMS_TCM_PCR_INFO_SHORT(,x)
#define PARAMS_TCM_PCR_INFO_SHORT_R(x) \
  PARAMS_TCM_PCR_INFO_SHORT(&,x)


#define FORMAT_TCM_PCRSIG_BLOB  "o" FORMAT_TCM_PCR_COMPOSITE
#define PARAMS_TCM_PCRSIG_BLOB(pre,x) \
   pre(x)->currentLocality,\
   PARAMS_TCM_PCR_COMPOSITE(pre,&(x)->pcrsComposite)
#define PARAMS_TCM_PCRSIG_BLOB_W(x) \
  PARAMS_TCM_PCRSIG_BLOB(,x)
#define PARAMS_TCM_PCRSIG_BLOB_R(x) \
  PARAMS_TCM_PCRSIG_BLOB(&,x)


#define FORMAT_TCM_STORE_ASYMKEY "o%%%@@@"
#define PARAMS_TCM_STORE_ASYMKEY(pre,x) \
   pre(x)->payload, \
   TCM_SECRET_SIZE, pre(x)->usageAuth,\
   TCM_SECRET_SIZE, pre(x)->migrationAuth, \
   TCM_DIGEST_SIZE, pre(x)->pubDataDigest, \
   pre(x)->privKey.d_key.size, pre(x)->privKey.d_key.buffer, \
   pre(x)->privKey.p_key.size, pre(x)->privKey.p_key.buffer, \
   pre(x)->privKey.q_key.size, pre(x)->privKey.q_key.buffer
#define PARAMS_TCM_STORE_ASYMKEY_W(x) \
   PARAMS_TCM_STORE_ASYMKEY(,x)
#define PARAMS_TCM_STORE_ASYMKEY_R(x) \
   PARAMS_TCM_STORE_ASYMKEY(&,x)

#define FORMAT_TCM_SEALED_PUB_DATA "SS**"
#define PARAMS_TCM_SEALED_PUB_DATA(pre,x) \
   pre(x)->tag, pre(x)->et, \
   pre(x)->pcrInfo.size, pre(x)->pcrInfo.buffer, \
   pre(x)->encData.size, pre(x)->encData.buffer
#define PARAMS_TCM_SEALED_PUB_DATA_W(x) \
   PARAMS_TCM_SEALED_PUB_DATA(,x)
#define PARAMS_TCM_SEALED_PUB_DATA_R(x) \
   PARAMS_TCM_SEALED_PUB_DATA(&,x)


#define FORMAT_TCM_CMK_AUTH "%%%"
#define PARAMS_TCM_CMK_AUTH(pre,x) \
   TCM_DIGEST_SIZE, pre(x)->migrationAuthorityDigest,\
   TCM_DIGEST_SIZE, pre(x)->destinationKeyDigest, \
   TCM_DIGEST_SIZE, pre(x)->sourceKeyDigest
#define PARAMS_TCM_CMK_AUTH_W(x) \
   PARAMS_TCM_CMK_AUTH(,x)
#define PARAMS_TCM_CMK_AUTH_R(x) \
   PARAMS_TCM_CMK_AUTH(&,x)

#define FORMAT_TCM_EK_BLOB_ACTIVATE "S" FORMAT_TCM_SYMMETRIC_KEY "%" FORMAT_TCM_PCR_INFO_SHORT
#define PARAMS_TCM_EK_BLOB_ACTIVATE(pre,x) \
  pre(x)->tag,\
  PARAMS_TCM_SYMMETRIC_KEY(pre,&(x)->sessionKey),\
  TCM_HASH_SIZE, pre(x)->idDigest,\
  PARAMS_TCM_PCR_INFO_SHORT(pre,&(x)->pcrInfo)
#define PARAMS_TCM_EK_BLOB_ACTIVATE_W(x) \
  PARAMS_TCM_EK_BLOB_ACTIVATE(,x)
#define PARAMS_TCM_EK_BLOB_ACTIVATE_R(x) \
  PARAMS_TCM_EK_BLOB_ACTIVATE(&,x)


#define FORMAT_TCM_EK_BLOB "SS*"
#define PARAMS_TCM_EK_BLOB(pre,x) \
  pre(x)->tag,\
  pre(x)->ekType,\
  pre(x)->blob.size, pre(x)->blob.buffer
#define PARAMS_TCM_EK_BLOB_W(x)\
  PARAMS_TCM_EK_BLOB(,x)
#define PARAMS_TCM_EK_BLOB_R(x)\
  PARAMS_TCM_EK_BLOB(&,x)


#define FORMAT_TCM_ASYM_CA_CONTENTS FORMAT_TCM_SYMMETRIC_KEY "%"
#define PARAMS_TCM_ASYM_CA_CONTENTS(pre,x) \
  PARAMS_TCM_SYMMETRIC_KEY(pre, &(x)->sessionKey),\
  TCM_HASH_SIZE, pre(x)->idDigest
#define PARAMS_TCM_ASYM_CA_CONTENTS_W(x) \
  PARAMS_TCM_ASYM_CA_CONTENTS(,x)
#define PARAMS_TCM_ASYM_CA_CONTENTS_R(x) \
  PARAMS_TCM_ASYM_CA_CONTENTS(&,x)


#define FORMAT_TCM_TRANSPORT_PUBLIC "SLLS"
#define PARAMS_TCM_TRANSPORT_PUBLIC(pre,x) \
  pre(x)->tag,\
  pre(x)->transAttributes,\
  pre(x)->algId,\
  pre(x)->encMode
#define PARAMS_TCM_TRANSPORT_PUBLIC_W(x)\
  PARAMS_TCM_TRANSPORT_PUBLIC(,x)
#define PARAMS_TCM_TRANSPORT_PUBLIC_R(x)\
  PARAMS_TCM_TRANSPORT_PUBLIC(&,x)


#define FORMAT_TCM_TRANSPORT_AUTH "S%"
#define PARAMS_TCM_TRANSPORT_AUTH(pre,x) \
  pre(x)->tag,\
  TCM_AUTHDATA_SIZE, pre(x)->authData
#define PARAMS_TCM_TRANSPORT_AUTH_W(x)\
  PARAMS_TCM_TRANSPORT_AUTH(,x)
#define PARAMS_TCM_TRANSPORT_AUTH_R(x)\
  PARAMS_TCM_TRANSPORT_AUTH(&,x)


#define FORMAT_TCM_CAP_VERSION_INFO "SLLo"
#define PARAMS_TCM_CAP_VERSION_INFO(pre,x) \
  pre(x)->tag,\
  pre(x)->tcmID,\
  pre(x)->platformID,\
  pre(x)->revision
#define PARAMS_TCM_CAP_VERSION_INFO_W(x)\
  PARAMS_TCM_CAP_VERSION_INFO(,x)
#define PARAMS_TCM_CAP_VERSION_INFO_R(x)\
  PARAMS_TCM_CAP_VERSION_INFO(&,x)


#define FORMAT_TCM_NV_DATA_PUBLIC "SL" FORMAT_TCM_PCR_INFO_SHORT FORMAT_TCM_PCR_INFO_SHORT "SLoooL"
#define PARAMS_TCM_NV_DATA_PUBLIC(pre,x) \
   pre(x)->tag, \
   pre(x)->nvIndex, \
   PARAMS_TCM_PCR_INFO_SHORT(pre,&(x)->pcrInfoRead), \
   PARAMS_TCM_PCR_INFO_SHORT(pre,&(x)->pcrInfoWrite), \
   pre(x)->permission.tag, \
   pre(x)->permission.attributes, \
   pre(x)->bReadSTClear, \
   pre(x)->bWriteSTClear, \
   pre(x)->bWriteDefine, \
   pre(x)->dataSize
#define PARAMS_TCM_NV_DATA_PUBLIC_W(x) \
  PARAMS_TCM_NV_DATA_PUBLIC(,x)
#define PARAMS_TCM_NV_DATA_PUBLIC_R(x) \
  PARAMS_TCM_NV_DATA_PUBLIC(&,x)


#define FORMAT_TCM_SYMMETRIC_KEY "LS&"
#define PARAMS_TCM_SYMMETRIC_KEY(pre,x) \
   pre(x)->algId,\
   pre(x)->encScheme,\
   pre(x)->size, pre(x)->data
#define PARAMS_TCM_SYMMETRIC_KEY_W(x)\
  PARAMS_TCM_SYMMETRIC_KEY(,x)
#define PARAMS_TCM_SYMMETRIC_KEY_R(x)\
  PARAMS_TCM_SYMMETRIC_KEY(&,x)


#define FORMAT_TCM_FAMILY_TABLE_ENTRY "SoLLL"
#define PARAMS_TCM_FAMILY_TABLE_ENTRY(pre,x)\
  pre(x)->tag,\
  pre(x)->familyLabel,\
  pre(x)->familyID,\
  pre(x)->verificationCount,\
  pre(x)->flags
#define PARAMS_TCM_FAMILY_TABLE_ENTRY_W(x)\
  PARAMS_TCM_FAMILY_TABLE_ENTRY(,x)
#define PARAMS_TCM_FAMILY_TABLE_ENTRY_R(x)\
  PARAMS_TCM_FAMILY_TABLE_ENTRY(&,x)


#define FORMAT_TCM_CURRENT_TICKS "SLLS%"
#define PARAMS_TCM_CURRENT_TICKS(pre,x)\
  pre(x)->tag,\
  pre(x)->currentTicks.sec,\
  pre(x)->currentTicks.usec,\
  pre(x)->tickRate,\
  TCM_HASH_SIZE, pre(x)->tickNonce
#define PARAMS_TCM_CURRENT_TICKS_W(x)\
  PARAMS_TCM_CURRENT_TICKS(,x)
#define PARAMS_TCM_CURRENT_TICKS_R(x)\
  PARAMS_TCM_CURRENT_TICKS(&,x)




#define FORMAT_TCM_CURRENT_TICKS_SHORT "LL"
#define PARAMS_TCM_CURRENT_TICKS_SHORT(pre,x)\
  pre(x)->sec,\
  pre(x)->usec
#define PARAMS_TCM_CURRENT_TICKS_SHORT_W(x)\
  PARAMS_TCM_CURRENT_TICKS_SHORT(,x)
#define PARAMS_TCM_CURRENT_TICKS_SHORT_R(x)\
  PARAMS_TCM_CURRENT_TICKS_SHORT(&,x)






#define FORMAT_TCM_COUNTER_VALUE "S%L"
#define PARAMS_TCM_COUNTER_VALUE(pre,x) \
  pre(x)->tag,\
  sizeof((x)->label), pre(x)->label,\
  pre(x)->counter
#define PARAMS_TCM_COUNTER_VALUE_W(x)\
  PARAMS_TCM_COUNTER_VALUE(,x)
#define PARAMS_TCM_COUNTER_VALUE_R(x)\
  PARAMS_TCM_COUNTER_VALUE(&,x)



#define FORMAT_TCM_KEY_PARAMS_SM2 "L"
#define PARAMS_TCM_KEY_PARAMS_SM2(pre,x)\
  pre(x)->keyLength
#define PARAMS_TCM_KEY_PARAMS_SM2_W(x)\
  PARAMS_TCM_KEY_PARAMS_SM2(,x)
#define PARAMS_TCM_KEY_PARAMS_SM2_R(x)\
		PARAMS_TCM_KEY_PARAMS_SM2(&,x)

#define FORMAT_TCM_KEY_PARAMS_SM4 "LLL%"
#define PARAMS_TCM_KEY_PARAMS_SM4(pre,x) \
  pre(x)->keyLength,\
  pre(x)->blockSize,\
  pre(x)->ivSize,\
  TCM_IV_SIZE,pre(x)->IV
#define PARAMS_TCM_KEY_PARAMS_SM4_W(x)\
  PARAMS_TCM_KEY_PARAMS_SM4(,x)
#define PARAMS_TCM_KEY_PARAMS_SM4_R(x)\
		PARAMS_TCM_KEY_PARAMS_SM4(&,x)


#define FORMAT_TCM_PCR_LIST_TIMESTAMP "LL%LL"
#define PARAMS_TCM_PCR_LIST_TIMESTAMP(pre,x) \
  pre(x)->ordinal,\
  pre(x)->pcrIndex,\
  TCM_HASH_SIZE, pre(x)->digest,\
  pre(x)->timestamp_hi, \
  pre(x)->timestamp_lo
#define PARAMS_TCM_PCR_LIST_TIMESTAMP_W(x)\
  PARAMS_TCM_PCR_LIST_TIMESTAMP(,x)
#define PARAMS_TCM_PCR_LIST_TIMESTAMP_R(x)\
  PARAMS_TCM_PCR_LIST_TIMESTAMP(&,x)

#define FORMAT_TCM_PCR_LIST_TIMESTAMP_INST "LLL%LL"
#define PARAMS_TCM_PCR_LIST_TIMESTAMP_INST(pre,x) \
  pre(x)->instance,\
  pre(x)->ordinal,\
  pre(x)->pcrIndex,\
  TCM_HASH_SIZE, pre(x)->digest,\
  pre(x)->timestamp_hi, \
  pre(x)->timestamp_lo
#define PARAMS_TCM_PCR_LIST_TIMESTAMP_INST_W(x)\
  PARAMS_TCM_PCR_LIST_TIMESTAMP_INST(,x)
#define PARAMS_TCM_PCR_LIST_TIMESTAMP_INST_R(x)\
  PARAMS_TCM_PCR_LIST_TIMESTAMP_INST(&,x)


/*
 * TCM-client specific defines
 */
#define FORMAT_TCM_SM2_KEY_PARMS_EMB "L"
#define PARAMS_TCM_SM2_KEY_PARMS_EMB(pre,x) \
  pre(x)->keyLength
#define PARAMS_TCM_SM2_KEY_PARMS_EMB_W(x)\
  PARAMS_TCM_SM2_KEY_PARMS_EMB(,x)
#define PARAMS_TCM_SM2_KEY_PARMS_EMB_R(x)\
  PARAMS_TCM_SM2_KEY_PARMS_EMB(&,x)


#define FORMAT_TCM_SYMMETRIC_KEY_PARMS_EMB "LL!"
#define PARAMS_TCM_SYMMETRIC_KEY_PARMS_EMB(pre,x) \
		pre(x)->keyLength,\
		pre(x)->blockSize,\
    	pre(x)->ivSize, \
    	sizeof((x)->IV) ,pre(x)->IV
#define PARAMS_TCM_SYMMETRIC_KEY_PARMS_EMB_W(x)\
  PARAMS_TCM_SYMMETRIC_KEY_PARMS_EMB(,x)
#define PARAMS_TCM_SYMMETRIC_KEY_PARMS_EMB_R(x)\
  PARAMS_TCM_SYMMETRIC_KEY_PARMS_EMB(&,x)

#define FORMAT_TCM_KEY_PARMS_EMB_SM2 "LSSL" FORMAT_TCM_SM2_KEY_PARMS_EMB
#define PARAMS_TCM_KEY_PARMS_EMB_SM2(pre,x)\
  pre(x)->algorithmID,\
  pre(x)->encScheme,\
  pre(x)->sigScheme,\
  pre(x)->parmSize,\
  PARAMS_TCM_SM2_KEY_PARMS_EMB(pre,&(x)->sm2para)
#define PARAMS_TCM_KEY_PARMS_EMB_SM2_W(x)\
  PARAMS_TCM_KEY_PARMS_EMB_SM2(,x)
#define PARAMS_TCM_KEY_PARMS_EMB_SM2_R(x)\
  PARAMS_TCM_KEY_PARMS_EMB_SM2(&,x)

#define FORMAT_TCM_KEY_PARMS_EMB_SYM "LSSL" FORMAT_TCM_SYMMETRIC_KEY_PARMS_EMB
#define PARAMS_TCM_KEY_PARMS_EMB_SYM(pre,x)\
  pre(x)->algorithmID,\
  pre(x)->encScheme,\
  pre(x)->sigScheme,\
  pre(x)->parmSize,\
  PARAMS_TCM_SYMMETRIC_KEY_PARMS_EMB(pre,&(x)->sm4para)
#define PARAMS_TCM_KEY_PARMS_EMB_SYM_W(x)\
  PARAMS_TCM_KEY_PARMS_EMB_SYM(,x)
#define PARAMS_TCM_KEY_PARMS_EMB_SYM_R(x)\
  PARAMS_TCM_KEY_PARMS_EMB_SYM(&,x)


#define FORMAT_TCM_STORE_PUBKEY_EMB "!"
#define PARAMS_TCM_STORE_PUBKEY_EMB(pre,x)\
  pre(x)->keyLength,sizeof((x)->modulus),pre(x)->modulus
#define PARAMS_TCM_STORE_PUBKEY_EMB_W(x)\
  PARAMS_TCM_STORE_PUBKEY_EMB(,x)
#define PARAMS_TCM_STORE_PUBKEY_EMB_R(x)\
  PARAMS_TCM_STORE_PUBKEY_EMB(&,x)


#define FORMAT_TCM_AUDIT_EVENT_IN "S%" FORMAT_TCM_COUNTER_VALUE
#define PARAMS_TCM_AUDIT_EVENT_IN(pre,x)\
  pre(x)->tag,\
  32, pre(x)->inputParms,\
  PARAMS_TCM_COUNTER_VALUE(pre, &(x)->auditCount)
#define PARAMS_TCM_AUDIT_EVENT_IN_W(x)\
  PARAMS_TCM_AUDIT_EVENT_IN(,x)
#define PARAMS_TCM_AUDIT_EVENT_IN_R(x)\
  PARAMS_TCM_AUDIT_EVENT_IN(&,x)


#define FORMAT_TCM_AUDIT_EVENT_OUT "S%" FORMAT_TCM_COUNTER_VALUE
#define PARAMS_TCM_AUDIT_EVENT_OUT(pre,x)\
  pre(x)->tag,\
  32, pre(x)->outputParms,\
	PARAMS_TCM_COUNTER_VALUE(pre, &(x)->auditCount)
#define PARAMS_TCM_AUDIT_EVENT_OUT_W(x)\
  PARAMS_TCM_AUDIT_EVENT_OUT(,x)
#define PARAMS_TCM_AUDIT_EVENT_OUT_R(x)\
  PARAMS_TCM_AUDIT_EVENT_OUT(&,x)


#define FORMAT_TCM_DA_ACTION_TYPE "SL"
#define PARAMS_TCM_DA_ACTION_TYPE(pre,x)\
  pre(x)->tag,\
  pre(x)->actions
#define PARAMS_TCM_DA_ACTION_TYPE_W(x)\
  PARAMS_TCM_DA_ACTION_TYPE(,x)
#define PARAMS_TCM_DA_ACTION_TYPE_R(x)\
  PARAMS_TCM_DA_ACTION_TYPE(&,x)

#define FORMAT_TCM_DA_INFO "SoSS" FORMAT_TCM_DA_ACTION_TYPE "L*"
#define PARAMS_TCM_DA_INFO(pre,x)\
  pre(x)->tag,\
  pre(x)->state,\
  pre(x)->currentCount,\
  pre(x)->thresholdCount,\
  PARAMS_TCM_DA_ACTION_TYPE(pre, &(x)->actionAtThreshold),\
  pre(x)->actionDependValue,\
  pre(x)->vendorData.size, pre(x)->vendorData.buffer
#define PARAMS_TCM_DA_INFO_W(x)\
  PARAMS_TCM_DA_INFO(,x)
#define PARAMS_TCM_DA_INFO_R(x)\
  PARAMS_TCM_DA_INFO(&,x)

#define FORMAT_TCM_DA_INFO_LIMITED "So" FORMAT_TCM_DA_ACTION_TYPE "*"
#define PARAMS_TCM_DA_INFO_LIMITED(pre,x)\
  pre(x)->tag,\
  pre(x)->state,\
  PARAMS_TCM_DA_ACTION_TYPE(pre, &(x)->actionAtThreshold),\
  pre(x)->vendorData.size, pre(x)->vendorData.buffer
#define PARAMS_TCM_DA_INFO_LIMITED_W(x)\
  PARAMS_TCM_DA_INFO_LIMITED(,x)
#define PARAMS_TCM_DA_INFO_LIMITED_R(x)\
  PARAMS_TCM_DA_INFO_LIMITED(&,x)


#define FORMAT_TCM_KEY_EMB_SM2 FORMAT_TCM_STRUCT_VER "SLo" FORMAT_TCM_KEY_PARMS_EMB_SM2 "!" FORMAT_TCM_STORE_PUBKEY_EMB "!"
#define PARAMS_TCM_KEY_EMB_SM2(pre,x)\
  PARAMS_TCM_STRUCT_VER(pre, &(x)->v.ver),\
  pre(x)->keyUsage,\
  pre(x)->keyFlags,\
  pre(x)->authDataUsage,\
  PARAMS_TCM_KEY_PARMS_EMB_SM2(pre, &(x)->pub.algorithmParms),\
  pre(x)->pub.pcrInfo.size, sizeof((x)->pub.pcrInfo.buffer), pre(x)->pub.pcrInfo.buffer,\
  PARAMS_TCM_STORE_PUBKEY_EMB(pre, &(x)->pub.pubKey),\
  pre(x)->encData.size, sizeof((x)->encData.buffer), pre(x)->encData.buffer
#define PARAMS_TCM_KEY_EMB_SM2_W(x)\
  PARAMS_TCM_KEY_EMB_SM2(,x)
#define PARAMS_TCM_KEY_EMB_SM2_R(x)\
  PARAMS_TCM_KEY_EMB_SM2(&,x)

#define FORMAT_TCM_PUBKEY_EMB_SM2 FORMAT_TCM_KEY_PARMS_EMB_SM2 FORMAT_TCM_STORE_PUBKEY_EMB
#define PARAMS_TCM_PUBKEY_EMB_SM2(pre,x)\
  PARAMS_TCM_KEY_PARMS_EMB_SM2(pre, &(x)->algorithmParms),\
  PARAMS_TCM_STORE_PUBKEY_EMB(pre, &(x)->pubKey)
#define PARAMS_TCM_PUBKEY_EMB_SM2_W(x)\
  PARAMS_TCM_PUBKEY_EMB_SM2(,x)
#define PARAMS_TCM_PUBKEY_EMB_SM2_R(x)\
  PARAMS_TCM_PUBKEY_EMB_SM2(&,x)

#define FORMAT_TCM_PUBKEY_EMB_SYM FORMAT_TCM_KEY_PARMS_EMB_SYM FORMAT_TCM_STORE_PUBKEY_EMB
#define PARAMS_TCM_PUBKEY_EMB_SYM(pre,x)\
  PARAMS_TCM_KEY_PARMS_EMB_SYM(pre, &(x)->algorithmParms),\
  PARAMS_TCM_STORE_PUBKEY_EMB(pre, &(x)->pubKey)
#define PARAMS_TCM_PUBKEY_EMB_SYM_W(x)\
  PARAMS_TCM_PUBKEY_EMB_SYM(,x)
#define PARAMS_TCM_PUBKEY_EMB_SYM_R(x)\
  PARAMS_TCM_PUBKEY_EMB_SYM(&,x)

#define FORMAT_TCM_KEY12_EMB_SM2 "SSSLo" FORMAT_TCM_KEY_PARMS_EMB_SM2 "!" FORMAT_TCM_STORE_PUBKEY_EMB "!"
#define PARAMS_TCM_KEY12_EMB_SM2(pre,x)\
  pre(x)->hdr.key12.tag,\
  pre(filler),\
  pre(x)->keyUsage,\
  pre(x)->keyFlags,\
  pre(x)->authDataUsage,\
  PARAMS_TCM_KEY_PARMS_EMB_SM2(pre, &(x)->pub.algorithmParms),\
  pre(x)->pub.pcrInfo.size, sizeof((x)->pub.pcrInfo.buffer), pre(x)->pub.pcrInfo.buffer,\
  PARAMS_TCM_STORE_PUBKEY_EMB(pre, &(x)->pub.pubKey),\
  pre(x)->encData.size, sizeof((x)->encData.buffer), pre(x)->encData.buffer
#define PARAMS_TCM_KEY12_EMB_SM2_W(x)\
  PARAMS_TCM_KEY12_EMB_SM2(,x)
#define PARAMS_TCM_KEY12_EMB_SM2_R(x)\
  PARAMS_TCM_KEY12_EMB_SM2(&,x)


#define FORMAT_TCM_KEY12_EMB_SM4 "SSSLo" FORMAT_TCM_KEY_PARMS_EMB_SYM  "!" FORMAT_TCM_STORE_PUBKEY_EMB "!"
#define PARAMS_TCM_KEY12_EMB_SM4(pre,x)\
  pre(x)->hdr.key12.tag,\
  pre(filler),\
  pre(x)->keyUsage,\
  pre(x)->keyFlags,\
  pre(x)->authDataUsage,\
  PARAMS_TCM_KEY_PARMS_EMB_SYM (pre, &(x)->pub.algorithmParms),\
  pre(x)->pub.pcrInfo.size, sizeof((x)->pub.pcrInfo.buffer), pre(x)->pub.pcrInfo.buffer,\
  PARAMS_TCM_STORE_PUBKEY_EMB(pre, &(x)->pub.pubKey),\
  pre(x)->encData.size, sizeof((x)->encData.buffer), pre(x)->encData.buffer
#define PARAMS_TCM_KEY12_EMB_SM4_W(x)\
  PARAMS_TCM_KEY12_EMB_SM4(,x)
#define PARAMS_TCM_KEY12_EMB_SM4_R(x)\
  PARAMS_TCM_KEY12_EMB_SM4(&,x)




#define FORMAT_TCM_TRANSPORT_LOG_IN "S%%"
#define PARAMS_TCM_TRANSPORT_LOG_IN(pre,x)\
  pre(x)->tag,\
  TCM_DIGEST_SIZE, pre(x)->parameters,\
  TCM_DIGEST_SIZE, pre(x)->pubKeyHash
#define PARAMS_TCM_TRANSPORT_LOG_IN_W(x)\
    PARAMS_TCM_TRANSPORT_LOG_IN(,x)
#define PARAMS_TCM_TRANSPORT_LOG_IN_R(x)\
    PARAMS_TCM_TRANSPORT_LOG_IN(&,x)

#define FORMAT_TCM_TRANSPORT_LOG_OUT "S" FORMAT_TCM_CURRENT_TICKS_SHORT "%L"
#define PARAMS_TCM_TRANSPORT_LOG_OUT(pre,x)\
  pre(x)->tag,\
  PARAMS_TCM_CURRENT_TICKS_SHORT(pre,&(x)->currentTicks),\
  TCM_DIGEST_SIZE, pre(x)->parameters,\
  pre(x)->locality
#define PARAMS_TCM_TRANSPORT_LOG_OUT_W(x)\
    PARAMS_TCM_TRANSPORT_LOG_OUT(,x)
#define PARAMS_TCM_TRANSPORT_LOG_OUT_R(x)\
    PARAMS_TCM_TRANSPORT_LOG_OUT(&,x)



#define FORMAT_SM2_PUBLIC_KEY "L%%"
#define PARAMS_SM2_PUBLIC_KEY(pre,k)\
  pre(k)->bits,\
  TCM_DIGEST_SIZE, pre(k)->x,\
  TCM_DIGEST_SIZE, pre(k)->y
#define PARAMS_SM2_PUBLIC_KEY_W(k) \
		PARAMS_SM2_PUBLIC_KEY(,k)
#define PARAMS_SM2_PUBLIC_KEY_R(k) \
		PARAMS_SM2_PUBLIC_KEY(&,k)


#endif
