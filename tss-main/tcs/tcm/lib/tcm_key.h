/********************************************************************************/
/*
	Written by S.Y
	2015-03-11
	Changelog:
*/
/********************************************************************************/

#ifndef TCM_KEY_H
#define TCM_KEY_H

#include "tcm_structures.h"
#include "tcmkeys.h"


#define TCM_KEY_SM2_NUMBITS     256
#define TCM_Key_GetPrivKey  TCM_Key_GetNativeKey
#define TCM_Key_Load(tcm_key, stream, stream_size)		 TCM_Key_LoadPub(tcm_key, stream, stream_size)
#define TCM_Key_Store(sbuffer, tcm_key)		 TCM_Key_StorePub(sbuffer, FALSE, tcm_key)
#if 0
extern unsigned char tcm_default_sm2_exponent[];
#endif

/*
	TCM_KEY
*/

void TCM_Secret_Init(TCM_SECRET tcm_secret);
void TCM_Digest_Init(TCM_DIGEST tcm_digest);
TCM_RESULT TCM_Secret_Store(TCM_STORE_BUFFER *sbuffer,
                            const TCM_SECRET tcm_secret);
TCM_RESULT TCM_Digest_Store(TCM_STORE_BUFFER *sbuffer,
                            const TCM_DIGEST tcm_digest);
//Key
void       TCM_Key_Init(TCM_KEY *tcm_key);
//deserialize stream into TCM_KEY_PUB structure
//original func:TCM_Key_Load
TCM_RESULT TCM_Key_LoadPub(TCM_KEY *tcm_key,
                           unsigned char **stream,
                           uint32_t *stream_size);
//deserialize stream into TCM_KEY_PUB structure excluding encData
//original func:TCM_Key_LoadPubData
TCM_RESULT TCM_Key_LoadPubAttr(TCM_KEY *tcm_key,
                               TCM_BOOL isEK,
                               unsigned char **stream,
                               uint32_t *stream_size);
//deserialize stream into TCM_KEY_PUB structure and fill in TCM_KEY_PRIV to write whole TCM_KEY
//original func: TCM_Key_LoadClear
TCM_RESULT TCM_Key_LoadClear(TCM_KEY *tcm_key,
                             TCM_BOOL isEK,
                             unsigned char **stream,
                             uint32_t *stream_size);
//serialize TCM_KEY_PUB structure to a buffer
//original func:  TCM_Key_Store
TCM_RESULT TCM_Key_StorePub(TCM_STORE_BUFFER *sbuffer, TCM_BOOL isEK,
                            TCM_KEY *tcm_key);
//serialize TCM_KEY_PUB structure to a buffer excluding encData
//original func:  TCM_Key_StorePubData
TCM_RESULT TCM_Key_StorePubAttr(TCM_STORE_BUFFER *sbuffer,
                                TCM_BOOL isEK,
                                TCM_KEY *tcm_key);//Excluding encData
TCM_RESULT TCM_Key_GetPCRSelection(TCM_PCR_SELECTION **tcm_pcr_selection, TCM_KEY *keyInfo);
//delete structure and buffer occupation in TCM_KEY structure
//original func:  TCM_Key_Delete
void       TCM_Key_Delete(TCM_KEY *tcm_key);
//dereference
#if 0
TCM_RESULT TCM_Key_CheckStruct(int *ver, TCM_KEY *tcm_key);
#endif
//set TCM_KEY by parameters
//original func:  TCM_Key_Set
TCM_RESULT TCM_Key_Set(TCM_KEY *tcm_key,//out
                       TCM_KEY_USAGE keyUsage,				/* input */
                       TCM_KEY_FLAGS keyFlags,				/* input */
                       TCM_AUTH_DATA_USAGE authDataUsage,		/* input */
                       TCM_KEY_PARMS *keyInfo,			/* input */
                       BYTE *publickey,			/* public key byte array */
                       TCM_KEY_PRIV *tcm_key_priv); /* cache TCM_KEY_PRIV */
//serialize TCM_KEY structure to a buffer
//original func:  TCM_Key_StoreClear
TCM_RESULT TCM_Key_StoreClear(TCM_STORE_BUFFER *sbuffer,
                              TCM_BOOL isEK,
                              TCM_KEY *tcm_key);

//get TCM_KEY_PRIV
//original func:  TCM_Key_LoadStoreAsymKey
TCM_RESULT TCM_Key_LoadPriv(TCM_KEY *tcm_key,
                            TCM_BOOL isEK,
                            unsigned char **stream,
                            uint32_t *stream_size);
//store pubkey to buffer
//original func:  TCM_Key_StorePubkey
TCM_RESULT TCM_Key_StoreKeyPubShort(TCM_STORE_BUFFER *keyShortStream,
                                    const unsigned char **keyShortStreamBuffer,
                                    uint32_t *keyShortStreamLength,
                                    TCM_KEY *tcm_key);







TCM_RESULT TCM_Key_GetKeyInfoPriv(TCM_KEY_PRIV **tcm_key_priv,
                                  TCM_KEY *tcm_key);
//Get TCM_KEY_PRIV structure point
//original func:  TCM_Key_GetMigrateAsymkey

TCM_RESULT TCM_Key_GetUsageAuth(TCM_SECRET **usageSecret,
                                TCM_KEY *tcm_key);
//Try to get migrateSecret in TCM_KEY_PRIV
//original func:  TCM_Key_GetMigrateAuth
TCM_RESULT TCM_Key_GetMigrateSecret(TCM_SECRET **migrateSecret,
                                    TCM_KEY *tcm_key);
//Try to get public key in TCM_KEY_PUB
//original func:  TCM_Key_GetPublicKey
TCM_RESULT TCM_Key_GetPublicKey(uint32_t	*nbytes,
                                unsigned char   **narr,
                                TCM_KEY  *tcm_key);
//dereference
//TCM_RESULT TCM_Key_GetPrimeFactorP(uint32_t 		*pbytes,
//                                   unsigned char        **parr,
//                                   TCM_KEY              *tcm_key);

//Try to get nativeKey in TCM_KEY_PRIV
//original func:  TCM_Key_GetPrivateKey
TCM_RESULT TCM_Key_GetNativeKey(uint32_t	*dbytes,
                                unsigned char  **darr,
                                TCM_KEY  *tcm_key);

//deference
//TCM_RESULT TCM_Key_CheckProperties(int *ver,
//                                   TCM_KEY *tcm_key,
//                                  uint32_t keyLength,
//                                  TCM_BOOL FIPS);

//Try to check if there is pcr protection in TCM_KEY_PUB
//original func:  TCM_Key_GetPCRUsage
TCM_RESULT TCM_Key_GetPCRUsage(TCM_BOOL *pcrUsage,
                               TCM_KEY *tcm_key,
                               size_t start_index);
//Get locality at release in TCM_KEY_PUB
//original func:  TCM_Key_GetLocalityAtRelease
TCM_RESULT TCM_Key_GetLocalityAtRelease(TCM_LOCALITY_SELECTION *localityAtRelease,
                                        TCM_KEY *tcm_key);
//original func: None
TCM_RESULT TCM_Key_GetAlgorithmID(TCM_ALGORITHM_ID *algID, TCM_KEY *tcm_key);
TCM_RESULT TCM_Key_GetAlgPubParamsStruct(TCM_ALG_PUB_PARAMS *algPubParams, TCM_KEY *tcm_key);
TCM_RESULT TCM_Key_CheckProperties(TCM_KEY *keyInfo, TCM_KEY_USAGE requiredKeyUsage,
                                   TCM_KEY_FLAGS requiredKeyFlags,
                                   uint32_t requiredKeyLength	/* in bits */);
/*
	TCM_KEY_PUB
*/


void       TCM_KeyPub_Init(TCM_KEY_PUB *tcm_key_pub);
//deserialize stream into TCM_KEY_PUB structure
//original func:TCM_Key_Load
TCM_RESULT TCM_KeyPub_Load(TCM_KEY_PUB *tcm_key_pub,
                           unsigned char **stream,
                           uint32_t *stream_size);

//deserialize stream into TCM_KEY_PUB structure excluding encData
//original func:TCM_Key_Load
TCM_RESULT TCM_KeyPub_LoadAttr(TCM_KEY_PUB *tcm_key_pub,
                               TCM_BOOL isEK,
                               unsigned char **stream,
                               uint32_t *stream_size);

//serialize TCM_KEY_PUB structure to a buffer
//original func:  TCM_Key_Store
TCM_RESULT TCM_KeyPub_Store(TCM_STORE_BUFFER *sbuffer, TCM_BOOL isEK,
                            TCM_KEY_PUB *tcm_key_pub);

//serialize TCM_KEY_PUB structure to a buffer excluding encData
//original func:  TCM_Key_StorePubData
TCM_RESULT TCM_KeyPub_StoreAttr(TCM_STORE_BUFFER *sbuffer,
                                TCM_BOOL isEK,
                                TCM_KEY_PUB *tcm_key_pub);//Excluding encData

//delete structure and buffer occupation in TCM_KEY structure
//original func:  TCM_Key_Delete
void       TCM_KeyPub_Delete(TCM_KEY_PUB *tcm_key);

//set TCM_KEY_PUB by parameters excluding encData
//original func:  TCM_Key_Set
TCM_RESULT TCM_KeyPub_Set(TCM_KEY_PUB *tcm_key_pub,
                          TCM_KEY_USAGE keyUsage,
                          TCM_KEY_FLAGS keyFlags,
                          TCM_AUTH_DATA_USAGE authDataUsage,
                          TCM_KEY_PARMS *keyInfo,
                          BYTE *publicKey);


//store pubkey to buffer
//original func:  TCM_Key_StorePubkey
TCM_RESULT TCM_KeyPub_StoreShort(TCM_STORE_BUFFER *keyShortStream,
                                 const unsigned char **keyShortStreamBuffer,
                                 uint32_t *keyShortStreamLength,
                                 TCM_KEY_PUB *tcm_key_pub);

//Serialize a TCM_PUBKEY derived from the TCM_KEY_PUB and calculates its digest.
//original func:  TCM_Key_GeneratePubkeyDigest
TCM_RESULT TCM_KeyPub_GenerateKeyPubShortDigest(TCM_DIGEST tcm_digest,
        TCM_KEY_PUB *tcm_key_pub);


//Try to get migrateSecret in TCM_KEY_PRIV
//original func:  TCM_Key_GetPublicKey
TCM_RESULT TCM_KeyPub_GetPublicKey(uint32_t	*nbytes,
                                   unsigned char   **narr,
                                   TCM_KEY_PUB  *tcm_key_pub);
//TCM_RESULT TCM_KeyPub_GetPubKeyBuf(TCM_SIZED_BUFFER **pubKey, TCM_KEY_PUB *tcm_key_pub);
//Try to get buffer (TCM_ALG_PUB_PARAMS) in TCM_KEY_PRIV
//original func:  TCM_Key_GetExponent
TCM_RESULT TCM_KeyPub_StorePubParamsAddr(TCM_ALG_PUB_PARAMS **algPubParams,
        TCM_KEY_PUB  *tcm_key_pub);



TCM_RESULT TCM_KeyPub_GetAlgorithmID(TCM_ALGORITHM_ID *algID, TCM_KEY_PUB *tcm_key_pub);
TCM_RESULT TCM_KeyPub_CheckProperties(TCM_KEY_PUB *tcm_key_pub, TCM_KEY_USAGE requiredKeyUsage,
                                      TCM_KEY_FLAGS requiredKeyFlags,
                                      uint32_t requiredKeyLength/* in bits */);


//original function: TCM_StoreAsymkey_Init
void       TCM_KeyPriv_Init(TCM_KEY_PRIV *tcm_key_priv);
//original function: TCM_StoreAsymkey_Load
TCM_RESULT TCM_KeyPriv_Load(TCM_KEY_PRIV *tcm_key_priv,
                            TCM_BOOL isEK,
                            unsigned char **stream,
                            uint32_t *stream_size,
                            TCM_ALGORITHM_ID algID,
                            TCM_ALG_PUB_PARAMS *algPubParams,//may be in silence according to algorithm
                            TCM_SIZED_BUFFER *pubKey);//may be in silence according to algorithm


//original function: TCM_StoreAsymkey_Store
TCM_RESULT TCM_KeyPriv_Store(TCM_STORE_BUFFER *sbuffer,
                             TCM_BOOL isEK,
                             TCM_KEY_PRIV *tcm_key_priv);
//original function: TCM_StoreAsymkey_Delete
void       TCM_KeyPriv_Delete(TCM_KEY_PRIV *tcm_key_priv);
//original function: TCM_StoreAsymkey_GenerateEncData
TCM_RESULT TCM_KeyPriv_GenerateEncData(TCM_SIZED_BUFFER *encData,
                                       TCM_KEY_PRIV *tcm_key_priv,
                                       TCM_KEY *parent_key);
//original function: TCM_StoreAsymkey_GetPrimeFactorP
TCM_RESULT TCM_KeyPriv_GetAlgPrivParams(uint32_t 		*pbytes,
                                        unsigned char       **parr,
                                        TCM_KEY_PRIV   *tcm_key_priv);

//Try to get nativeKey in TCM_KEY_PRIV
//original func:  TCM_Key_GetPrivateKey
TCM_RESULT TCM_KeyPriv_GetNativeKey(uint32_t	*dbytes,
                                    unsigned char  **darr,
                                    TCM_KEY_PRIV  *tcm_key_priv);

/*
  TCM_KEY_FLAGS
*/


TCM_RESULT TCM_KeyFlags_Load(TCM_KEY_FLAGS *tcm_key_flags,
                             unsigned char **stream,
                             uint32_t *stream_size);

void TCM_KeyParms_Init(TCM_KEY_PARMS *tcm_key_parms);

TCM_RESULT TCM_KeyParms_Load(TCM_KEY_PARMS *tcm_key_parms,	/* result */
                             unsigned char **stream,		/* pointer to next parameter */
                             uint32_t *stream_size);		/* stream size left */


TCM_RESULT TCM_KeyParms_Load(TCM_KEY_PARMS *tcm_key_parms,	/* result */
                             unsigned char **stream,		/* pointer to next parameter */
                             uint32_t *stream_size);		/* stream size left */

void TCM_KeyParms_Delete(TCM_KEY_PARMS *tcm_key_parms);
TCM_RESULT TCM_KeyParms_Store(TCM_STORE_BUFFER *sbuffer,
                              TCM_KEY_PARMS *tcm_key_parms);
TCM_RESULT TCM_KeyParms_Copy(TCM_KEY_PARMS *tcm_key_parms_dest,
                             TCM_KEY_PARMS *tcm_key_parms_src);

TCM_RESULT TCM_KeyParms_GetKeyParms(TCM_ALG_PUB_PARAMS *KeyParms,
                                    TCM_KEY_PARMS *keyInfo);

TCM_RESULT TCM_KeyParms_GetKeyLength(uint32_t *keyLength,
                                     TCM_KEY_PARMS *keyInfo);
TCM_RESULT TCM_KeyParms_GetAlgorithmID(TCM_ALGORITHM_ID *algID, TCM_KEY_PARMS *keyInfo);


void TCM_ALG_PUB_PARAMS_Init(TCM_ALG_PUB_PARAMS *algPubParams);

void TCM_ALG_PUB_PARAMS_Delete(TCM_ALG_PUB_PARAMS *algPubParams);


//original function: TCM_KeyParms_CheckProperties
TCM_RESULT TCM_KeyParms_CheckProperties(TCM_KEY_PARMS *keyInfo,  TCM_KEY_USAGE keyUsage, uint32_t requiredKeyLength);

/*
	TCM_CIPH_SCHM_ALG
*/

void TCM_AlgParams_Init(TCM_CIPH_SCHM_ALG *algorithm);
TCM_RESULT TCM_AlgParams_GetPubParams(TCM_ALG_PUB_PARAMS **algPubParams, TCM_CIPH_SCHM_ALG *algorithm);
TCM_RESULT TCM_AlgParams_GetAlgorithmID(TCM_ALGORITHM_ID *algID, TCM_CIPH_SCHM_ALG *algorithm);
TCM_RESULT TCM_AlgParams_Load(TCM_CIPH_SCHM_ALG *algorithm, unsigned char **stream, uint32_t *stream_size);
TCM_RESULT TCM_AlgParams_Store(TCM_STORE_BUFFER *sbuffer, TCM_CIPH_SCHM_ALG *algorithm);
TCM_RESULT TCM_AlgParams_Copy(TCM_CIPH_SCHM_ALG *algorithm_dest, TCM_CIPH_SCHM_ALG *algorithm_src);
//original function: TCM_KeyParms_SetRSA
TCM_RESULT TCM_AlgParams_SetSpecific(TCM_CIPH_SCHM_ALG *algorithm,  unsigned char *stream, uint32_t stream_size);
TCM_RESULT TCM_AlgParams_SetSM2(TCM_CIPH_SCHM_ALG *algorithm,
                                TCM_SM2_ASYMKEY_PARAMETERS *sm2PubParams);
TCM_RESULT TCM_AlgParams_SetSM4(TCM_CIPH_SCHM_ALG *algorithm,
                                TCM_SYMMETRIC_KEY_PARMS *sm4PubParams);

void TCM_AlgParams_Delete(TCM_CIPH_SCHM_ALG *algorithm);

/*
	TCM_SM2_PUB_PARAMS
*/
void TCM_SM2PubParams_Init(TCM_SM2_ASYMKEY_PARAMETERS *tcm_sm2_pub_params);

TCM_RESULT TCM_SM2PubParams_Load(TCM_SM2_ASYMKEY_PARAMETERS *tcm_sm2_pub_params,
                                 unsigned char **stream,
                                 uint32_t *stream_size);

TCM_RESULT TCM_SM2PubParams_Store(TCM_STORE_BUFFER *sbuffer,
                                  const TCM_SM2_ASYMKEY_PARAMETERS *tcm_sm2_pub_params);

void       TCM_SM2PubParams_Delete(TCM_SM2_ASYMKEY_PARAMETERS *tcm_sm2_pub_params);

TCM_RESULT TCM_SM2PubParams_Copy(TCM_SM2_ASYMKEY_PARAMETERS *tcm_sm2_pub_params_dest,
                                 TCM_SM2_ASYMKEY_PARAMETERS *tcm_sm2_key_params_src);





/*
	TCM_SM4_PUB_PARAMS
*/

void TCM_SM4PubParams_Init(TCM_SYMMETRIC_KEY_PARMS *sm4PubParams);
TCM_RESULT TCM_SM4PubParams_Store(TCM_STORE_BUFFER *sbuffer, TCM_SYMMETRIC_KEY_PARMS *sm4PubParams);
TCM_RESULT TCM_SM4PubParams_Load(TCM_SYMMETRIC_KEY_PARMS *tcm_sm4_pub_params,
                                 unsigned char **stream,
                                 uint32_t *stream_size);

TCM_RESULT TCM_SM4PubParams_Copy(TCM_SYMMETRIC_KEY_PARMS *tcm_sm4_pub_params_dest,
                                 TCM_SYMMETRIC_KEY_PARMS *tcm_sm4_key_params_src);
TCM_RESULT TCM_SM4PubParams_CheckIV(TCM_SYMMETRIC_KEY_PARMS *tcm_sm4_pub_params, TCM_ENC_SCHEME mode);

void       TCM_SM4PubParams_Delete(TCM_SYMMETRIC_KEY_PARMS *tcm_sm4_pub_params);



/*
	TCM_NATIVE_KEY
*/
void TCM_NativeKey_Init(TCM_NATIVE_KEY *nativeKey);
TCM_RESULT TCM_NativeKey_Load(TCM_NATIVE_KEY *nativeKey, unsigned char **stream,  uint32_t *stream_size);
TCM_RESULT TCM_NativeKey_Store(TCM_STORE_BUFFER *sbuffer, TCM_NATIVE_KEY *nativeKey);
void TCM_NativeKey_Delete(TCM_NATIVE_KEY *nativeKey);

/*TCM_CERTINFO*/
void TCM_CertInfo_Init(TCM_CERTINFO *certInfo);
TCM_RESULT TCM_CertInfo_Load(TCM_CERTINFO *certInfo, unsigned char **stream,  uint32_t *stream_size);
TCM_RESULT TCM_CertInfo_Store(TCM_STORE_BUFFER *sbuffer, TCM_CERTINFO *certInfo);
void TCM_CertInfo_Delete(TCM_CERTINFO *certInfo);

/* Command Processing Functions */

TCM_RESULT TCM_Key_GenerateSM2(TCM_KEY *tcm_key,
                               keydata *keyparms);
TCM_RESULT TCM_Key_GeneratePubDataDigest(TCM_KEY *tcm_key);

#endif
