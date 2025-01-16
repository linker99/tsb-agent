/********************************************************************************/

/********************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tcm_key.h"
#include "tcm_store.h"
#include "tcm.h"
#include "tcm_memory.h"
#include "tcm_sizedbuffer.h"
#include "tcmfunc.h"
#include "tcm_error.h"
#include "tcm_load.h"
#include "sm_if.h"

//x: object    l: length
#define Param_isLegal(x, l)	((x.size == l && x.buffer != NULL)?TRUE:FALSE)

//x: object
#define Param_isZero(x)   ((x.size == 0 && x.buffer == NULL)?TRUE:FALSE)

/*
	TCM_KEY
*/

//Key
void TCM_Key_Init(TCM_KEY *tcm_key)
{
    //	printf(" TCM_Key_Init:\n");
    TCM_KeyPub_Init(&(tcm_key->tcm_key_pub));
    tcm_key->tcm_key_priv = NULL;
    return;
}



//deserialize stream into TCM_KEY_PUB structure
//original func:TCM_Key_Load
TCM_RESULT TCM_Key_LoadPub(TCM_KEY *tcm_key,
                           unsigned char **stream,
                           uint32_t *stream_size)
{
    //	printf(" TCM_Key_Load(Pub):\n");
#ifdef TCM_USE_TAG_IN_STRUCTURE
    tcm_key->tag = TCM_TAG_KEY;
#endif
    return TCM_KeyPub_Load(&(tcm_key->tcm_key_pub), stream, stream_size);
}



//deserialize stream into TCM_KEY_PUB structure excluding encData
//original func:TCM_Key_LoadPubData
TCM_RESULT TCM_Key_LoadPubAttr(TCM_KEY *tcm_key,
                               TCM_BOOL isEK,
                               unsigned char **stream,
                               uint32_t *stream_size)
{
    //	printf(" TCM_Key_LoadPubAttr:\n");
    return TCM_KeyPub_LoadAttr(&(tcm_key->tcm_key_pub), isEK, stream, stream_size);
}

//serialize TCM_KEY_PUB structure to a buffer
//original func:  TCM_Key_Store

TCM_RESULT TCM_Key_StorePub(TCM_STORE_BUFFER *sbuffer, TCM_BOOL isEK,
                            TCM_KEY *tcm_key)
{
    //	printf(" TCM_Key_Store(Pub):\n");
    return TCM_KeyPub_Store(sbuffer, isEK, &(tcm_key->tcm_key_pub));
}
//serialize TCM_KEY_PUB structure to a buffer excluding encData
//original func:  TCM_Key_StorePubData
TCM_RESULT TCM_Key_StorePubAttr(TCM_STORE_BUFFER *sbuffer,
                                TCM_BOOL isEK,
                                TCM_KEY *tcm_key)
{
    //	printf(" TCM_Key_StorePubAttr:\n");
    return TCM_KeyPub_StoreAttr(sbuffer, isEK, &(tcm_key->tcm_key_pub));
}


//delete structure and buffer occupation in TCM_KEY structure
//original func:  TCM_Key_Delete
void       TCM_Key_Delete(TCM_KEY *tcm_key)
{
    //	printf("TCM_Key_Delete:\n");
    if(tcm_key != NULL) {
        TCM_KeyPub_Delete(&(tcm_key->tcm_key_pub));
        TCM_KeyPriv_Delete(tcm_key->tcm_key_priv);
        free((unsigned char *)tcm_key->tcm_key_priv);
        TCM_Key_Init(tcm_key);
    }
    return;
}


//Generate pubDataDigest and fill in the TCM_KEY
//original func:  TCM_Key_GeneratePubDataDigest
TCM_RESULT TCM_Key_GeneratePubDataDigest(TCM_KEY *tcm_key)
{
    TCM_RESULT		rc = 0;
    TCM_STORE_BUFFER	sbuffer;	/* TCM_KEY serialization */
    TCM_KEY_PRIV	*tcm_key_priv;

    //	printf(" TCM_Key_GeneratePubDataDigest:\n");
    TCM_Sbuffer_Init(&sbuffer);			/* freed @1 */
    /* serialize the TCM_KEY excluding the encData fields */
    if (rc == 0) {
        rc = TCM_KeyPub_StoreAttr(&sbuffer, FALSE, &(tcm_key->tcm_key_pub));
    }
    /* get the TCM_KEY_PRIV structure */
    if (rc == 0) {
        rc = TCM_Key_GetKeyInfoPriv(&tcm_key_priv, tcm_key);
    }
    /* hash the serialized buffer to pubDataDigest */
    if (rc == 0) {
        TSS_sm3(sbuffer.buffer, sbuffer.buffer_current - sbuffer.buffer, tcm_key_priv->pubDataDigest);
    }
    TCM_Sbuffer_Delete(&sbuffer);	/* @1 */
    return rc;
}


TCM_RESULT TCM_Key_Set(TCM_KEY *tcm_key,//out
                       TCM_KEY_USAGE keyUsage,				/* input */
                       TCM_KEY_FLAGS keyFlags,				/* input */
                       TCM_AUTH_DATA_USAGE authDataUsage,		/* input */
                       TCM_KEY_PARMS *keyInfo,			/* input */
                       BYTE *publickey,			/* public key byte array */
                       TCM_KEY_PRIV *tcm_key_priv) /* cache TCM_KEY_PRIV */
{
    //	printf("TCM_Key_Set:\n");
    TCM_RESULT rc = 0;
    TCM_STORE_BUFFER sbuffer;
    TCM_Sbuffer_Init(&sbuffer);
    rc = TCM_KeyPub_Set(&(tcm_key->tcm_key_pub), keyUsage, keyFlags, authDataUsage, keyInfo, publickey);
    /*
    if(rc == 0) {
    	tcm_key->tcm_key_priv = tcm_key_priv;
    	if(parent_key == NULL){//root key, no parent key, just serialize the TCM_KEY_PRIV structure
    		if (rc == 0) {
    			rc = TCM_KeyPriv_Store(&sbuffer, FALSE, tcm_key_priv);
    		}
    		if (rc == 0) {
    			rc = TCM_SizedBuffer_SetFromStore(&(tcm_key->tcm_key_pub.encData), &sbuffer);
    		}
    	}
    }
    */
    if(rc == 0) {
        TCM_Key_GeneratePubDataDigest(tcm_key);
    }
    TCM_Sbuffer_Delete(&sbuffer);
    return rc;
}
//serialize TCM_KEY structure to a buffer
//original func:  TCM_Key_StoreClear
TCM_RESULT TCM_Key_StoreClear(TCM_STORE_BUFFER *sbuffer,
                              TCM_BOOL isEK,
                              TCM_KEY *tcm_key)
{
    TCM_RESULT		rc = 0;
    TCM_STORE_BUFFER	privSbuffer;
    const unsigned char *privStream;
    uint32_t		privLength;

    //    printf(" TCM_Key_StoreClear:\n");
    TCM_Sbuffer_Init(&privSbuffer);			/* freed @1 */
    /* store the pubData */
    if (rc == 0) {
        rc = TCM_Key_StorePubAttr(sbuffer, isEK, tcm_key);
    }
    /* store TCM_KEY_PRIV cache as cleartext */
    if (rc == 0) {
        /* if the TCM_KEY_PRIV cache exists */
        if (tcm_key->tcm_key_priv != NULL) {
            /* , serialize it */
            if (rc == 0) {
                rc = TCM_KeyPriv_Store(&privSbuffer, isEK, tcm_key->tcm_key_priv);
            }
            /* get the result */
            TCM_Sbuffer_Get(&privSbuffer, &privStream, &privLength);
            /* store the result as a sized buffer */
            if (rc == 0) {
                rc = TCM_Sbuffer_Append32(sbuffer, privLength);
            }
            if (rc == 0) {
                rc = TCM_Sbuffer_Append(sbuffer, privStream, privLength);
            }
        }
        /* If there is no TCM_KEY_PRIV cache, mark it empty.  This can occur for an internal
           key that has not been created yet.  */
        else {
            rc = TCM_Sbuffer_Append32(sbuffer, 0);
        }
    }
    TCM_Sbuffer_Delete(&privSbuffer);			/* @1 */
    return rc;
}

//get TCM_KEY_PRIV
//original func:  TCM_Key_LoadStoreAsymKey
TCM_RESULT TCM_Key_LoadPriv(TCM_KEY *tcm_key,
                            TCM_BOOL isEK,
                            unsigned char **stream,
                            uint32_t *stream_size)
{
    TCM_ALG_PUB_PARAMS algPubParams ;
    TCM_SIZED_BUFFER *pubKey;
    TCM_ALGORITHM_ID algID = 0;
    TCM_RESULT	rc = 0;
    /* This function should never be called when the TCM_KEY_PRIV structure has already been
       loaded.	This indicates an internal error. */
    //    printf(" TCM_Key_LoadPriv:\n");
    if (rc == 0) {
        if (tcm_key->tcm_key_priv != NULL) {
            printf("TCM_Key_LoadPriv: Error (fatal), TCM_KEY_PRIV already loaded\n");
            rc = ERR_BAD_ARG;	/* should never occur */
        }
    }
    /* If the stream size is 0, there is an internal error. */
    if (rc == 0) {
        if (*stream_size == 0) {
            printf("TCM_Key_LoadPriv: Error (fatal), stream size is 0\n");
            rc = ERR_BAD_ARG;	/* should never occur */
        }
    }
    /* allocate memory for the structure */
    if (rc == 0) {
        rc = TCM_Malloc((unsigned char **) & (tcm_key->tcm_key_priv),
                        sizeof(TCM_KEY_PRIV));
    }
    if(rc == 0) {
        rc = TCM_KeyParms_GetKeyParms(&algPubParams, &(tcm_key->tcm_key_pub.algorithmParms));
    }
    if(rc == 0) {
        rc = TCM_Key_GetAlgorithmID(&algID, tcm_key);
    }
    pubKey = &(tcm_key->tcm_key_pub.pubKey);
    if (rc == 0) {
        TCM_KeyPriv_Init(tcm_key->tcm_key_priv);
        //		rc = TCM_KeyPriv_Load(tcm_key->tcm_key_priv, isEK,
        //				   stream, stream_size, algID,
        //				   algPubParams, pubKey);

    }
    return rc;
}
//store pubkey to buffer
//original func:  TCM_Key_StorePubkey
TCM_RESULT TCM_Key_StoreKeyPubShort(TCM_STORE_BUFFER *keyShortStream,
                                    const unsigned char **keyShortStreamBuffer,
                                    uint32_t *keyShortStreamLength,
                                    TCM_KEY *tcm_key)
{
    //	printf("TCM_Key_StoreKeyPubShort:\n");
    return TCM_KeyPub_StoreShort(keyShortStream, keyShortStreamBuffer, keyShortStreamLength, &(tcm_key->tcm_key_pub));
}






//Get TCM_KEY_PRIV structure point
//original func:  TCM_Key_GetStoreAsymkey
TCM_RESULT TCM_Key_GetKeyInfoPriv(TCM_KEY_PRIV **tcm_key_priv,
                                  TCM_KEY *tcm_key)
{

    TCM_RESULT		rc = 0;
    //	printf("TCM_Key_GetKeyInfoPriv:\n");
    if (rc == 0) {
        /* return the cached structure */
        *tcm_key_priv = tcm_key->tcm_key_priv;
        //if (*tcm_key_priv == NULL) {
        //	printf("TCM_Key_GetKeyInfoPriv: Error (fatal), no cache\n");
        //	rc = TCM_FAIL;	/* indicate no cache */
        //}
    }
    return rc;
}

//Try to get public key in TCM_KEY_PUB
//original func:  TCM_Key_GetPublicKey
TCM_RESULT TCM_Key_GetPublicKey(uint32_t	*nbytes,
                                unsigned char   **narr,
                                TCM_KEY  *tcm_key)
{
    //	printf(" TCM_Key_GetPublicKey:\n");
    return TCM_KeyPub_GetPublicKey(nbytes, narr, &(tcm_key->tcm_key_pub));
}
//dereference
//TCM_RESULT TCM_Key_GetPrimeFactorP(uint32_t 		*pbytes,
//                                   unsigned char        **parr,
//                                   TCM_KEY              *tcm_key);

//Try to get nativeKey in TCM_KEY_PRIV
//original func:  TCM_Key_GetPrivateKey
TCM_RESULT TCM_Key_GetNativeKey(uint32_t	*dbytes,
                                unsigned char  **darr,
                                TCM_KEY  *tcm_key)
{
    TCM_RESULT rc = 0;
    //	printf("TCM_Key_GetNativeKey:\n");
    TCM_KEY_PRIV *tcm_key_priv;
    rc = TCM_Key_GetKeyInfoPriv(&tcm_key_priv, tcm_key);
    if(rc == 0) {
        rc = TCM_KeyPriv_GetNativeKey(dbytes, darr, tcm_key_priv);
    }
    return rc;
}



TCM_RESULT TCM_Key_GetAlgorithmID(TCM_ALGORITHM_ID *algID, TCM_KEY *tcm_key)
{
    //	printf("TCM_Key_GetAlgorithmID:\n");
    return TCM_KeyPub_GetAlgorithmID(algID, &(tcm_key->tcm_key_pub));
}
TCM_RESULT TCM_Key_GetAlgPubParamsStruct(TCM_ALG_PUB_PARAMS *algPubParams, TCM_KEY *tcm_key)
{
    TCM_RESULT rc = 0;
    //	printf("TCM_Key_GetAlgPubParamsStruct:\n");
    rc = TCM_KeyParms_GetKeyParms(algPubParams, &(tcm_key->tcm_key_pub.algorithmParms));
    return rc;
}

/* TCM_Key_CheckProperties() checks that the TCM can generate a key of the type requested in
   'TCM_key'.

   if keyLength is non-zero, checks that the TCM_key specifies the correct key length.  If keyLength
   is 0, any TCM_key key length is accepted.

   Returns TCM_BAD_KEY_PROPERTY on error.
 */

TCM_RESULT TCM_Key_CheckProperties(TCM_KEY *keyInfo, TCM_KEY_USAGE requiredKeyUsage,
                                   TCM_KEY_FLAGS requiredKeyFlags,
                                   uint32_t requiredKeyLength	/* in bits */)
{
    TCM_RESULT	rc = 0;

    //   printf(" TCM_Key_CheckProperties:\n");
    /* most of the work is done by TCM_KeyPub_CheckProperties() */
    if (rc == 0) {
        rc = TCM_KeyPub_CheckProperties(&(keyInfo->tcm_key_pub), requiredKeyUsage, requiredKeyFlags, requiredKeyLength);
    }
    return rc;
}


/*
	TCM_KEY_PUB
*/


void TCM_KeyPub_Init(TCM_KEY_PUB *tcm_key_pub)
{
    //	printf(" TCM_KeyPub_init:\n");
    tcm_key_pub->tag =  TCM_TAG_KEY;
    tcm_key_pub->fill = 0x0000;
    tcm_key_pub->keyUsage = TCM_KEY_USG_UNINITIALIZED;
    tcm_key_pub->keyFlags = TCM_KEY_FLG_UNINITIALIZED;
    tcm_key_pub->authDataUsage = TCM_AUTH_NEVER;
    TCM_KeyParms_Init(&(tcm_key_pub->algorithmParms));
    tcm_key_pub->tcm_pcr_info = NULL;
    TCM_SizedBuffer_Init(&(tcm_key_pub->pcrInfo));
    TCM_SizedBuffer_Init(&(tcm_key_pub->pubKey));
    TCM_SizedBuffer_Init(&(tcm_key_pub->encData));
    return;
}
//deserialize stream into TCM_KEY_PUB structure
//original func:TCM_Key_Load
TCM_RESULT TCM_KeyPub_Load(TCM_KEY_PUB *tcm_key_pub,
                           unsigned char **stream,
                           uint32_t *stream_size)
{
    TCM_RESULT		rc = 0;

    //	printf(" TCM_KeyPub_Load:\n");
    /* load public data, and create PCR cache */
    if (rc == 0) {
        rc = TCM_KeyPub_LoadAttr(tcm_key_pub, FALSE, stream, stream_size);
    }
    /* load encDataSize and encData */
    if (rc == 0) {
        rc = TCM_SizedBuffer_Load(&(tcm_key_pub->encData), stream, stream_size);
    }
    return rc;
}

//serialize TCM_KEY_PUB structure to a buffer
//original func:  TCM_Key_Store
TCM_RESULT TCM_KeyPub_Store(TCM_STORE_BUFFER *sbuffer, TCM_BOOL isEK,
                            TCM_KEY_PUB *tcm_key_pub)
{
    TCM_RESULT	rc = 0;

    //	printf(" TCM_KeyPub_Store:\n");
    /* store the pubData */
    if (rc == 0) {
        rc = TCM_KeyPub_StoreAttr(sbuffer, isEK, tcm_key_pub);
    }
    /* store encDataSize and encData */
    if (rc == 0) {
        rc = TCM_SizedBuffer_Store(sbuffer, &(tcm_key_pub->encData));
    }
    return rc;

}



//deserialize stream into TCM_KEY_PUB structure excluding encData
//original func:TCM_Key_LoadPubData
TCM_RESULT TCM_KeyPub_LoadAttr(TCM_KEY_PUB *tcm_key_pub,
                               TCM_BOOL isEK,
                               unsigned char **stream,
                               uint32_t *stream_size)
{
    TCM_RESULT		rc = 0;

    //   printf(" TCM_KeyPub_LoadAttr:\n");

    /* load tag */
    if (rc == 0) {
        rc = TCM_Load16(&(tcm_key_pub->tag), stream, stream_size);
        printf("tag:%08x", tcm_key_pub->tag);
    }
    /* load fill */
    if (rc == 0) {
        rc = TCM_Load16(&(tcm_key_pub->fill), stream, stream_size);
        printf("fill:%08x", tcm_key_pub->fill);
    }

    /* load keyUsage */
    if (rc == 0) {
        rc = TCM_Load16(&(tcm_key_pub->keyUsage), stream, stream_size);
        printf("keyUsage:%08x", tcm_key_pub->keyUsage);
    }
    /* load keyFlags */
    if (rc == 0) {
        rc = TCM_KeyFlags_Load(&(tcm_key_pub->keyFlags), stream, stream_size);
        printf("keyFlags:%08x", tcm_key_pub->keyFlags);
    }
    /* load authDataUsage */
    if (rc == 0) {
        rc = TCM_Load8(&(tcm_key_pub->authDataUsage), stream, stream_size);
    }
    /* load algorithmParms */
    if (rc == 0) {
        rc = TCM_KeyParms_Load(&(tcm_key_pub->algorithmParms), stream, stream_size);
    }
    /* load PCRInfo */
    if ((rc == 0) && !isEK) {
        rc = TCM_SizedBuffer_Load(&(tcm_key_pub->pcrInfo), stream, stream_size);
    }
    /* set TCM_PCR_INFO TCM_pcr_info cache from PCRInfo stream.	 If the stream is empty, a NULL is
       returned.
    */
    if ((rc == 0) && !isEK) {
        //	    rc = TCM_PCRInfo_CreateFromBuffer(&(tcm_key_pub->tcm_pcr_info),
        //				      &(tcm_key_pub->pcrInfo));
    }
    /* load pubKey */
    if (rc == 0) {
        rc = TCM_SizedBuffer_Load(&(tcm_key_pub->pubKey), stream, stream_size);
    }
    return rc;
}


TCM_RESULT TCM_KeyPub_StoreAttr(TCM_STORE_BUFFER *sbuffer,
                                TCM_BOOL isEK,
                                TCM_KEY_PUB *tcm_key_pub)//Excluding encData
{
    TCM_RESULT	rc = 0;

    //	printf(" TCM_KeyPub_StoreAttr:\n");
    if (rc == 0) {
        rc = TCM_Sbuffer_Append16(sbuffer, tcm_key_pub->tag);
    }
    if (rc == 0) {
        rc = TCM_Sbuffer_Append16(sbuffer, tcm_key_pub->fill);
    }
    /* store keyUsage */
    if (rc == 0) {
        rc = TCM_Sbuffer_Append16(sbuffer, tcm_key_pub->keyUsage);
    }
    /* store keyFlags */
    if (rc == 0) {
        rc = TCM_Sbuffer_Append32(sbuffer, tcm_key_pub->keyFlags);
    }
    /* store authDataUsage */
    if (rc == 0) {
        rc = TCM_Sbuffer_Append(sbuffer, &(tcm_key_pub->authDataUsage), sizeof(TCM_AUTH_DATA_USAGE));
    }
    /* store algorithmParms */
    if (rc == 0) {
        rc = TCM_KeyParms_Store(sbuffer, &(tcm_key_pub->algorithmParms));
    }
    /* store pcrInfo */
    if ((rc == 0) && !isEK) {
        /* copy cache to pcrInfo */
        /*		rc = TCM_SizedBuffer_SetStructure(&(tcm_key_pub->pcrInfo),
        			tcm_key_pub->tcm_pcr_info,
        			(TCM_STORE_FUNCTION_T)TCM_PCRInfo_Store);
        			*/
    }
    /* copy pcrInfo to sbuffer */
    if ((rc == 0) && !isEK) {
        rc = TCM_SizedBuffer_Store(sbuffer, &(tcm_key_pub->pcrInfo));
    }
    /* store pubKey */
    if (rc == 0) {
        rc = TCM_SizedBuffer_Store(sbuffer, &(tcm_key_pub->pubKey));
    }
    return rc;
}


//delete structure and buffer occupation in TCM_KEY structure
//original func:  TCM_Key_Delete
void       TCM_KeyPub_Delete(TCM_KEY_PUB *tcm_key_pub)
{
    if (tcm_key_pub != NULL) {
        //		printf(" TCM_KeyPub_Delete:\n");
        TCM_KeyParms_Delete(&(tcm_key_pub->algorithmParms));
        /* pcrInfo */
        TCM_SizedBuffer_Delete(&(tcm_key_pub->pcrInfo));
        /* pcr caches */
        //
        //		TCM_PCRInfo_Delete(tcm_key_pub->tcm_pcr_info);
        free(tcm_key_pub->tcm_pcr_info);
        TCM_SizedBuffer_Delete(&(tcm_key_pub->pubKey));
        TCM_SizedBuffer_Delete(&(tcm_key_pub->encData));
        TCM_KeyPub_Init(tcm_key_pub);
    }
    return;
}

//set TCM_KEY_PUB by parameters excluding encData
//original func:  TCM_Key_Set
TCM_RESULT TCM_KeyPub_Set(TCM_KEY_PUB *tcm_key_pub,
                          TCM_KEY_USAGE keyUsage,
                          TCM_KEY_FLAGS keyFlags,
                          TCM_AUTH_DATA_USAGE authDataUsage,
                          TCM_KEY_PARMS *keyInfo,
                          BYTE *publicKey)
{

    TCM_RESULT rc = 0;
    TCM_ALGORITHM_ID algID = 0;
    uint32_t length = 0;
    uint32_t keyLength = 0;

    //	printf("TCM_KeyPub_Set:\n");

    tcm_key_pub->tag =  TCM_TAG_KEY;
    tcm_key_pub->fill = 0x0000;
    tcm_key_pub->keyFlags = keyFlags;
    tcm_key_pub->keyUsage = keyUsage;
    tcm_key_pub->authDataUsage = authDataUsage;
    rc = TCM_KeyParms_Copy(&(tcm_key_pub->algorithmParms), keyInfo);
    if(rc == 0) {
        rc = TCM_KeyParms_GetKeyLength(&keyLength, keyInfo);
    }

    if(rc == 0) {
        rc = TCM_KeyPub_GetAlgorithmID(&algID, tcm_key_pub);
        if(rc == 0) {
            switch (algID) {
            case TCM_ALG_SM2:
                length = keyLength / 4;
                break;
            case TCM_ALG_SM4:
                length = 0;
                break;
            default:
                rc = TCM_UNSUPPORT_ALG;
                break;
            }
        }
    }
    if(rc == 0) {
        rc = TCM_SizedBuffer_Set(&(tcm_key_pub->pubKey), length, publicKey);
    }

    return rc;

}


//store pubkey to buffer
//original func:  TCM_Key_StorePubkey
TCM_RESULT TCM_KeyPub_StoreShort(TCM_STORE_BUFFER *keyShortStream,
                                 const unsigned char **keyShortStreamBuffer,
                                 uint32_t *keyShortStreamLength,
                                 TCM_KEY_PUB *tcm_key_pub)
{
    TCM_RESULT	rc = 0;

    //	printf(" TCM_KeyPub_StoreShort:\n");
    /* the first part is a TCM_CIPHER_SCHEME */
    if (rc == 0) {
        rc = TCM_KeyParms_Store(keyShortStream, &(tcm_key_pub->algorithmParms));
    }
    /* the second part is the TCM_SIZED_BUFFER pubKey */
    if (rc == 0) {
        rc = TCM_SizedBuffer_Store(keyShortStream, &(tcm_key_pub->pubKey));
    }
    /* retrieve the resulting pubkey stream */
    if (rc == 0) {
        TCM_Sbuffer_Get(keyShortStream,
                        keyShortStreamBuffer,
                        keyShortStreamLength);
    }
    return rc;
}


//Serialize a TCM_PUBKEY derived from the TCM_KEY_PUB and calculates its digest.
//original func:  TCM_Key_GeneratePubkeyDigest
TCM_RESULT TCM_KeyPub_GenerateKeyPubShortDigest(TCM_DIGEST tcm_digest,
        TCM_KEY_PUB *tcm_key_pub)
{
    TCM_RESULT		rc = 0;
    TCM_STORE_BUFFER	keyShortStream;		/* from tcm_key_pub */
    const unsigned char *keyShortStreamBuffer;
    uint32_t		keyShortStreamLength;

    //	printf(" TCM_KeyPub_GenerateKeyPubShortDigest:\n");
    TCM_Sbuffer_Init(&keyShortStream);		/* freed @1 */
    /* serialize a TCM_ derived from the TCM_KEY */
    if (rc == 0) {
        rc = TCM_KeyPub_StoreShort(&keyShortStream,		/* output */
                                   &keyShortStreamBuffer,	/* output */
                                   &keyShortStreamLength,	/* output */
                                   tcm_key_pub);		/* input */
    }
    if (rc == 0) {
        TSS_sm3((void *)keyShortStreamBuffer, keyShortStreamLength, tcm_digest);
    }
    TCM_Sbuffer_Delete(&keyShortStream);		/* @1 */
    return rc;
}


//Try to get migrateSecret in TCM_KEY_PRIV
//original func:  TCM_Key_GetPublicKey
TCM_RESULT TCM_KeyPub_GetPublicKey(uint32_t	*nbytes,
                                   unsigned char   **narr,
                                   TCM_KEY_PUB  *tcm_key_pub)
{
    TCM_RESULT	 rc = 0;
    //	printf(" TCM_KeyPub_GetPublicKey:\n");
    if (rc == 0) {
        *nbytes = tcm_key_pub->pubKey.size;
        *narr = tcm_key_pub->pubKey.buffer;
    }
    return rc;
}


TCM_RESULT TCM_KeyPub_GetAlgorithmID(TCM_ALGORITHM_ID *algID, TCM_KEY_PUB *tcm_key_pub)
{
    //	printf("TCM_KeyPub_GetAlgorithmID:\n");
    return TCM_KeyParms_GetAlgorithmID(algID, &(tcm_key_pub->algorithmParms));
}

TCM_RESULT TCM_KeyPub_CheckProperties(TCM_KEY_PUB *tcm_key_pub, TCM_KEY_USAGE requiredKeyUsage,
                                      TCM_KEY_FLAGS requiredKeyFlags,
                                      uint32_t requiredKeyLength	/* in bits */)
{
    TCM_RESULT	rc = 0;
    TCM_KEY_USAGE keyUsage = TCM_KEY_USG_UNINITIALIZED;
    TCM_KEY_FLAGS keyFlags = TCM_KEY_FLG_UNINITIALIZED;
    TCM_ALGORITHM_ID alg = 0;
    uint32_t keyLength = 0;
    //	printf(" TCM_KeyPub_CheckProperties:\n");
    /* most of the work is done by TCM_KeyParms_CheckProperties() */
    keyUsage = tcm_key_pub->keyUsage;
    keyFlags = tcm_key_pub->keyFlags;
    if(rc == 0 && requiredKeyUsage != 0)	{
        if(keyUsage != requiredKeyUsage) {
            printf("TCM_KeyPub_CheckProperties: Error, Bad keyUsage should be %u, was %u\n", requiredKeyUsage, keyUsage);
            rc = TCM_BAD_KEY_PROPERTY;
        }
    }

    if(rc == 0 && requiredKeyFlags != 0) {
        if((keyFlags & (~TCM_KEY_FLG_MASK)) != 0 || (keyFlags & requiredKeyFlags) != ((requiredKeyFlags & TCM_KEY_FLG_NOT_REQUIRED) ? 0 : requiredKeyFlags)) {
            printf("TCM_KeyPub_CheckProperties: Error, Bad keyFlags, should be %u, was %u\n", requiredKeyFlags, keyFlags);
            rc = TCM_BAD_KEY_PROPERTY;
        }
    }


    if(rc == 0) {
        switch(keyUsage) {
        case TCM_SM4KEY_STORAGE:
        case TCM_SM4KEY_BIND:
            if(tcm_key_pub->algorithmParms.algorithmID != TCM_ALG_SM4) {
                rc = TCM_BAD_KEY_PROPERTY;
                printf("TCM_KeyPub_CheckProperties : bad keyType %04hx\n", tcm_key_pub->algorithmParms.algorithmID);
            }

            break;
        case TCM_SM4KEY_MIGRATION:
            if(tcm_key_pub->algorithmParms.algorithmID != TCM_ALG_SM4) {
                rc = TCM_BAD_KEY_PROPERTY;
                printf("TCM_KeyPub_CheckProperties : bad keyType %04hx\n", tcm_key_pub->algorithmParms.algorithmID);
            }
            if(keyFlags & TCM_KEY_FLG_MIGRATABLE) {
                rc = TCM_BAD_KEY_PROPERTY;
                printf("TCM_KeyPub_CheckProperties : bad key flags %04hx\n", keyFlags);
            }
            break;
        case TCM_SM2KEY_SIGNING:
        case TCM_SM2KEY_MIGRATION:
        case TCM_SM2KEY_BIND:
        case TCM_SM2KEY_STORAGE:
        case TCM_SM2KEY_PEK:
            if(tcm_key_pub->algorithmParms.algorithmID != TCM_ALG_SM2) {
                rc = TCM_BAD_KEY_PROPERTY;
                printf("TCM_KeyPub_CheckProperties : bad keyType %04hx\n", tcm_key_pub->algorithmParms.algorithmID);
            }
            break;
        case TCM_SM2KEY_IDENTITY:
            if(tcm_key_pub->algorithmParms.algorithmID != TCM_ALG_SM2) {
                rc = TCM_BAD_KEY_PROPERTY;
                printf("TCM_KeyPub_CheckProperties : bad keyType %04hx\n", tcm_key_pub->algorithmParms.algorithmID);
            }
            if(keyFlags & TCM_KEY_FLG_MIGRATABLE) {
                rc = TCM_BAD_KEY_PROPERTY;
                printf("TCM_KeyPub_CheckProperties : bad key flags %04hx\n", keyFlags);
            }
            break;
        default:
            rc = TCM_BAD_KEY_PROPERTY;
            printf("TCM_KeyPub_CheckProperties : bad key properties\n");
            break;
        }
    }
    if (rc == 0) {
        rc = TCM_KeyParms_CheckProperties(&(tcm_key_pub->algorithmParms), keyUsage, requiredKeyLength);
    }
    if(rc == 0)
        rc = TCM_KeyParms_GetAlgorithmID(&alg, &(tcm_key_pub->algorithmParms));
    if(rc == 0)
        rc = TCM_KeyParms_GetKeyLength(&keyLength, &(tcm_key_pub->algorithmParms));
    if(rc == 0) {
        switch(alg) {
        case TCM_ALG_SM2:
            if(tcm_key_pub->pubKey.size != 0 && keyLength != (tcm_key_pub->pubKey.size << 2)) {
                printf("TCM_KeyPub_CheckProperties: pubKey (X,Y) each has %d bits, not equal to %d\n", tcm_key_pub->pubKey.size << 2, keyLength);
                rc = TCM_BAD_KEY_PROPERTY;
            }
            break;
        case TCM_ALG_SM4:
            if(tcm_key_pub->pubKey.size) {
                printf("TCM_KeyPub_CheckProperties: symetric key has no pubkey\n");
                rc = TCM_BAD_KEY_PROPERTY;
            }
            break;
        default:
            printf("Unsupported algorithm\n");
            rc = TCM_BAD_KEY_PROPERTY;
            break;
        }
    }
    return rc;
}

/*
	TCM_KEY_PRIV
*/

void TCM_Secret_Init(TCM_SECRET tcm_secret)
{
    //   printf("  TCM_Secret_Init:\n");
    memset(tcm_secret, 0, TCM_SECRET_SIZE);
    return;
}

void TCM_Digest_Init(TCM_DIGEST tcm_digest)
{
    //   printf("  TCM_Digest_Init:\n");
    memset(tcm_digest, 0, TCM_DIGEST_SIZE);
    return;
}



TCM_RESULT TCM_Secret_Store(TCM_STORE_BUFFER *sbuffer,
                            const TCM_SECRET tcm_secret)
{
    TCM_RESULT rc = 0;

    //    printf("  TCM_Secret_Store:\n");
    rc = TCM_Sbuffer_Append(sbuffer, tcm_secret, TCM_SECRET_SIZE);
    return rc;
}

TCM_RESULT TCM_Digest_Store(TCM_STORE_BUFFER *sbuffer,
                            const TCM_DIGEST tcm_digest)
{
    TCM_RESULT	rc = 0;

    //    printf("  TCM_Digest_Store:\n");
    rc = TCM_Sbuffer_Append(sbuffer, tcm_digest, TCM_DIGEST_SIZE);
    return rc;
}


//original function: TCM_StoreAsymkey_Init
void       TCM_KeyPriv_Init(TCM_KEY_PRIV *tcm_key_priv)
{
    //	printf(" TCM_KeyPriv_Init:\n");
    tcm_key_priv->payloadType = 0x01; //TCM_PT_ASYM
    TCM_Secret_Init(tcm_key_priv->usageSecret);
    TCM_Secret_Init(tcm_key_priv->migrationSecret);
    TCM_Digest_Init(tcm_key_priv->pubDataDigest);
    TCM_NativeKey_Init(&(tcm_key_priv->nativeKey));
    TCM_SizedBuffer_Init(&(tcm_key_priv->algPrivParams));
    tcm_key_priv->tcm_alg_priv_params = NULL;
    return;
}


//original function: TCM_StoreAsymkey_Store
TCM_RESULT TCM_KeyPriv_Store(TCM_STORE_BUFFER *sbuffer,
                             TCM_BOOL isEK,
                             TCM_KEY_PRIV *tcm_key_priv)
{
    TCM_RESULT	rc = 0;

    //	printf(" TCM_KeyPriv_Store:\n");
    /* store payload */
    if ((rc == 0) && !isEK) {
        rc = TCM_Sbuffer_Append(sbuffer, &(tcm_key_priv->payloadType), sizeof(TCM_PAYLOAD_TYPE));
    }
    /* store usageAuth */
    if ((rc == 0) && !isEK) {
        rc = TCM_Secret_Store(sbuffer, tcm_key_priv->usageSecret);
    }
    /* store migrationAuth */
    if ((rc == 0) && !isEK) {
        rc = TCM_Secret_Store(sbuffer, tcm_key_priv->migrationSecret);
    }
    /* store pubDataDigest */
    if (rc == 0) {
        rc = TCM_Digest_Store(sbuffer, tcm_key_priv->pubDataDigest);
    }
    /* store NaitveKey */
    if (rc == 0) {
        rc = TCM_NativeKey_Store(sbuffer, &(tcm_key_priv->nativeKey));
    }
    if (rc == 0 && tcm_key_priv->tcm_alg_priv_params == NULL) {//always succeed
        rc = TCM_SizedBuffer_Store(sbuffer, &(tcm_key_priv->algPrivParams));
    }
    return rc;
}
//original function: TCM_StoreAsymkey_Delete
void       TCM_KeyPriv_Delete(TCM_KEY_PRIV *tcm_key_priv)
{
    //	printf("TCM_KeyPriv_Delete:\n");
    if(tcm_key_priv != NULL) {
        TCM_NativeKey_Delete(&(tcm_key_priv->nativeKey));
        TCM_SizedBuffer_Delete(&tcm_key_priv->algPrivParams);
        //temporarily TCM_ALG_PRIV_PARAMS hasn't been used, handle it as void
        free(tcm_key_priv->tcm_alg_priv_params);
        TCM_KeyPriv_Init(tcm_key_priv);
    }
    return;
}
//original function: TCM_StoreAsymkey_GenerateEncData
TCM_RESULT TCM_KeyPriv_GenerateEncData(TCM_SIZED_BUFFER *encData,
                                       TCM_KEY_PRIV *tcm_key_priv,
                                       TCM_KEY *parent_key)
{
    TCM_RESULT		rc = 0;
    TCM_STORE_BUFFER	sbuffer;
    TCM_SIZED_BUFFER sizedBuffer;
    TCM_ALGORITHM_ID algID = 0;
    //	printf(" TCM_KeyPriv_GenerateEncData;\n");
    TCM_Sbuffer_Init(&sbuffer);			/* freed @1 */
    TCM_SizedBuffer_Init(&sizedBuffer);    /* freed @2 */
    /* serialize the TCM_KEY_PRIV member */
    if (rc == 0) {
        rc = TCM_KeyPriv_Store(&sbuffer, FALSE, tcm_key_priv);
    }
    if(rc == 0) {
        rc = TCM_SizedBuffer_SetFromStore(&sizedBuffer, &sbuffer);
    }
    if (rc == 0) {
        rc = TCM_Key_GetAlgorithmID(&algID, parent_key);
    }
    if (rc == 0) {
        //		rc = TCM_EncryptSbuffer_Key(encData, &sizedBuffer, parent_key);
#if 0
        switch(algID) {
        case TCM_ALG_SM2:
            rc = TCM_EncryptSbuffer_Key(encData, &sizedBuffer, parent_key, (TCM_ENCRYPT_FUNCTION_T)TCM_SM2PublicEncrypt_Key);
            break;
        case TCM_ALG_SM4:
            rc = TCM_EncryptSbuffer_Key(encData, &sizedBuffer, parent_key, (TCM_ENCRYPT_FUNCTION_T)TCM_SM4Encrypt_Key);
            break;
        default:
            rc = TCM_UNSUPPORT_ALG;
            break;
        }
#endif
    }
    TCM_Sbuffer_Delete(&sbuffer);	/* @1 */
    TCM_SizedBuffer_Delete(&sizedBuffer);   /* freed @2 */
    return rc;
}
//original function: TCM_StoreAsymkey_GetPrimeFactorP
TCM_RESULT TCM_KeyPriv_GetAlgPrivParams(uint32_t	*pbytes,
                                        unsigned char       **parr,
                                        TCM_KEY_PRIV   *tcm_key_priv)
{
    pbytes = pbytes;
    parr = parr;
    tcm_key_priv = tcm_key_priv;
    printf("TCM_KeyPriv_GetAlgPrivParams: not implement\n");
    return TCM_FAIL;
}



//Try to get nativeKey in TCM_KEY_PRIV
//original func:  TCM_Key_GetPrivateKey
TCM_RESULT TCM_KeyPriv_GetNativeKey(uint32_t	*dbytes,
                                    unsigned char  **darr,
                                    TCM_KEY_PRIV  *tcm_key_priv)
{
    TCM_RESULT	rc = 0;
    //	printf(" TCM_KeyPriv_GetNativeKey:\n");
    if (rc == 0) {
        *dbytes = tcm_key_priv->nativeKey.keyData.size;
        *darr = tcm_key_priv->nativeKey.keyData.buffer;
    }
    return rc;
}

/*
  TCM_KEY_FLAGS
*/


TCM_RESULT TCM_KeyFlags_Load(TCM_KEY_FLAGS *tcm_key_flags,
                             unsigned char **stream,
                             uint32_t *stream_size)
{
    TCM_RESULT		rc = 0;

    /* load keyFlags */
    if (rc == 0) {
        rc = TCM_Load32(tcm_key_flags, stream, stream_size);
    }
    /* check TCM_KEY_FLAGS validity, look for extra bits set */
    if (rc == 0) {
        if (*tcm_key_flags & ~TCM_KEY_FLG_MASK) {
            printf("TCM_KeyFlags_Load: Error, illegal keyFlags value %08x\n",
                   *tcm_key_flags);
            rc = TCM_BAD_KEY_PROPERTY;
        }
    }
    return rc;
}



/*
  TCM_KEY_PARMS
*/

void TCM_KeyParms_Init(TCM_KEY_PARMS *tcm_key_parms)
{
    //    printf(" TCM_KeyParms_Init:\n");
    tcm_key_parms->algorithmID = 0;
    tcm_key_parms->encScheme = TCM_ES_SM2NONE;
    tcm_key_parms->sigScheme = TCM_SS_SM2NONE;
    tcm_key_parms->parmSize = 0;
    tcm_key_parms->sm2para.keyLength = 0;
    tcm_key_parms->sm4para.keyLength = 0;
    tcm_key_parms->sm4para.blockSize = 0;
    tcm_key_parms->sm4para.ivSize = 16;
    memset(tcm_key_parms->sm4para.IV, 0, 16);
    return;
}






/* TCM_KeyParms_Load deserializes a stream to a TCM_KEY_PARMS structure.

   Must be freed by TCM_KeyParms_Delete() after use
*/

TCM_RESULT TCM_KeyParms_Load(TCM_KEY_PARMS *tcm_key_parms,	/* result */
                             unsigned char **stream,		/* pointer to next parameter */
                             uint32_t *stream_size)		/* stream size left */
{
    TCM_RESULT		rc = 0;

    //   printf(" TCM_KeyParms_Load:\n");
    /* load algorithmID */
    if (rc == 0) {
        rc = TCM_Load32(&(tcm_key_parms->algorithmID), stream, stream_size);
        printf(" TCM_KeyParms_Load:algorithmID is %08x\n", tcm_key_parms->algorithmID);
    }
    /* load encScheme */
    if (rc == 0) {
        rc = TCM_Load16(&(tcm_key_parms->encScheme), stream, stream_size);
    }
    /* load sigScheme */
    if (rc == 0) {
        rc = TCM_Load16(&(tcm_key_parms->sigScheme), stream, stream_size);
    }
    /* load parmSize and parms */
    if (rc == 0) {
        rc = TCM_Load32(&(tcm_key_parms->parmSize), stream, stream_size);
    }
    if((rc == 0) && tcm_key_parms->parmSize > 0) {
        if (rc == 0) {
            switch(tcm_key_parms->algorithmID) {

            case TCM_ALG_SM2:
                if(tcm_key_parms->parmSize != sizeof(uint32_t)) {
                    printf("error,key parameter length must  %lu", sizeof(uint32_t));
                } else {
                    TCM_SM2PubParams_Load(&(tcm_key_parms->sm2para), stream, stream_size);
                    tcm_key_parms->sm2para.keyLength = 256; //need remove
                }
                break;
            case TCM_ALG_SM4:

                rc = TCM_SM4PubParams_Load(&(tcm_key_parms->sm4para), stream, stream_size);
                tcm_key_parms->sm4para.keyLength = 128;
                if((tcm_key_parms->sm4para.ivSize != 16) && (tcm_key_parms->sm4para.ivSize != 0)) {
                    rc = TCM_BAD_KEY_PROPERTY;
                }
                break;
            default:
                rc = TCM_BAD_KEY_PROPERTY;
            }
        }
    }

    return rc;
}

/* TCM_KeyParms_Store serializes a TCM_KEY_PARMS structure, appending results to 'sbuffer'
*/

TCM_RESULT TCM_KeyParms_Store(TCM_STORE_BUFFER *sbuffer,
                              TCM_KEY_PARMS *tcm_key_parms)
{
    TCM_RESULT	rc = 0;

    //   printf(" TCM_KeyParms_Store:\n");
    /* store algorithmID */
    if (rc == 0) {
        rc = TCM_Sbuffer_Append32(sbuffer, tcm_key_parms->algorithmID);
    }
    /* store encScheme */
    if (rc == 0) {
        rc = TCM_Sbuffer_Append16(sbuffer, tcm_key_parms->encScheme);
    }
    /* store sigScheme */
    if (rc == 0) {
        rc = TCM_Sbuffer_Append16(sbuffer, tcm_key_parms->sigScheme);
    }
    /* store parmSize */
    if (rc == 0) {
        rc = TCM_Sbuffer_Append32(sbuffer, tcm_key_parms->parmSize);
    }
    if((rc == 0) && (tcm_key_parms->parmSize > 0)) {
        if ((rc == 0)) {
            switch (tcm_key_parms->algorithmID) {
            case TCM_ALG_SM2:
                rc = TCM_SM2PubParams_Store(sbuffer, &(tcm_key_parms->sm2para));
                break;
            case TCM_ALG_SM4:
                rc = TCM_SM4PubParams_Store(sbuffer, &(tcm_key_parms->sm4para));
                break;
            default:
                printf("Cannot handle algorithmID %x\n", tcm_key_parms->algorithmID);
                rc = TCM_BAD_KEY_PROPERTY;
                break;
            }

        }
    }
    return rc;
}


TCM_RESULT TCM_KeyParms_Copy(TCM_KEY_PARMS *tcm_key_parms_dest,
                             TCM_KEY_PARMS *tcm_key_parms_src)
{
    TCM_RESULT rc = 0;

    if (rc == 0) {
        tcm_key_parms_dest->algorithmID = tcm_key_parms_src->algorithmID;
        tcm_key_parms_dest->encScheme	= tcm_key_parms_src->encScheme;
        tcm_key_parms_dest->sigScheme	= tcm_key_parms_src->sigScheme;
        tcm_key_parms_dest->parmSize	= tcm_key_parms_src->parmSize;

    }
    if((rc == 0) && (tcm_key_parms_src->parmSize > 0)) {
        switch(tcm_key_parms_src->algorithmID) {
        case TCM_ALG_SM2:
            rc = TCM_SM2PubParams_Copy(&(tcm_key_parms_dest->sm2para), &(tcm_key_parms_src->sm2para));
            break;
        case TCM_ALG_SM4:
            rc = TCM_SM4PubParams_Copy(&(tcm_key_parms_dest->sm4para), &(tcm_key_parms_src->sm4para));
            break;
        default:
            printf("invalid algorithmID %x\n", tcm_key_parms_src->algorithmID);
            rc = TCM_BAD_KEY_PROPERTY;
            break;
        }
    }

    return rc;
}

void TCM_KeyParms_Delete(TCM_KEY_PARMS *tcm_key_parms)
{
    if (tcm_key_parms != NULL) {
        if(tcm_key_parms->algorithmID == TCM_ALG_SM4 ) {
            TCM_SM4PubParams_Delete(&tcm_key_parms->sm4para);
        }
        TCM_KeyParms_Init(tcm_key_parms);
    }
    return;
}



TCM_RESULT TCM_KeyParms_GetKeyParms(TCM_ALG_PUB_PARAMS *KeyParms,
                                    TCM_KEY_PARMS *keyInfo)
{
    TCM_RESULT		rc = 0;



    if((keyInfo == NULL) || (KeyParms == NULL)) {
        printf("Error, TCM_KEY_PARMS is NULL or other\n");
        rc = TCM_BAD_KEY_PROPERTY;
    } else {
        printf("algorithmID =%d \n " , keyInfo->algorithmID);
        printf("encScheme =%d \n " , keyInfo->encScheme);
        printf("encScheme =%d \n" , keyInfo->sigScheme);
    }


    if(rc == 0) {
        KeyParms->algorithmID = keyInfo->algorithmID;
        switch(keyInfo->algorithmID) {
        case   TCM_ALG_SM2:
            rc = TCM_SM2PubParams_Copy(&(KeyParms->SM2_PUB_PARAMS), &(keyInfo->sm2para));
            break;
        case	TCM_ALG_SM4:
            rc = TCM_SM4PubParams_Copy(&(KeyParms->SM4_PUB_PARAMS), &(keyInfo->sm4para));
            break;
        default:
            rc = TCM_BAD_KEY_PROPERTY;
        }
    }
    return rc;
}

TCM_RESULT TCM_KeyParms_GetKeyLength(uint32_t *keyLength,
                                     TCM_KEY_PARMS *keyInfo)
{
    TCM_RESULT		rc = 0;

    if(rc == 0) {
        switch(keyInfo->algorithmID) {
        case   TCM_ALG_SM2:
            *keyLength = keyInfo->sm2para.keyLength;
            break;
        case	TCM_ALG_SM4:
            *keyLength = keyInfo->sm4para.keyLength;
            break;
        default:
            rc = TCM_BAD_KEY_PROPERTY;
        }
    }
    return rc;
}
TCM_RESULT TCM_KeyParms_GetAlgorithmID(TCM_ALGORITHM_ID *algID, TCM_KEY_PARMS *keyInfo)
{
    *algID = keyInfo->algorithmID;
    return  TCM_SUCCESS;
}


void TCM_ALG_PUB_PARAMS_Init(TCM_ALG_PUB_PARAMS *algPubParams)
{
    if(algPubParams) {
        algPubParams->algorithmID = TCM_ALG_UNINITIALIZED;
        TCM_SM4PubParams_Init(&algPubParams->SM4_PUB_PARAMS);
    }
}
void TCM_ALG_PUB_PARAMS_Delete(TCM_ALG_PUB_PARAMS *algPubParams)
{



    if(algPubParams) {
        switch(algPubParams->algorithmID) {
        case  TCM_ALG_SM4:
            TCM_SM4PubParams_Delete(&(algPubParams->SM4_PUB_PARAMS));

        }
        TCM_ALG_PUB_PARAMS_Init(algPubParams);
    }
    return;

}





//  need modify
TCM_RESULT TCM_KeyParms_CheckProperties(TCM_KEY_PARMS *keyInfo, TCM_KEY_USAGE keyUsage, uint32_t requiredKeyLength)
{
    TCM_RESULT	rc = 0;
    uint32_t  keyLength = 0 ;
    TCM_ALG_PUB_PARAMS tcm_alg_pub_params ;	/* used if algorithmID indicates SM2 or SM4*/
    TCM_ALGORITHM_ID algID;

    printf("keyUsage %04hx\n", keyUsage);
    printf("keyLength %04hx\n", requiredKeyLength);

    TCM_ALG_PUB_PARAMS_Init(&tcm_alg_pub_params);//free@1

    rc = TCM_KeyParms_GetAlgorithmID(&algID, keyInfo);
    if (rc == 0) {
        /* the code currently only supports SM4 and SM2 */
        if (algID != TCM_ALG_SM2 && algID != TCM_ALG_SM4) {
            printf("Error, algorithmID not TCM_ALG_SM2 or TCM_ALG_SM4\n");
            rc = TCM_BAD_KEY_PROPERTY;
        }
    }

    if(rc == 0) {
        rc = TCM_KeyParms_GetKeyLength(&keyLength, keyInfo);
    }
    /* check key length if specified as input parameter */
    if ((rc == 0) && (requiredKeyLength != 0)) {
        if (keyLength != requiredKeyLength) {	/* in bits */
            printf("Error, Bad keyLength should be %u, was %u\n",
                   requiredKeyLength, keyLength);
            rc = TCM_BAD_KEY_PROPERTY;
        }
    }
    /* get the TCM_ALG_PUB_PARAMS structure from the TCM_CIPHER_SCHEME structure */
    /* NOTE: for now only support SM2 and SM4 keys */
    if (rc == 0) {
        rc = TCM_KeyParms_GetKeyParms(&tcm_alg_pub_params, keyInfo);
    }
    //TCM_CIPHER_SCHEME's members checking
    if (rc == 0) {
        switch(algID) {
        case TCM_ALG_SM2:
            if(keyLength > TCM_SM2_KEY_LENGTH_MAX || keyLength < TCM_SM2_KEY_LENGTH_MIN) {
                printf("Error, Bad keyLength %u~%u, was %u\n", TCM_SM2_KEY_LENGTH_MIN,
                       TCM_SM2_KEY_LENGTH_MAX, keyLength);
                rc = TCM_BAD_KEY_PROPERTY;
            }
            break;
        case TCM_ALG_SM4:
            if(keyLength != TCM_SM4_KEY_LENGTH) {
                printf("Error, Bad keyLength max %u, was %u\n",
                       TCM_SM4_KEY_LENGTH, keyLength);
                rc = TCM_BAD_KEY_PROPERTY;
            }
            if(rc == 0 ) {
                //no mode parameter  maybe have some problem
                rc = TCM_SM4PubParams_CheckIV(&(tcm_alg_pub_params.SM4_PUB_PARAMS), TCM_ES_SM4_CBC);
            }
            break;
        default:
            printf("Error, bad properties 1\n");
            rc = TCM_BAD_KEY_PROPERTY;
            break;
        }
    }




    /* From Part 2 5.7.1 Mandatory Key Usage Schemes  and TCM_CreateWrapKey, TCM_LoadKey */
    //TCM_KEY_PUB's members checking
    switch (keyUsage) {
    case TCM_SM2KEY_IDENTITY:
    case TCM_SM2KEY_SIGNING:
        switch (algID) {
        case TCM_ALG_SM2:
            if (keyInfo->sigScheme != TCM_SS_SM2 && keyInfo->sigScheme != TCM_SS_SM2NONE) {
                printf("Error, Signing mode %08hx is not correct\n",	keyInfo->sigScheme);
                rc = TCM_BAD_KEY_PROPERTY;
            }
            break;
        default:
            printf("Error, bad algorithm ID %04hx\n",
                   algID);
            rc = TCM_BAD_KEY_PROPERTY;
            break;
        }
        break;
    case TCM_SM2KEY_STORAGE:
        /*			if(keyInfo->sigScheme !=  TCM_SS_SM2NONE) {
        				TRC_I("TCM_KeyParms_CheckProperties: Error, "
        				"Storage mode(TCM_KEY_TYP_ASYMMETRIC) %08hx is not correct\n", keyInfo->encScheme);
        				rc = TCM_BAD_KEY_PROPERTY;
        			}
        */
        break;

    case TCM_SM4KEY_STORAGE:
        if(keyInfo->encScheme != TCM_ES_SM4_CBC) {
            printf("Error, "
                   "Storage mode(TCM_KEY_TYP_SYMMETRIC) %08hx is not correct\n", keyInfo->encScheme);
            rc = TCM_BAD_KEY_PROPERTY;
        }
        break;
    case TCM_SM2KEY_BIND:
        if(keyInfo->sigScheme !=  TCM_SS_SM2NONE) {
            printf("Error, "
                   "Encryption mode(TCM_KEY_TYP_ASYMMETRIC) %08hx is not correct\n", keyInfo->encScheme);
            rc = TCM_BAD_KEY_PROPERTY;
        }
        break;
    case TCM_SM4KEY_BIND:
        if(keyInfo->encScheme != TCM_ES_SM4_CBC ) {
            printf("Error, "
                   "Encryption mode(TCM_KEY_TYP_SYMMETRIC) %08hx is not correct\n", keyInfo->encScheme);
            rc = TCM_BAD_KEY_PROPERTY;
        }
        break;

    case TCM_SM2KEY_MIGRATION:
        if(keyInfo->sigScheme != TCM_SS_SM2NONE) {
            printf("Error, "
                   "SignEncryption mode %08hx is not correct\n", keyInfo->encScheme);
            rc = TCM_BAD_KEY_PROPERTY;
        }
        break;
    case TCM_SM4KEY_MIGRATION:
        if(keyInfo->sigScheme != TCM_SS_SM2NONE) {
            printf("Error, "
                   "SignEncryption mode %08hx is not correct\n", keyInfo->encScheme);
            rc = TCM_BAD_KEY_PROPERTY;
        }
        break;
    default:
        printf("Error, bad properties 10\n");
        rc = TCM_BAD_KEY_PROPERTY;
        break;
    }

    TCM_ALG_PUB_PARAMS_Delete(&tcm_alg_pub_params);//free@1
    return rc;
}

























/*
	TCM_CIPH_SCHM_ALG
*/

void TCM_AlgParams_Init(TCM_CIPH_SCHM_ALG *algorithm)
{
    //	printf(" TCM_AlgParams_Init:\n");
    algorithm->algID = 0;
    TCM_SizedBuffer_Init(&(algorithm->algPubParams));
    TCM_ALG_PUB_PARAMS_Init(&algorithm->tcm_alg_pub_params);
    return;
}

TCM_RESULT TCM_AlgParams_GetPubParams(TCM_ALG_PUB_PARAMS **algPubParams, TCM_CIPH_SCHM_ALG *algorithm)
{
    //	printf("TCM_AlgParams_GetPubParams:\n");
    *algPubParams = &(algorithm->tcm_alg_pub_params);
    return 0;
}

TCM_RESULT TCM_AlgParams_GetAlgorithmID(TCM_ALGORITHM_ID *algID, TCM_CIPH_SCHM_ALG *algorithm)
{
    //	printf("TCM_AlgParams_GetAlgorithmID:\n");
    *algID = algorithm->algID;
    return 0;
}
TCM_RESULT TCM_AlgParams_Load(TCM_CIPH_SCHM_ALG *algorithm, unsigned char **stream, uint32_t *stream_size)
{
    TCM_RESULT rc = 0;
    //	printf("TCM_AlgParams_Load:\n");
    if(rc == 0) {
        rc = TCM_Load32(&(algorithm->algID), stream, stream_size);
    }
    if(rc == 0) {
        rc = TCM_SizedBuffer_Load(&(algorithm->algPubParams), stream, stream_size);
    }
    if(rc == 0 && algorithm->algPubParams.size != 0) {
        rc = TCM_AlgParams_SetSpecific(algorithm, algorithm->algPubParams.buffer, algorithm->algPubParams.size);
    }
    return rc;
}

TCM_RESULT TCM_AlgParams_Store(TCM_STORE_BUFFER *sbuffer, TCM_CIPH_SCHM_ALG *algorithm)
{
    TCM_RESULT rc = 0;
    //	printf("TCM_AlgParams_Store:\n");
    if(rc == 0) {
        rc = TCM_Sbuffer_Append32(sbuffer, algorithm->algID);
    }
    if(rc == 0) {
        switch (algorithm->algID) {
        /* Allow store of uninitialized structures */
        case TCM_ALG_UNINITIALIZED:
            break;
        case TCM_ALG_SM2:
            /*				rc = TCM_SizedBuffer_SetStructure(&(algorithm->algPubParams),
            																			(void *)(algorithm->tcm_alg_pub_params),
            																			(TCM_STORE_FUNCTION_T)TCM_SM2PubParams_Store);*/
            break;
        case TCM_ALG_SM4:
            /*	rc = TCM_SizedBuffer_SetStructure(&(algorithm->algPubParams),
            																(void *)(algorithm->tcm_alg_pub_params),
            																(TCM_STORE_FUNCTION_T)TCM_SM4PubParams_Store);*/
            break;
        default:
            printf("TCM_AlgParams_Store: Cannot handle algID %08x\n",
                   algorithm->algID);
            rc = TCM_BAD_KEY_PROPERTY;
            break;
        }
    }
    if(rc == 0) {
        rc = TCM_SizedBuffer_Store(sbuffer, &(algorithm->algPubParams));
    }
    return rc;
}

TCM_RESULT TCM_AlgParams_Copy(TCM_CIPH_SCHM_ALG *algorithm_dest, TCM_CIPH_SCHM_ALG *algorithm_src)
{
    TCM_RESULT rc = 0;
    //	printf("TCM_AlgParams_Copy:\n");
    if(rc == 0) {
        algorithm_dest->algID = algorithm_src->algID;
        rc = TCM_SizedBuffer_Copy(&(algorithm_dest->algPubParams), &(algorithm_src->algPubParams));
    }
    if(rc == 0) {
        algorithm_dest->tcm_alg_pub_params.algorithmID = algorithm_src->tcm_alg_pub_params.algorithmID;
        switch(algorithm_src->algID) {
        case TCM_ALG_UNINITIALIZED:
            break;
        case TCM_ALG_SM2:

            if(rc == 0) {
                TCM_SM2PubParams_Init(&(algorithm_dest->tcm_alg_pub_params.SM2_PUB_PARAMS));
                rc = TCM_SM2PubParams_Copy(&(algorithm_dest->tcm_alg_pub_params.SM2_PUB_PARAMS), &(algorithm_src->tcm_alg_pub_params.SM2_PUB_PARAMS));
            }
            break;
        case TCM_ALG_SM4:

            if(rc == 0) {
                TCM_SM4PubParams_Init(&(algorithm_dest->tcm_alg_pub_params.SM4_PUB_PARAMS));
                rc = TCM_SM4PubParams_Copy(&(algorithm_dest->tcm_alg_pub_params.SM4_PUB_PARAMS), &(algorithm_src->tcm_alg_pub_params.SM4_PUB_PARAMS));
            }
            break;
        default:
            rc = TCM_UNSUPPORT_ALG;
            break;
        }
    }
    return rc;
}

//original function: TCM_KeyParms_SetRSA
TCM_RESULT TCM_AlgParams_SetSpecific(TCM_CIPH_SCHM_ALG *algorithm, unsigned char *stream, uint32_t stream_size)
{
    TCM_RESULT rc = 0;


    switch(algorithm->algID) {
    case TCM_ALG_UNINITIALIZED:
        break;
    case TCM_ALG_SM2:
        algorithm->tcm_alg_pub_params.algorithmID = algorithm->algID;
        if(rc == 0) {
            rc = TCM_SM2PubParams_Load(&(algorithm->tcm_alg_pub_params.SM2_PUB_PARAMS), &stream, &stream_size);
        }
        break;
    case TCM_ALG_SM4:
        algorithm->tcm_alg_pub_params.algorithmID = algorithm->algID;
        if(rc == 0) {
            rc = TCM_SM4PubParams_Load(&(algorithm->tcm_alg_pub_params.SM4_PUB_PARAMS), &stream, &stream_size);
        }
        break;
    default:
        rc = TCM_UNSUPPORT_ALG;
        break;
    }
    return rc;
}


TCM_RESULT TCM_AlgParams_SetSM2(TCM_CIPH_SCHM_ALG *algorithm,
                                TCM_SM2_ASYMKEY_PARAMETERS *sm2PubParams)
{
    TCM_RESULT rc = 0;

    if (rc == 0) {
        rc = TCM_SM2PubParams_Copy(&(algorithm->tcm_alg_pub_params.SM2_PUB_PARAMS), sm2PubParams);
    }
    return rc;
}

TCM_RESULT TCM_AlgParams_SetSM4(TCM_CIPH_SCHM_ALG *algorithm,
                                TCM_SYMMETRIC_KEY_PARMS *sm4PubParams)
{
    TCM_RESULT rc = 0;
    if (rc == 0) {
        rc = TCM_SM4PubParams_Copy(&(algorithm->tcm_alg_pub_params.SM4_PUB_PARAMS), sm4PubParams);
    }
    return rc;
}

void TCM_AlgParams_Delete(TCM_CIPH_SCHM_ALG *algorithm)
{
    TCM_RESULT rc = 0;
    TCM_ALGORITHM_ID algID = TCM_ALG_UNINITIALIZED;
    if(algorithm != NULL) {
        rc = TCM_AlgParams_GetAlgorithmID(&algID, algorithm);
        if(rc == 0) {
            TCM_SizedBuffer_Delete(&(algorithm->algPubParams));
            switch (algID) {
            case TCM_ALG_UNINITIALIZED:
                break;
            case TCM_ALG_SM2:
                TCM_SM2PubParams_Delete(&(algorithm->tcm_alg_pub_params.SM2_PUB_PARAMS));
                break;
            case TCM_ALG_SM4:
                TCM_SM4PubParams_Delete(&(algorithm->tcm_alg_pub_params.SM4_PUB_PARAMS));
                break;
            default:
                rc = TCM_UNSUPPORT_ALG;
                break;
            }
        }
    }

    TCM_AlgParams_Init(algorithm);
    return;
}

/*
	TCM_SM2_PUB_PARAMS
*/


void TCM_SM2PubParams_Init(TCM_SM2_ASYMKEY_PARAMETERS *tcm_sm2_pub_params)
{
    tcm_sm2_pub_params->keyLength = 0;
    return;
}
//original function: TCM_RSAKeyParms_Load
TCM_RESULT TCM_SM2PubParams_Load(TCM_SM2_ASYMKEY_PARAMETERS *tcm_sm2_pub_params,
                                 unsigned char **stream,
                                 uint32_t *stream_size)
{
    TCM_RESULT rc = 0;
    rc = TCM_Load32(&(tcm_sm2_pub_params->keyLength), stream, stream_size);
    return rc;
}
//original function: TCM_RSAKeyParms_Store
TCM_RESULT TCM_SM2PubParams_Store(TCM_STORE_BUFFER *sbuffer,
                                  const TCM_SM2_ASYMKEY_PARAMETERS *tcm_sm2_pub_params)
{
    TCM_RESULT	rc = 0;

    /* store fieldType */
    if (rc == 0) {
        rc = TCM_Sbuffer_Append32(sbuffer, tcm_sm2_pub_params->keyLength);
    }
    return rc;
}
//original function: TCM_RSAKeyParms_Delete
void       TCM_SM2PubParams_Delete(TCM_SM2_ASYMKEY_PARAMETERS *tcm_sm2_pub_params)
{
    if (tcm_sm2_pub_params != NULL) {
        TCM_SM2PubParams_Init(tcm_sm2_pub_params);
    }
    return;
}
//original function: TCM_RSAKeyParms_Copy
TCM_RESULT TCM_SM2PubParams_Copy(TCM_SM2_ASYMKEY_PARAMETERS *tcm_sm2_pub_params_dest,
                                 TCM_SM2_ASYMKEY_PARAMETERS *tcm_sm2_key_params_src)
{
    TCM_RESULT rc = 0;
    if (rc == 0) {
        tcm_sm2_pub_params_dest->keyLength = tcm_sm2_key_params_src->keyLength;
    }

    return rc;
}





/*
	TCM_SM4_PUB_PARAMS
*/

void TCM_SM4PubParams_Init(TCM_SYMMETRIC_KEY_PARMS *sm4PubParams)
{

    if(sm4PubParams) {
        sm4PubParams->blockSize = 0;
        sm4PubParams->keyLength = 0;
        sm4PubParams->ivSize = 16;
        memset(sm4PubParams->IV , 0 , 16);
    }
    return;
}


TCM_RESULT TCM_SM4PubParams_Store(TCM_STORE_BUFFER *sbuffer, TCM_SYMMETRIC_KEY_PARMS *sm4PubParams)
{
    TCM_RESULT rc = 0;
    if((sbuffer == NULL) || (sm4PubParams == NULL)) {
        rc = TCM_BAD_PARAMETER;
    }
    if (rc == 0) {
        rc = TCM_Sbuffer_Append32(sbuffer, sm4PubParams->keyLength);
    }
    if (rc == 0) {
        rc = TCM_Sbuffer_Append32(sbuffer, sm4PubParams->blockSize);
    }
    if (rc == 0) {
        rc = TCM_Sbuffer_Append32(sbuffer, sm4PubParams->ivSize);
    }
    if (rc == 0) {
        rc = TCM_Sbuffer_Append(sbuffer, sm4PubParams->IV, 16);
    }
    return rc;
}

TCM_RESULT TCM_SM4PubParams_Load(TCM_SYMMETRIC_KEY_PARMS *tcm_sm4_pub_params,
                                 unsigned char **stream,
                                 uint32_t *stream_size)
{
    TCM_RESULT rc = 0;
    if(tcm_sm4_pub_params == NULL) {
        rc = TCM_BAD_PARAMETER;
    }

    if (rc == 0) {
        rc = TCM_Load32(&(tcm_sm4_pub_params->keyLength), stream, stream_size);
    }
    if (rc == 0) {
        rc = TCM_Load32(&(tcm_sm4_pub_params->blockSize), stream, stream_size);
    }
    if (rc == 0) {
        rc = TCM_Load32(&(tcm_sm4_pub_params->ivSize), stream, stream_size);
    }
    if (rc == 0) {
        rc = TCM_Loadn(tcm_sm4_pub_params->IV, 16, stream, stream_size);
    }
    return rc;
}


TCM_RESULT TCM_SM4PubParams_Copy(TCM_SYMMETRIC_KEY_PARMS *tcm_sm4_pub_params_dest,
                                 TCM_SYMMETRIC_KEY_PARMS *tcm_sm4_key_params_src)
{
    TCM_RESULT rc = 0;
    if (rc == 0) {
        tcm_sm4_pub_params_dest->keyLength = tcm_sm4_key_params_src->keyLength;
        tcm_sm4_pub_params_dest->blockSize = tcm_sm4_key_params_src->blockSize;
        tcm_sm4_pub_params_dest->ivSize = tcm_sm4_key_params_src->ivSize;
    }
    if (rc == 0) {
        memcpy(tcm_sm4_pub_params_dest->IV, tcm_sm4_key_params_src->IV, 16);
    }
    return rc;
}

TCM_RESULT TCM_SM4PubParams_CheckIV(TCM_SYMMETRIC_KEY_PARMS *tcm_sm4_pub_params, TCM_ENC_SCHEME mode)
{
    TCM_RESULT rc = 0;
    switch(mode) {
    case TCM_ES_SM4_CBC:
        if(!(tcm_sm4_pub_params->ivSize == 0 )
                && !(tcm_sm4_pub_params->ivSize == TCM_SM4_KEY_SIZE)) {
            printf("bad parameter format for mode %8hx\n", mode);
            rc = TCM_BAD_KEY_PROPERTY;
        }
        break;
    default:
        printf("bad parameter format for mode %8hx\n", mode);
        rc = TCM_BAD_KEY_PROPERTY;
    }
    return rc;
}

void       TCM_SM4PubParams_Delete(TCM_SYMMETRIC_KEY_PARMS *tcm_sm4_pub_params)
{
    if (tcm_sm4_pub_params != NULL) {
        TCM_SM4PubParams_Init(tcm_sm4_pub_params);
    }
    return;
}






/*
	TCM_NATIVE_KEY
*/
void  TCM_NativeKey_Init(TCM_NATIVE_KEY *nativeKey)
{
    //	printf("TCM_NativeKey_Init:\n");
    TCM_SizedBuffer_Init(&(nativeKey->keyData));
    return;
}

TCM_RESULT TCM_NativeKey_Load(TCM_NATIVE_KEY *nativeKey, unsigned char **stream,  uint32_t *stream_size)
{
    TCM_RESULT rc = 0;
    //	printf("TCM_NativeKey_Load:\n");
    if(rc == 0) {
        TCM_SizedBuffer_Load(&(nativeKey->keyData), stream, stream_size);
    }
    return rc;
}

TCM_RESULT TCM_NativeKey_Store(TCM_STORE_BUFFER *sbuffer, TCM_NATIVE_KEY *nativeKey)
{
    TCM_RESULT rc = 0;
    //	printf("TCM_NativeKey_Store:\n");
    if(rc == 0) {
        TCM_SizedBuffer_Store(sbuffer, &(nativeKey->keyData));
    }
    return rc;
}

void TCM_NativeKey_Delete(TCM_NATIVE_KEY *nativeKey)
{
    //	printf("TCM_NativeKey_Delete:\n");
    TCM_SizedBuffer_Delete(&(nativeKey->keyData));
    TCM_SizedBuffer_Init(&(nativeKey->keyData));
    return;
}






TCM_RESULT TCM_Key_GenerateSM2(TCM_KEY *tcm_key,
                               keydata *keyparms)
{
    TCM_RESULT	rc = 0;
    TCM_ALG_PUB_PARAMS	*tcm_sm2_pub_parms = NULL;
    uint32_t  keyLength = 256 ;

    /* generated SM2 key */
    unsigned char	*d = NULL; /* private key */
    unsigned char	*P = NULL; /* public key */
    uint32_t privkey_len = 0, pubkey_len = 0;

    //   printf(" TCM_Key_GenerateSM2:\n");


    /* allocate storage for TCM_KEY_PRIV.	The structure is not freed.  It is cached in the
       TCM_KEY->TCM_STORE_ASYMKEY member and freed when they are deleted. */
    if (rc == 0) {
        rc = TCM_Malloc((unsigned char **) & (tcm_key->tcm_key_priv),
                        sizeof(TCM_KEY_PRIV));
    }
    if (rc == 0) {
        TCM_KeyPriv_Init(tcm_key->tcm_key_priv);
    }
    /* generate the key pair */
    if (rc == 0) {
        rc = os_sm2_generate_key(&d, &privkey_len, &P, &pubkey_len);
    }
    /* construct the TCM_KEY_PRIV member */
    if (rc == 0) {
        //		TCM_dump_data("privkey#######",P,privkey_len);
        //		TCM_dump_data("pubkey#######",d,pubkey_len);
        /* add the private key to the TCM_KEY_PRIV object */
        rc = TCM_SizedBuffer_Set(&(tcm_key->tcm_key_priv->nativeKey.keyData),
                                 keyLength / CHAR_BIT,
                                 d);
    }
    if (rc == 0) {
        rc = TCM_Key_Set(tcm_key,
                         keyparms->keyUsage,				/* TCM_KEY_USAGE */
                         keyparms->keyFlags,			/* TCM_KEY_FLAGS */
                         keyparms->authDataUsage,				/* TCM_AUTH_DATA_USAGE */
                         & (keyparms->pub.algorithmParms),				/* TCM_CIPHER_SCHEME */
                         P,				/* (public key) */
                         /* FIXME redundant */
                         tcm_key->tcm_key_priv);	/* cache the TCM_KEY_PRIV structure */
    }
    free(P);
    free(d);
    return rc;
}


















