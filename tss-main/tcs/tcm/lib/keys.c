

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
#include <oiaposap.h>
#include <tcmfunc.h>
#include <tcmutil.h>
#include <tcmkeys.h>
#include <tcm_constants.h>
#include "tcm_error.h"
#include <hmac.h>
#include <newserialize.h>





/****************************************************************************/
/*                                                                          */
/* Creates an revocable endorsement key pair                                */
/*                                                                          */
/* uses the following standard parameters in its request:                   */
/*                                                                          */
/* algorithm: RSA                                                           */
/* encScheme: enc_SCHEME                                                    */
/* sigScheme: TCM_SS_SASSAPKCS1v15_SHA1                                     */
/* numPrimes: 2                                                             */
/* keybitlen: 2048                                                          */
/*                                                                          */
/* The arguments are ...                                                    */
/*                                                                          */
/* genreset     a boolean that determines whether to generate ekreset       */
/* inputekreset A pointer to a hash that is used as ekreset if genreset is  */
/*              FALSE                                                       */
/* pubkeybuff   A pointer to an area that will hold the public key          */
/* pubkeybuflen is the size of the pubkeybuff as given by the caller and    */
/*              on returns the number of bytes copied into that buffer      */
/****************************************************************************/

uint32_t TCM_CreateRevocableEK(TCM_BOOL genreset,
                               unsigned char *inputekreset,
                               unsigned char *resetEKbuff)
{
    unsigned char nonce[TCM_HASH_SIZE];
    STACK_TCM_BUFFER( tcmdata)
    keydata k;
    uint32_t ret;
    uint32_t ordinal_no = htonl(TCM_ORD_CreateRevocableEK);
    int serkeylen;
    STACK_TCM_BUFFER(serkey)
    uint32_t size;

    memset(&k, 0x0, sizeof(k));
    k.hdr.key12.tag = TCM_TAG_KEY;
    k.hdr.key12.fill = 0;
    k.pub.algorithmParms.algorithmID = TCM_ALG_SM2;
    /* Should be ignored, but a certain HW TCM requires the correct encScheme */
    k.pub.algorithmParms.encScheme = TCM_ES_SM2;
    k.pub.algorithmParms.sigScheme = TCM_SS_SM2NONE;
    k.pub.algorithmParms.parmSize = 4;
    k.pub.algorithmParms.sm2para.keyLength = 256;
    k.keyUsage = TCM_SM2KEY_STORAGE;
    k.keyFlags &= ~TCM_KEY_FLG_MIGRATABLE;

    TSS_gennonce(nonce);

    serkeylen = TCM_WriteKeyInfo(&serkey, &k);

    if ( (serkeylen & ERR_MASK) != 0 ) {
        return serkeylen;
    }

    if (FALSE == genreset) {

        ret = TSS_buildbuff("00 c1 T l % % o %", &tcmdata,
                            ordinal_no,
                            TCM_HASH_SIZE, nonce,
                            serkeylen, serkey.buffer,
                            genreset,
                            TCM_HASH_SIZE, inputekreset);
    } else {
        unsigned char empty[TCM_HASH_SIZE];
        memset(empty, 0x0, TCM_HASH_SIZE);
        ret = TSS_buildbuff("00 c1 T l % % o %", &tcmdata,
                            ordinal_no,
                            TCM_HASH_SIZE, nonce,
                            serkeylen, serkey.buffer,
                            genreset,
                            TCM_HASH_SIZE, empty);
    }

    if ((ret & ERR_MASK)) {
        return ret;
    }

//#if defined(platform_C) || defined(platform_M) || defined(platform_2700)
//	system ("echo 1000 > /sys/module/httctdd/parameters/recv_mdelay");
//#endif

    ret = TCM_Transmit(&tcmdata, "CreateRevocableEK");

//#if defined(platform_C) || defined(platform_M) || defined(platform_2700)
//	system ("echo 500 > /sys/module/httctdd/parameters/recv_mdelay");
//#endif

    if (0 != ret) {
        return ret;
    }

    size = TSS_PubKeySize(&tcmdata, TCM_DATA_OFFSET , 0);
    if ((size & ERR_MASK))
        return size;

    /*
     * Verify the checksum...
     */
    {
        sm3_context sm3;
        unsigned char digest[TCM_DIGEST_SIZE];
        sm3_init(&sm3);
        sm3_update(&sm3,
                   &tcmdata.buffer[TCM_DATA_OFFSET],
                   size);
        sm3_update(&sm3,
                   nonce,
                   TCM_NONCE_SIZE);
        sm3_finish(&sm3, digest);
        if (0 != memcmp(digest,
                        &tcmdata.buffer[TCM_DATA_OFFSET + size],
                        TCM_DIGEST_SIZE)) {
            ret = ERR_CHECKSUM;
        }

        if(NULL != resetEKbuff) {
            memcpy(resetEKbuff, &tcmdata.buffer[TCM_DATA_OFFSET + size + TCM_HASH_SIZE], TCM_HASH_SIZE);
        }
    }

    return ret;
}


/****************************************************************************/
/*                                                                          */
/* Owner Read the TCM Endorsement Key                                       */
/*                                                                          */
/****************************************************************************/
uint32_t TCM_ReadPubek(unsigned char *ownauth, pubkeydata *k)
{


    STACK_TCM_BUFFER(tcmdata)
    uint32_t ret;
    uint32_t len;
    uint32_t ordinal = htonl(TCM_ORD_ReadPubek);
    unsigned char antiReplay[TCM_NONCE_SIZE];

    /* check input argument */
    if (k == NULL)
        return ERR_NULL_ARG;

    ret = TSS_gennonce(antiReplay);
    if (ret == 0)
        return ERR_CRYPT_ERR;

    /* copy Read PubKey request template to buffer */
    ret = TSS_buildbuff("00 c1 T l %", &tcmdata,
                        ordinal,
                        TCM_HASH_SIZE, antiReplay);
    if ((ret & ERR_MASK) != 0) return ret;
    ret = TCM_Transmit(&tcmdata, "ReadPubEK-auth1");
    if (ret)
        return ret;
    len = TSS_PubKeyExtract(&tcmdata, TCM_DATA_OFFSET , k);

    /*
     * Verify the checksum...
     */
    {
        sm3_context sm3_ctxt;
        unsigned char digest[TCM_DIGEST_SIZE];
        sm3_init(&sm3_ctxt);
        sm3_update(&sm3_ctxt,
                   &tcmdata.buffer[TCM_DATA_OFFSET],
                   len);
        sm3_update(&sm3_ctxt,
                   antiReplay,
                   TCM_HASH_SIZE);
        sm3_finish(&sm3_ctxt, digest);
        if (0 != memcmp(digest,
                        &tcmdata.buffer[TCM_DATA_OFFSET + len],
                        TCM_DIGEST_SIZE)) {
            printf("TCM_ReadPubek: checksum error.\n");
            ret = -1;
        }
    }

    return ret;

}



/****************************************************************************/
/*                                                                          */
/* Create and Wrap a Key                                                    */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the parent key of the new key                 */
/*           0x40000000 for the SRK                                         */
/* parauth   is the authorization data (password) for the parent key        */
/*           if NULL, the default auth data of all zeros is assumed         */
/* newauth   is the authorization data (password) for the new key           */
/* migauth   is the authorization data (password) for migration of the new  */
/*           key, or NULL if the new key is not migratable                  */
/*           all authorization values must be 20 bytes long                 */
/* keyparms  is a pointer to a keydata structure with parms set for the new */
/*           key                                                            */
/* key       is a pointer to a keydata structure returned filled in         */
/*           with the public key data for the new key, or NULL if no        */
/*           keydata is to be returned                                      */
/* keyblob   is a pointer to an area which will receive a copy of the       */
/*           encrypted key blob.  If NULL no copy is returned               */
/* bloblen   is a pointer to an integer which will receive the length of    */
/*           the key blob, or NULL if no length is to be returned           */
/*                                                                          */
/****************************************************************************/
uint32_t TCM_CreateWrapKey(uint32_t keyhandle,
                           unsigned char *parauth,
                           unsigned char *newauth,
                           unsigned char *migauth,
                           keydata *keyparms,
                           keydata *key,   //out
                           unsigned char *keyblob, //out
                           unsigned int  *bloblen) //out
{
    uint32_t ret;
    STACK_TCM_BUFFER( tcmdata)
    STACK_TCM_BUFFER(kparmbuf)
    session sess;
    unsigned char encauth1[TCM_HASH_SIZE];
    unsigned char encauth2[TCM_HASH_SIZE];
    //unsigned char nonceodd[TCM_NONCE_SIZE];
    unsigned char pubauth[TCM_HASH_SIZE];
    unsigned char dummyauth[TCM_HASH_SIZE];
    unsigned char *cparauth;
    unsigned char *cnewauth;
    unsigned char *cmigauth;
    unsigned char c = 0;
    uint32_t ordinal = htonl(TCM_ORD_CreateWrapKey);
    uint32_t keyhndl = htonl(keyhandle);

    //uint16_t keytype;
    int      kparmbufsize;
    STACK_TCM_BUFFER(response);

    memset(dummyauth, 0, sizeof dummyauth);
    /* check input arguments */
    if (keyparms == NULL) return ERR_NULL_ARG;
    if (parauth == NULL) cparauth = dummyauth;
    else                 cparauth = parauth;
    if (newauth == NULL) cnewauth = dummyauth;
    else                 cnewauth = newauth;
    if (migauth == NULL) cmigauth = dummyauth;
    else 				 cmigauth = migauth;
    //if (keyhandle == 0x40000000) keytype = 0x0004;
    //else                         keytype = 0x0001;
    ret = needKeysRoom(keyhandle, 0, 0, 0          );
    if (ret != 0) {
        return ret;
    }

    /* Open OSAP Session */
    ret = TSS_SessionOpen(SESSION_OSAP/*|SESSION_DSAP*/, &sess, cparauth, TCM_ET_KEYHANDLE, keyhandle);
    if (ret != 0)
        return ret;

    ret = TCM_CreateEncAuth(&sess, cnewauth, encauth1);
	if(ret != 0){
		TSS_SessionClose(&sess);
		return ret;
	}
    /* calculate encrypted authorization value for migration of new key */

    ret = TCM_CreateEncAuth(&sess, cmigauth, encauth2);
	if(ret != 0){
		TSS_SessionClose(&sess);
		return ret;
	}

    /* move Network byte order data to variables for hmac calculation */
    /* convert keyparm structure to buffer */
    ret = TCM_WriteKey(&kparmbuf, keyparms);
    if ((ret & ERR_MASK) != 0) {
        TSS_SessionClose(&sess);
        return ret;
    }
    kparmbufsize = ret;
    /* calculate authorization HMAC value */
    ret = TSS_authhmac1(pubauth, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                        TSS_Session_GetSeq(&sess), c,
                        TCM_U32_SIZE, &ordinal,
                        TCM_HASH_SIZE, encauth1,
                        TCM_HASH_SIZE, encauth2,
                        kparmbufsize, kparmbuf.buffer,
                        0, 0);
    if (ret != 0) {
        TSS_SessionClose(&sess);
        return ret;
    }
    /* build the request buffer */

    ret = TSS_buildbuff("00 c2 T l  l % % % L %", &tcmdata,
                        ordinal,
                        keyhndl,
                        TCM_HASH_SIZE, encauth1,
                        TCM_HASH_SIZE, encauth2,
                        kparmbuf.used, kparmbuf.buffer,
                        TSS_Session_GetHandle(&sess),
                        TCM_HASH_SIZE, pubauth);
    if ((ret & ERR_MASK) != 0) {
        TSS_SessionClose(&sess);
        return ret;
    }
    /* transmit the request buffer to the TCM device and read the reply */
    ret = TCM_Transmit(&tcmdata, "CreateWrapKey - AUTH");

    if (ret != 0) {
        TSS_SessionClose(&sess);
        return ret;
    }

    kparmbufsize = TSS_KeySize(&tcmdata, TCM_DATA_OFFSET  );
    ret = TSS_checkhmac1(&tcmdata, ordinal,
                         TSS_Session_GetSeq(&sess),
                         TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                         kparmbufsize, TCM_DATA_OFFSET ,
                         0, 0);
    TSS_SessionClose(&sess);
    if (ret != 0)
        return ret;

    /* convert the returned key to a structure */
    if (key != NULL)
        TSS_KeyExtract(&tcmdata, TCM_DATA_OFFSET  , key);

    /* copy the key blob to caller */
    if (keyblob != NULL) {
        memcpy(keyblob, &tcmdata.buffer[TCM_DATA_OFFSET ], kparmbufsize);
        if (bloblen != NULL) *bloblen = kparmbufsize;
    }
    return 0;
}


/****************************************************************************/
/*                                                                          */
/* Load a new Key into the TCM                                              */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of parent key for the new key                    */
/*           0x40000000 for the SRK                                         */
/* keyauth   is the authorization data (password) for the parent key        */
/*           if null, it is assumed that the parent requires no auth        */
/* keyparms  is a pointer to a keydata structure with all data  for the new */
/*           key                                                            */
/* newhandle is a pointer to a 32bit word which will receive the handle     */
/*           of the new key                                                 */
/*                                                                          */
/****************************************************************************/
uint32_t TCM_LoadKey(uint32_t keyhandle, unsigned char *keyauth,
                     keydata *keyparms, uint32_t *newhandle )
{
    uint32_t ret;
    STACK_TCM_BUFFER(tcmdata)
    STACK_TCM_BUFFER(kparmbuf)
    //unsigned char nonceodd[TCM_NONCE_SIZE];
    unsigned char pubauth[TCM_HASH_SIZE];
    unsigned char c = 0;
    uint32_t ordinal = htonl(TCM_ORD_LoadKey);

    uint32_t keyhndl;
    int      kparmbufsize;
    ret = needKeysRoom(keyhandle, 0, 0, 0  );
    if (ret != 0) {
        return ret;
    }

    /* check input arguments */
    if (keyparms == NULL || newhandle == NULL)
        return ERR_NULL_ARG;

    if (keyauth != NULL) { /* parent requires authorization */
        session sess;
        /* Open OIAP Session */
        ret = TSS_SessionOpen(SESSION_OSAP | SESSION_OIAP,
                              &sess,
                              keyauth, TCM_ET_KEYHANDLE, keyhandle);
        if (ret != 0) return ret;
        /* move Network byte order data to variables for hmac calculation */
        keyhndl = htonl(keyhandle);

        /* convert keyparm structure to buffer */
        ret = TCM_WriteKey(&kparmbuf, keyparms);
        if ((ret & ERR_MASK) != 0) {
            TSS_SessionClose(&sess);
            return ret;
        }
        kparmbufsize = ret;

        //TCM_dump_data("key2",kparmbuf.buffer,ret);

        /* calculate authorization HMAC value */
        ret = TSS_authhmac1(pubauth, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                            TSS_Session_GetSeq(&sess), c,
                            TCM_U32_SIZE, &ordinal,
                            //       TCM_U32_SIZE,&userid, //lyf
                            kparmbufsize, kparmbuf.buffer,
                            0, 0);
        if ((ret & ERR_MASK)) {
            TSS_SessionClose(&sess);
            return ret;
        }
        /* build the request buffer */

        ret = TSS_buildbuff("00 c2 T l l % L %", &tcmdata,
                            ordinal,
                            keyhndl,
                            kparmbuf.used, kparmbuf.buffer,
                            TSS_Session_GetHandle(&sess),
                            TCM_HASH_SIZE, pubauth);
        if ((ret & ERR_MASK) != 0) {
            TSS_SessionClose(&sess);
            return ret;
        }

        /* transmit the request buffer to the TCM device and read the reply */
        ret = TCM_Transmit(&tcmdata, "LoadKey - AUTH");
        if (ret != 0) {
            TSS_SessionClose(&sess);
            return ret;
        }
        ret = TSS_checkhmac1(&tcmdata, ordinal,
                             TSS_Session_GetSeq(&sess),
                             TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                             0, 0);

        TSS_SessionClose(&sess);
        if (ret != 0)
            return ret;

        ret = tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET , newhandle);
        if ((ret & ERR_MASK)) {
            return ret;
        }
    } else { /* parent requires NO authorization */
        /* move Network byte order data to variables for hmac calculation */
        keyhndl = htonl(keyhandle);
        /* convert keyparm structure to buffer */
        ret = TCM_WriteKey(&kparmbuf, keyparms);
        if ((ret & ERR_MASK) != 0) return ret;
        //kparmbufsize = ret;
        /* build the request buffer */
        /*   ret = TSS_buildbuff("00 c1 T l l l %",&tcmdata,
                           			ordinal,
                           			 userid,
                           			   keyhndl,
                           				 kparmbuf.used,kparmbuf.buffer);*/
        ret = TSS_buildbuff("00 c1 T  l l %", &tcmdata,
                            ordinal,
                            //	 userid,
                            keyhndl,
                            kparmbuf.used, kparmbuf.buffer);

        if ((ret & ERR_MASK) != 0) return ret;
        /* transmit the request buffer to the TCM device and read the reply */
        ret = TCM_Transmit(&tcmdata, "LoadKey-no auth");
        if (ret != 0) return ret;
        ret = tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET , newhandle);
        if ((ret & ERR_MASK)) {
            return ret;
        }
    }

    return 0;
}

/****************************************************************************/
/*                                                                          */
/* Load a new Key into the TCM                                              */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of parent key for the new key                    */
/*           0x40000000 for the SRK                                         */
/* keyauth   is the authorization data (password) for the parent key        */
/*           if null, it is assumed that the parent requires no auth        */
/* keyparms  is a pointer to a keydata structure with all data  for the new */
/*           key                                                            */
/* newhandle is a pointer to a 32bit word which will receive the handle     */
/*           of the new key                                                 */
/*                                                                          */
/****************************************************************************/

/****************************************************************************/
/*                                                                          */
/* Get a Public Key from the TCM                                            */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key to be read                            */
/*           0x40000000 for the SRK                                         */
/* keyauth   is the authorization data (password) for the key               */
/*           if null, it is assumed that the key requires no authorization  */
/* keyblob   is a pointer to an area which will receive a copy of the       */
/*           public key blob.                                               */
/* keyblen   is a pointer to an integer which will receive the length of    */
/*           the key blob                                                   */
/*                                                                          */
/****************************************************************************/
static uint32_t TCM_GetPubKey_Internal(uint32_t keyhandle,
                                       unsigned char *keyauth,
                                       pubkeydata *pk      )
{
    uint32_t ret;
    STACK_TCM_BUFFER(tcmdata)
    //unsigned char nonceodd[TCM_NONCE_SIZE];
    unsigned char pubauth[TCM_HASH_SIZE];
    unsigned char c = 0;
    uint32_t ordinal = htonl(TCM_ORD_GetPubKey);
    uint32_t keyhndl = htonl(keyhandle);

    int      size;

    /* check input arguments */
    if (pk == NULL) return ERR_NULL_ARG;
    if (keyauth != NULL) { /* key requires authorization */
        session sess;

        /* Open OIAP Session */
        ret = TSS_SessionOpen(SESSION_OSAP | SESSION_OIAP,
                              &sess,
                              keyauth, TCM_ET_KEYHANDLE, keyhandle);
        if (ret != 0) return ret;

        /* calculate authorization HMAC value */

        ret = TSS_authhmac1(pubauth, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE, TSS_Session_GetSeq(&sess), c,
                            TCM_U32_SIZE, &ordinal,
                            0, 0);

        if (ret != 0) {
            TSS_SessionClose(&sess);
            return ret;
        }
        /* build the request buffer */

        ret = TSS_buildbuff("00 c2 T l l L %", &tcmdata,
                            ordinal,
                            keyhndl,
                            TSS_Session_GetHandle(&sess),
                            TCM_HASH_SIZE, pubauth);
        if ((ret & ERR_MASK) != 0) {
            TSS_SessionClose(&sess);
            return ret;
        }
        /* transmit the request buffer to the TCM device and read the reply */
        ret = TCM_Transmit(&tcmdata, "GetKeyPubShort - AUTH");

        if (ret != 0) {
			TSS_SessionClose(&sess);
            return ret;
        }
        ret = TSS_PubKeyExtract(&tcmdata, TCM_DATA_OFFSET , pk); //later  change
        if ((ret & ERR_MASK)){
			TSS_SessionClose(&sess);
            return ret;
        }
        size = ret;

        ret = TSS_checkhmac1(&tcmdata, ordinal, TSS_Session_GetSeq(&sess), TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                             size, TCM_DATA_OFFSET ,
                             0, 0);
		TSS_SessionClose(&sess);
		
        if (ret != 0) return ret;
    } else { /* key requires NO authorization */
        /* build the request buffer */

        ret = TSS_buildbuff("00 c1 T l l", &tcmdata,
                            ordinal,
                            keyhndl);
        if ((ret & ERR_MASK) != 0) return ret;
        /* transmit the request buffer to the TCM device and read the reply */
        ret = TCM_Transmit(&tcmdata, "GetKeyPubShort - NO AUTH");
        if (ret != 0) return ret;
        ret = TSS_PubKeyExtract(&tcmdata, TCM_DATA_OFFSET , pk);
        if ((ret & ERR_MASK))
            return ret;
    }
    return 0;
}


uint32_t TCM_GetPubKey_UseRoom(uint32_t keyhandle,
                               unsigned char *keyauth,
                               pubkeydata *pk)
{
    uint32_t ret;
    uint32_t replaced_keyhandle;

    /* swap in keyhandle */
    ret = needKeysRoom_Stacked(keyhandle, &replaced_keyhandle          );
    if (ret != 0)
        return ret;

    ret = TCM_GetPubKey_Internal(keyhandle, keyauth, pk   );

    needKeysRoom_Stacked_Undo(keyhandle, replaced_keyhandle     );

    return ret;
}

uint32_t TCM_GetPubKey(uint32_t keyhandle,
                       unsigned char *keyauth,
                       pubkeydata *pk )
{
    uint32_t ret;

    ret = needKeysRoom(keyhandle, 0, 0, 0 );
    if (ret != 0)
        return ret;

    return TCM_GetPubKey_Internal(keyhandle, keyauth, pk   );
}

/****************************************************************************/
/*                                                                          */
/* Evict (delete) a  Key from the TCM                                       */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key to be evicted                         */
/*                                                                          */
/****************************************************************************/
static uint32_t TCM_EvictKey_Internal(uint32_t keyhandle,   int allowTransport)
{
    uint32_t ret;


    ret = TCM_FlushSpecific(keyhandle, TCM_RT_KEY, allowTransport);
    return ret;
}

uint32_t TCM_EvictKey_UseRoom(uint32_t keyhandle      )
{
    uint32_t ret;

    /*
     * To avoid recursion and major problems we assume for
     * this implementation here that the keyhandle is in
     * the TCM.
     *
     * uint32_t replaced_keyhandle;
     *
     * ret = needKeysRoom_Stacked(keyhandle, &replaced_keyhandle);
     * if (ret != 0)
     *        return 0;
     */

    ret = TCM_EvictKey_Internal(keyhandle,      0);

    /*
     * needKeysRoom_Stacked_Undo(0, replaced_keyhandle);
     */

    return ret;
}

/****************************************************************************/
/*                                                                          */
/* Calculate the size of a Key Blob                                         */
/*                                                                          */
/****************************************************************************/
int TSS_KeySize(const struct tcm_buffer *tb, unsigned int offset)
{

    unsigned int len;
    unsigned int offset_in = offset;
    unsigned int encLen;

    offset += TCM_U16_SIZE + TCM_U16_SIZE + TCM_U16_SIZE + TCM_U32_SIZE + 1; //keyType keyUsage keyFlags authDataUsage
    len = TSS_PubKeySize(tb, offset, 1);
    if ((len & ERR_MASK)) {
        return len;
    }
    offset += len;

    if (offset + 4 >= tb->used) {
        return ERR_STRUCTURE;
    }

    encLen = LOAD32(tb->buffer, offset); //pubkey size 64
    offset += TCM_U32_SIZE;
    offset += encLen;

    return (offset - offset_in);
}

/****************************************************************************/
/*                                                                          */
/* Calculate the size of a Public Key Blob                                  */
/*                                                                          */
/****************************************************************************/
//TCM_KeyPubShort_Store  length= TCM_CipherScheme_Store len + pubkey len
int TSS_PubKeySize(const struct tcm_buffer *tb, unsigned int offset, int pcrpresent)
{
    uint32_t parmsize;
    uint32_t pcrisize;
    uint32_t keylength;
    const unsigned char *keybuff = tb->buffer;
    uint32_t offset_in = offset;

    offset += TCM_U32_SIZE + TCM_U16_SIZE + TCM_U16_SIZE;
    if (offset + 4 >= tb->used) {
        return ERR_STRUCTURE;
    }
    parmsize = LOAD32(keybuff, offset);
    offset += TCM_U32_SIZE;
    offset += parmsize;
    if (pcrpresent) {
        if (offset + 4 >= tb->used) {
            return ERR_STRUCTURE;
        }
        pcrisize  = LOAD32(keybuff, offset);
        offset += TCM_U32_SIZE;
        offset += pcrisize;
    }
    if (offset + 4 >= tb->used) {
        return ERR_STRUCTURE;
    }
    keylength = LOAD32(keybuff, offset);
    offset += TCM_U32_SIZE;
    offset += keylength;
    if (offset > tb->used) {
        return ERR_STRUCTURE;
    }
    return (offset - offset_in);
}


