

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
#include <tcm_structures.h>
#include <tcmfunc.h>
#include <oiaposap.h>
#include <hmac.h>
#include <pcrs.h>

#define MAXPCRINFOLEN ( (TCM_HASH_SIZE * 2) + TCM_U16_SIZE + TCM_PCR_MASK_SIZE )

/****************************************************************************/
/*                                                                          */
/* Seal a data object with caller Specified PCR info                        */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key used to seal the data                 */
/*           0x40000000 for the SRK                                         */
/* pcrinfo   is a pointer to a TPM_PCR_INFO structure containing            */
/*           a bit map of the PCR's to seal the data to, and a              */
/*           pair of TPM_COMPOSITE_HASH values for the PCR's                */
/* pcrinfosize is the length of the pcrinfo structure                       */
/* keyauth   is the authorization data (password) for the key               */
/* dataauth  is the authorization data (password) for the data being sealed */
/*           both authorization values must be 20 bytes long                */
/* data      is a pointer to the data to be sealed                          */
/* datalen   is the length of the data to be sealed (max 256?)              */
/* blob      is a pointer to an area to received the sealed blob            */
/*           it should be long enough to receive the encrypted data         */
/*           which is 256 bytes, plus some overhead. 512 total recommended? */
/* bloblen   is a pointer to an integer which will receive the length       */
/*           of the sealed blob                                             */
/*                                                                          */
/****************************************************************************/
uint32_t TCM_Seal(       uint32_t keyhandle,
                         unsigned char *pcrinfo, uint32_t pcrinfosize,
                         unsigned char *keyauth,
                         unsigned char *dataauth,
                         unsigned char *data, uint32_t datalen,
                         unsigned char *blob, uint32_t *bloblen)
{
    uint32_t ret = 0;
    session sess;
    unsigned char encauth[TCM_HASH_SIZE];
    unsigned char pubauth[TCM_HASH_SIZE];
    unsigned char dummyauth[TCM_HASH_SIZE];
    //unsigned char nonceodd[TCM_NONCE_SIZE];
    TCM_BOOL c = 0;
    uint32_t ordinal = htonl(TCM_ORD_Seal);
    uint32_t pcrsize = htonl(pcrinfosize);
    uint32_t datsize = htonl(datalen);
    uint32_t keyhndl = htonl(keyhandle);
    ALLOC_TCM_BUFFER(tcmdata, 0)
    uint16_t keytype;
    unsigned char *passptr1;
    unsigned char *passptr2;
    uint32_t    sealinfosize;
    uint32_t    encdatasize;
    uint32_t    storedsize;

    if (NULL == tcmdata) {
        return ERR_MEM_ERR;
    }

    /* check input arguments */
    if (data == NULL ||
            blob == NULL) {
        FREE_TCM_BUFFER(tcmdata);
        return ERR_NULL_ARG;
    }
    if (pcrinfosize != 0 &&
            pcrinfo == NULL) {
        FREE_TCM_BUFFER(tcmdata);
        return ERR_NULL_ARG;
    }

    ret = needKeysRoom(keyhandle, 0, 0, 0          );
    if (ret != 0) {
        goto exit;
    }

    memset(dummyauth, 0, sizeof dummyauth);

    if (keyhandle == 0x40000000) keytype = TCM_ET_SMK;
    else                         keytype = TCM_ET_KEYHANDLE;
    if (keyauth  == NULL) passptr1 = dummyauth;
    else                  passptr1 = keyauth;
    if (dataauth == NULL) passptr2 = dummyauth;
    else                  passptr2 = dataauth;

    /* Open OSAP Session */
    ret = TSS_SessionOpen(SESSION_OSAP/*|SESSION_DSAP*/, &sess, passptr1, keytype, keyhandle);
    if (ret != 0) {
        goto exit;
    }
    /* calculate encrypted authorization value */
    ret = TCM_CreateEncAuth(&sess, passptr2, encauth);
	if(ret){
		TSS_SessionClose(&sess);
		return ret;
	}
    /* generate odd nonce */
    //TSS_gennonce(nonceodd);
    /* move Network byte order data to variables for hmac calculation */

    /* calculate authorization HMAC value */
    if (pcrinfosize == 0) {
        /* no pcr info specified */
        ret = TSS_authhmac1(pubauth, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                            TSS_Session_GetSeq(&sess), c,
                            TCM_U32_SIZE, &ordinal,
                            TCM_HASH_SIZE, encauth,
                            TCM_U32_SIZE, &pcrsize,
                            TCM_U32_SIZE, &datsize,
                            datalen, data, 0, 0);
    } else {
        /* pcr info specified */
        ret = TSS_authhmac1(pubauth, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                            TSS_Session_GetSeq(&sess), c,
                            TCM_U32_SIZE, &ordinal,
                            TCM_HASH_SIZE, encauth,
                            TCM_U32_SIZE, &pcrsize,
                            pcrinfosize, pcrinfo,
                            TCM_U32_SIZE, &datsize,
                            datalen, data, 0, 0);
    }
    if (ret != 0) {
        TSS_SessionClose(&sess);
        goto exit;
    }
    /* build the request buffer */

    ret = TSS_buildbuff("00 C2 T l l % @ @ L %", tcmdata,
                        ordinal,
                        keyhndl,
                        TCM_HASH_SIZE, encauth,
                        pcrinfosize, pcrinfo,
                        datalen, data,
                        TSS_Session_GetHandle(&sess),
                        TCM_HASH_SIZE, pubauth);
    if ((ret & ERR_MASK) != 0) {
        TSS_SessionClose(&sess);
        goto exit;
    }
    /* transmit the request buffer to the TPM device and read the reply */
    ret = TCM_Transmit(tcmdata, "Seal - AUTH");
    if (ret != 0) {
        TSS_SessionClose(&sess);
        goto exit;
    }
    /* calculate the size of the returned Blob */
    ret = tcm_buffer_load32(tcmdata, TCM_DATA_OFFSET + TCM_U32_SIZE , &sealinfosize);
    if ((ret & ERR_MASK)) {
        TSS_SessionClose(&sess);
        goto exit;
    }
    ret  = tcm_buffer_load32(tcmdata, TCM_DATA_OFFSET + TCM_U32_SIZE + TCM_U32_SIZE + sealinfosize , &encdatasize);
    if ((ret & ERR_MASK)) {
        TSS_SessionClose(&sess);
        goto exit;
    }
    storedsize   = TCM_U32_SIZE + TCM_U32_SIZE + sealinfosize + TCM_U32_SIZE + encdatasize;
    /* check the HMAC in the response */
    ret = TSS_checkhmac1(tcmdata, ordinal,
                         TSS_Session_GetSeq(&sess), TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                         storedsize, TCM_DATA_OFFSET ,
                         0, 0);
    if (ret != 0) {
        TSS_SessionClose(&sess);
        goto exit;
    }

    TSS_SessionClose(&sess);
    /* copy the returned blob to caller */
	if((int)storedsize > (int)*bloblen){
		ret = ERR_BUFFER;
		goto exit;
	}
    memcpy(blob, &tcmdata->buffer[TCM_DATA_OFFSET ], storedsize);
    *bloblen = storedsize;

exit:
    FREE_TCM_BUFFER(tcmdata);
    return ret;
}


/****************************************************************************/
/*                                                                          */
/* Unseal a data object                                                     */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key used to seal the data                 */
/*           0x40000000 for the SRK                                         */
/* keyauth   is the authorization data (password) for the key               */
/*           or NULL if no password is required                             */
/* dataauth  is the authorization data (password) for the data being sealed */
/*           or NULL if no password is required                             */
/*           both authorization values must be 20 bytes long                */
/* blob      is a pointer to an area to containing the sealed blob          */
/* bloblen   is the length of the sealed blob                               */
/* rawdata   is a pointer to an area to receive the unsealed data (max 256?)*/
/* datalen   is a pointer to a int to receive the length of the data        */
/*                                                                          */
/****************************************************************************/
uint32_t TCM_Unseal(       uint32_t keyhandle,
                           unsigned char *keyauth,
                           unsigned char *dataauth,
                           unsigned char *blob, uint32_t bloblen,
                           unsigned char *rawdata, uint32_t *datalen)
{
    uint32_t ret;
    STACK_TCM_BUFFER(tcmdata)
    unsigned char dummyauth[TCM_NONCE_SIZE];
    unsigned char *passptr1;
    unsigned char *passptr2;
    unsigned char c = 0;
    uint32_t ordinal = htonl(TCM_ORD_Unseal);
    uint32_t keyhndl = htonl(keyhandle);

    unsigned char authdata[TCM_HASH_SIZE];
    unsigned char authdata2[TCM_HASH_SIZE];
    session sess;
    session sess2;
    ret = needKeysRoom(keyhandle, 0, 0, 0          );
    if (ret != 0) {
        return ret;
    }

    //TSS_gennonce(nonceodd);
    memset(dummyauth, 0, sizeof dummyauth);
    /* check input arguments */
    if (rawdata == NULL || blob == NULL) return ERR_NULL_ARG;
    if (dataauth == NULL) passptr2 = dummyauth;
    else                  passptr2 = dataauth;
    if (keyauth == NULL) passptr1 = dummyauth;
    else                 passptr1 = keyauth;


    if (passptr1 != NULL) {


        /* open TWO OIAP sessions, one for the Key and one for the Data */
        ret = TSS_SessionOpen(SESSION_OSAP/*|SESSION_DSAP*/,
                              &sess,
                              passptr1, TCM_ET_KEYHANDLE, keyhandle);
        if (ret != 0)
            return ret;

        ret = TSS_SessionOpen(SESSION_OIAP,
                              &sess2,
                              passptr2, TCM_ET_NONE, 0);

        if (ret != 0) {
            TSS_SessionClose(&sess);
            return ret;
        }

        /* calculate KEY authorization HMAC value */
        ret = TSS_authhmac1(authdata, TSS_Session_GetAuth(&sess), TCM_NONCE_SIZE,
                            TSS_Session_GetSeq(&sess), c,
                            TCM_U32_SIZE, &ordinal,
                            bloblen, blob,
                            0, 0);
        if (ret != 0) {
            TSS_SessionClose(&sess);
            TSS_SessionClose(&sess2);

            return ret;
        }

        /* calculate DATA authorization HMAC value */
        ret = TSS_authhmac1(authdata2, TSS_Session_GetAuth(&sess2), TCM_NONCE_SIZE,
                            TSS_Session_GetSeq(&sess2), c,
                            TCM_U32_SIZE, &ordinal,
                            bloblen, blob,
                            0, 0);
        if (ret != 0) {
            TSS_SessionClose(&sess);
            TSS_SessionClose(&sess2);
            return ret;
        }

        /* build the request buffer */

        ret = TSS_buildbuff("00 C3 T l l % L % L %", &tcmdata,
                            ordinal,
                            keyhndl,
                            bloblen, blob,
                            TSS_Session_GetHandle(&sess),
                            TCM_HASH_SIZE, authdata,
                            TSS_Session_GetHandle(&sess2),
                            TCM_HASH_SIZE, authdata2);

        if ((ret & ERR_MASK) != 0) {
            TSS_SessionClose(&sess);
            TSS_SessionClose(&sess2);
            return ret;
        }
        /* transmit the request buffer to the TPM device and read the reply */
        ret = TCM_Transmit(&tcmdata, "Unseal - AUTH");
		
        if (ret != 0) {
			TSS_SessionClose(&sess);
			TSS_SessionClose(&sess2);
			return ret;
		}

        ret = tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET , datalen);
        if ((ret & ERR_MASK)) {
			TSS_SessionClose(&sess);
            TSS_SessionClose(&sess2);
            return ret;
        }

        /* check HMAC in response */
        ret = TSS_checkhmac3(&tcmdata, ordinal,
                             TSS_Session_GetSeq(&sess), keyauth,
                             TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                             TCM_U32_SIZE, TCM_DATA_OFFSET ,
                             *datalen, TCM_DATA_OFFSET + TCM_U32_SIZE ,
                             0, 0);


    }
#if 0
    else /* no key password */ {
        /* open ONE OIAP session, for the Data */
        ret = TSS_SessionOpen(SESSION_OIAP,
                              &sess,
                              passptr2, 0, 0);
        if (ret != 0)
            return ret;
        /* calculate DATA authorization HMAC value */
        ret = TSS_authhmac(authdata2,/*passptr2*/TSS_Session_GetAuth(&sess), TPM_NONCE_SIZE,/*enonce2*/TSS_Session_GetENonce(&sess), nonceodd, c,
                           TPM_U32_SIZE, &ordinal,
                           bloblen, blob, 0, 0);
        if (ret != 0) {
            TSS_SessionClose(&sess);
            return ret;
        }
        /* build the request buffer */
        ret = TSS_buildbuff("00 C2 T l l % L % o %", &tpmdata,
                            ordinal,
                            keyhndl,
                            bloblen, blob,
                            TSS_Session_GetHandle(&sess),
                            TPM_NONCE_SIZE, nonceodd,
                            c,
                            TPM_HASH_SIZE, authdata2);

        if ((ret & ERR_MASK) != 0) {
            TSS_SessionClose(&sess);
            return ret;
        }
        /* transmit the request buffer to the TPM device and read the reply */
        ret = TPM_Transmit(&tpmdata, "Unseal - AUTH1");

        TSS_SessionClose(&sess);

        if (ret != 0) {
            return ret;
        }
        ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, datalen);
        if ((ret & ERR_MASK)) {
            return ret;
        }
        /* check HMAC in response */
        ret = TSS_checkhmac1(&tpmdata, ordinal, nonceodd,
                             TSS_Session_GetAuth(&sess), TPM_HASH_SIZE,
                             TPM_U32_SIZE, TPM_DATA_OFFSET,
                             *datalen, TPM_DATA_OFFSET + TPM_U32_SIZE,
                             0, 0);
    }
#endif
    TSS_SessionClose(&sess);
    TSS_SessionClose(&sess2);
    if (ret != 0) {
        return ret;
    }
    /* copy decrypted data back to caller */
    memcpy(rawdata,
           &tcmdata.buffer[TCM_DATA_OFFSET + TCM_U32_SIZE ],
           *datalen);
    return ret;
}

static uint32_t MGF1_encrypt(unsigned char *data, uint32_t datalen,
                             session *sess,
                             //  unsigned char *nonceodd,
                             unsigned char *output)
{
    uint32_t seedsize;
    struct tcm_buffer *seed;
    uint32_t ret = 0;
    uint32_t i;

    seed = TSS_AllocTCMBuffer(TCM_NONCE_SIZE + sizeof("XOR") - 1 + TCM_HASH_SIZE);
    if (NULL == seed) {
        return ERR_MEM_ERR;
    }

    ret = TSS_buildbuff("% % %", seed,
                        TCM_NONCE_SIZE, TSS_Session_GetSeq(sess),
                        //TCM_NONCE_SIZE, nonceodd,
                        sizeof("XOR") - 1, "XOR",
                        TCM_HASH_SIZE, TSS_Session_GetAuth(sess));
    if ((ret & ERR_MASK) != 0) {
        goto exit;
    }
    seedsize = ret;
    TSS_KDF1(output,
             datalen,
             seed->buffer,
             seedsize);

    for (i = 0; i < datalen; i++) {
        output[i] = output[i] ^ data[i];
    }

exit:
    TSS_FreeTCMBuffer(seed);
    return 0;
}


static uint32_t AES_CTR_crypt(unsigned char *data, uint32_t datalen,
                              const session *sess,
                              //unsigned char *nonceodd,
                              unsigned char *output)
{
    uint32_t ret = 0;
    //AES_KEY aeskey;
    unsigned char ivec[TCM_HASH_SIZE];
    //unsigned char work[TCM_NONCE_SIZE * 2];
    //int rc;
#if 0
    rc = AES_set_encrypt_key(TSS_Session_GetAuth((session *)sess),
                             TPM_AES_BITS,
                             &aeskey);
    (void)rc;
#endif
    //memcpy(&work[00], TSS_Session_GetSeq((session *)sess), TCM_NONCE_SIZE);
    //memcpy(&work[TCM_NONCE_SIZE],
    //                  nonceodd, TCM_NONCE_SIZE);
    TSS_sm3(TSS_Session_GetSeq((session *)sess), TCM_NONCE_SIZE, ivec);

    TCM_SM4_ctr128_encrypt(output,
                           data,
                           datalen,
                           TSS_Session_GetAuth((session *)sess),
                           ivec);


    return ret;
}

static uint32_t Sealx_DataEncrypt(unsigned char *data, uint32_t datalen,
                                  session *sess,
                                  // unsigned char *nonceodd,
                                  unsigned char *output)
{
    uint32_t ret = 0;
    int use_xor = 0;

    TCM_DetermineSessionEncryption(sess, &use_xor);
    if (use_xor) {
        ret = MGF1_encrypt(data, datalen,
                           sess,
                           //  nonceodd,
                           output);
    } else {
        ret = AES_CTR_crypt(data, datalen,
                            sess,
                            //   nonceodd,
                            output);
    }
    return ret;
}




static uint32_t MGF1_decrypt(unsigned char *data, uint32_t datalen,
                             session *sess,
                             //unsigned char *nonceodd,
                             unsigned char *output)
{
    unsigned char *x1;
    struct tcm_buffer *seed;
    uint32_t seedsize;
    uint32_t ret = 0;
    uint32_t i = 0;
    /*
     * Decrypt the data we have received using MGF1 decryption...
     * Build the seed first
     */
    x1 = malloc(datalen);
    if (NULL == x1) {
        return ERR_MEM_ERR;
    }

    seed = TSS_AllocTCMBuffer(TCM_NONCE_SIZE + sizeof("XOR") - 1 + TCM_HASH_SIZE);
    if (NULL == seed) {
        free(x1);
        return ERR_MEM_ERR;
    }

    ret = TSS_buildbuff("% % %", seed,
                        TCM_NONCE_SIZE, TSS_Session_GetSeq(sess),
                        // TCM_NONCE_SIZE, nonceodd,
                        sizeof("XOR") - 1, "XOR",
                        TCM_HASH_SIZE, TSS_Session_GetAuth(sess));
    if ((ret & ERR_MASK) != 0) {
        goto exit;
    }
    seedsize = ret;
    TSS_KDF1(x1,
             datalen,
             seed->buffer,
             seedsize);

    for (i = 0; i < datalen; i++) {
        output[i] = x1[i] ^ data[i];
    }
    ret = 0;
    //	printf("    MGF1_decrypt: output %x %x %x %x\n", output[0], output[1], output[2], output[3]);

    //printf("MGF1 dec. success! \n");
exit:
    TSS_FreeTCMBuffer(seed);
    free(x1);
    return ret;
}

//equal TCM_SealCryptCommon
static uint32_t Sealx_DataDecrypt(unsigned char *data, uint32_t datalen,
                                  session *sess,
                                  // unsigned char *nonceodd,
                                  unsigned char *output)
{
    uint32_t ret = 0;
    int use_xor = 0;

    TCM_DetermineSessionEncryption(sess, &use_xor);
    if (use_xor) {
        ret = MGF1_decrypt(data, datalen,
                           sess,
                           //    nonceodd,
                           output);
    } else {
        ret = AES_CTR_crypt(data, datalen,
                            sess,
                            //nonceodd,
                            output);
    }
    return ret;
}

