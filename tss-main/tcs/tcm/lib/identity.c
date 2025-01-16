/********************************************************************************/

/********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include <tcm.h>
#include <tcmfunc.h>
#include <tcmutil.h>
#include <oiaposap.h>
#include <hmac.h>
#include <tcm_types.h>
#include <tcm_constants.h>

/****************************************************************************/
/*                                                                          */
/* Generate a new Attestation Identity Key                                  */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle     is the handle of the key                                   */
/* identityauth  is the encrypted usage authorization data for the new     */
/*               identity                                                   */
/* identitylabel is a digest of the identity label for the new TPM identity */
/* keyparms      is a pointer to a key that contains information for the    */
/*               new key                                                    */
/* key           is a pointer to an area that will receive the newly        */
/*               created identity key                                       */
/* srkauth       is the authorization data for the inputs and the SRK       */
/* ownerAuth     is the authorization data of the owner                     */
/* idbinding     is a pointer to an area that will receive the signature of */
/*               TPM_IDENTITY_CONTENTS                                      */
/* idbindingsize must indicate the size of the idbinding area on input and  */
/*               will hold the used size in the idbinding area on output    */
/****************************************************************************/
uint32_t TCM_MakeIdentity(unsigned char *identityauth,
                          unsigned char *identitylabel,
                          keydata *keyparms,
                          keydata *key,
                          unsigned char *keyblob,
                          unsigned int  *keybloblen,
                          unsigned char *smkAuth,
                          unsigned char *ownerAuth,
                          unsigned char *idbinding,
                          uint32_t *idbsize,

                          pubkeydata *pubEK)
{
    uint32_t ret = 0;
    uint32_t ordinal_no = htonl(TCM_ORD_MakeIdentity);

    uint32_t keyhandle = 0x40000000;
    unsigned char continueAuthSession = 0;
    (void)idbinding;

    STACK_TCM_BUFFER(tcmdata)
    STACK_TCM_BUFFER(ser_key)

    unsigned char authdata[TCM_NONCE_SIZE];
    unsigned char authdata2[TCM_NONCE_SIZE];
    unsigned char dummy[TCM_HASH_SIZE];
    unsigned char encauth[TCM_NONCE_SIZE];
    session sess;
    session sess2;

    int      serkeysize;
    int      keylen;


    if (NULL == keyparms     ||
            NULL == key          ||
            NULL == identitylabel) {
        return ERR_NULL_ARG;
    }

    memset(dummy, 0x0, sizeof(dummy));
    if (NULL == identityauth)
        identityauth = dummy;

    /*
     * Serialize the key
     */
    serkeysize = TCM_WriteKey(&ser_key, keyparms);

    if (NULL != smkAuth) {




        ret = TSS_SessionOpen(SESSION_OSAP,
                              &sess2,
                              smkAuth, TCM_ET_KEYHANDLE, keyhandle);
        if (0 != ret) {
            return ret;
        }
        /*
         * Open OSAP session
         */
        ret = TSS_SessionOpen(SESSION_OSAP,
                              &sess, ownerAuth, TCM_ET_OWNER, 0);
        if (0 != ret) {
			TSS_SessionClose(&sess2);
            return ret;
        }

        /* Generate the encrypted usage authorization */
        /*	ret = tcm_sm2_encrypt_pubkey(identityauth, TCM_SECRET_SIZE,
        									pubEK->pubKey.modulus, pubEK->pubKey.keyLength,
        									&encauth, &encauthlen);*/
        ret = TCM_CreateEncAuth(&sess, identityauth, encauth);
		if (0 != ret) {
	        TSS_SessionClose(&sess);
	        return ret;
    	}

        ret = TSS_authhmac1(authdata, TSS_Session_GetAuth(&sess), TCM_NONCE_SIZE,
                            TSS_Session_GetSeq(&sess), continueAuthSession,
                            TCM_U32_SIZE, &ordinal_no,
                            TCM_HASH_SIZE, encauth,
                            TCM_HASH_SIZE, identitylabel,
                            serkeysize, ser_key.buffer,
                            0, 0);

        if (ret != 0) {
            TSS_SessionClose(&sess);
            TSS_SessionClose(&sess2);
            return ret;
        }


        ret = TSS_authhmac1(authdata2, TSS_Session_GetAuth(&sess2), TCM_NONCE_SIZE,
                            TSS_Session_GetSeq(&sess2), continueAuthSession,
                            TCM_U32_SIZE, &ordinal_no,
                            TCM_HASH_SIZE, encauth,
                            TCM_HASH_SIZE, identitylabel,
                            serkeysize, ser_key.buffer,
                            0, 0);

        if (ret != 0) {
            TSS_SessionClose(&sess);
            TSS_SessionClose(&sess2);
            return ret;
        }

        //       TCM_dump_data("encauth",encauth,TCM_HASH_SIZE);
        //       TCM_dump_data("identitylabel",identitylabel,TCM_HASH_SIZE);
        //       TCM_dump_data("ser_key",ser_key.buffer,serkeysize);
        //       TCM_dump_data("authdata2",authdata2,TCM_HASH_SIZE);
        //       TCM_dump_data("authdata",authdata,TCM_HASH_SIZE);
        ret = TSS_buildbuff("00 c3 T l % % % L % L %", &tcmdata,
                            ordinal_no,
                            TCM_HASH_SIZE, encauth,
                            TCM_HASH_SIZE, identitylabel,
                            serkeysize, ser_key.buffer,
                            TSS_Session_GetHandle(&sess2),
                            TCM_HASH_SIZE, authdata2,
                            TSS_Session_GetHandle(&sess),
                            TCM_HASH_SIZE, authdata);

        if (0 != (ret & ERR_MASK)) {
            TSS_SessionClose(&sess);
            TSS_SessionClose(&sess2);
            return ret;
        }
		
//#if defined(platform_C) || defined(platform_M) || defined(platform_2700)
//			system ("echo 1000 > /sys/module/httctdd/parameters/recv_mdelay");
//#endif

        ret = TCM_Transmit(&tcmdata, "MakeIdentity - AUTH2");
        if (0 != ret) {
            TSS_SessionClose(&sess);
            TSS_SessionClose(&sess2);
            return ret;
        }

//#if defined(platform_C) || defined(platform_M) || defined(platform_2700)
//			system ("echo 500 > /sys/module/httctdd/parameters/recv_mdelay");
//#endif

        /*
         * Have to deserialize the key
         */
        keylen = TSS_KeyExtract(&tcmdata,
                                TCM_DATA_OFFSET,
                                key);
        ret = tcm_buffer_load32(&tcmdata,
                                TCM_DATA_OFFSET + keylen,
                                idbsize);
        if ((ret & ERR_MASK)) {
            TSS_SessionClose(&sess);
            TSS_SessionClose(&sess2);
            return ret;
        }
        ret = TSS_checkhmac3(&tcmdata, ordinal_no,
                             TSS_Session_GetSeq(&sess2),
                             smkAuth,
                             TSS_Session_GetAuth(&sess2),
                             TCM_HASH_SIZE,
                             keylen + TCM_U32_SIZE + *idbsize,
                             TCM_DATA_OFFSET,
                             0, 0);


        TSS_SessionClose(&sess);
        TSS_SessionClose(&sess2);
    } else {

        ret = TSS_SessionOpen(SESSION_OSAP, &sess, ownerAuth, TCM_ET_OWNER, 0);
        if (0 != ret) {
            return ret;
        }

        /* Generate the encrypted usage authorization */
        /*		ret = tcm_sm2_encrypt_pubkey(identityauth, TCM_SECRET_SIZE,
        										pubEK->pubKey.modulus, pubEK->pubKey.keyLength,
        										&encauth, &encauthlen);*/

        ret = TCM_CreateEncAuth(&sess, identityauth, encauth);
		if (0 != ret) {
	        TSS_SessionClose(&sess);
	        return ret;
	    }

        ret = TSS_authhmac1(authdata, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                            TSS_Session_GetSeq(&sess), continueAuthSession,
                            TCM_U32_SIZE, &ordinal_no,
                            TCM_HASH_SIZE, encauth,
                            TCM_HASH_SIZE, identitylabel,
                            serkeysize, ser_key.buffer,
                            0, 0);
        if (0 != ret) {
            TSS_SessionClose(&sess);
            return ret;
        }

        ret = TSS_buildbuff("00 c2 T l @ % % L %", &tcmdata,
                            ordinal_no,
                            TCM_HASH_SIZE, encauth,
                            TCM_HASH_SIZE, identitylabel,
                            serkeysize, ser_key.buffer,
                            TSS_Session_GetHandle(&sess),
                            TCM_HASH_SIZE, authdata);

        if ((ret & ERR_MASK)) {
            TSS_SessionClose(&sess);
            return ret;
        }

        ret = TCM_Transmit(&tcmdata, "MakeIdentity");

        if (0 != ret) {
            TSS_SessionClose(&sess);
            return ret;
        }

        /*
         * Have to deserialize the key
         */
        keylen = TSS_KeyExtract(&tcmdata,
                                TCM_DATA_OFFSET,
                                key);
        ret = tcm_buffer_load32(&tcmdata,
                                TCM_DATA_OFFSET + keylen,
                                idbsize);
        if ((ret & ERR_MASK)) {
            TSS_SessionClose(&sess);
            return ret;
        }

        ret = TSS_checkhmac1(&tcmdata, ordinal_no,
                             TSS_Session_GetSeq(&sess),
                             TSS_Session_GetAuth(&sess),
                             TCM_HASH_SIZE,
                             keylen + TCM_U32_SIZE + *idbsize,
                             TCM_DATA_OFFSET,
                             0, 0);

        TSS_SessionClose(&sess);
    }

    /* extract the identity key blob, return to caller */
    if (ret == 0) {
        int len = TSS_KeySize(&tcmdata, TCM_DATA_OFFSET);
        if (keyblob != NULL) {
            memcpy(keyblob, &tcmdata.buffer[TCM_DATA_OFFSET], len);
            if (keybloblen != NULL) {
                *keybloblen = len ;
            }
        }
    }

    return ret;
}



