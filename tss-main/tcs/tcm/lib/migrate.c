/********************************************************************************/

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
#include <tcmkeys.h>
#include <oiaposap.h>
#include <tcmfunc.h>
#include <hmac.h>

/****************************************************************************/
/*                                                                          */
/* Authorize a Migration Key                                                */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* ownpass   is a pointer to the Owner password (20 bytes)                  */
/* migtype   is an integer containing 1 for normal migration and 2 for      */
/*           rewrap migration                                               */
/* keyblob   is a pointer to an area containing the migration public         */
/*           encrypted key blob                                             */
/* migblob   is a pointer to an area which will receive the migration       */
/*           key authorization blob                                         */
/*                                                                          */
/****************************************************************************/
uint32_t
TCM_AuthorizeMigrationKey(unsigned char *ownerauth,
                          int migtype,
                          struct tcm_buffer *keyblob,
                          struct tcm_buffer *migblob)
{
    uint32_t ret;

    STACK_TCM_BUFFER(tcmdata)
    unsigned char pubauth[TCM_HASH_SIZE];
    unsigned char c = 0;
    uint32_t ordinal = htonl(TCM_ORD_AuthorizeMigrationKey);
    uint16_t migscheme = htons(migtype);
    uint32_t size;
    session sess;
    /* check input arguments */
    if (keyblob == NULL || migblob == NULL || ownerauth == NULL)
        return ERR_NULL_ARG;

    /* Open OIAP Session */
    ret = TSS_SessionOpen(SESSION_OSAP | SESSION_OIAP,
                          &sess, ownerauth, TCM_ET_OWNER, 0);

    if (ret != 0)
        return ret;

    /* calculate authorization HMAC value */
    ret = TSS_authhmac1(pubauth, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                        TSS_Session_GetSeq(&sess), c,
                        TCM_U32_SIZE, &ordinal,
                        TCM_U16_SIZE, &migscheme,
                        keyblob->used, keyblob->buffer,
                        0, 0);
    if (ret != 0) {
        TSS_SessionClose(&sess);
        return ret;
    }
    /* build the request buffer */



    ret = TSS_buildbuff("00 c2 T l s % L %", &tcmdata,
                        ordinal,
                        migscheme,
                        keyblob->used, keyblob->buffer,
                        TSS_Session_GetHandle(&sess),
                        TCM_HASH_SIZE, pubauth);
    if ((ret & ERR_MASK) != 0) {
        TSS_SessionClose(&sess);
        return ret;
    }
    /* transmit the request buffer to the TPM device and read the reply */
    ret = TCM_Transmit(&tcmdata, "AuthorizeMigrationKey - AUTH1");
    if (ret != 0) {
        TSS_SessionClose(&sess);
        return ret;
    }

    size = TSS_PubKeySize(&tcmdata, TCM_DATA_OFFSET , 0);
    if ((size & ERR_MASK)) {
        TSS_SessionClose(&sess);
        return size;
    }

    size += TCM_U16_SIZE + TCM_HASH_SIZE;	/* size of MigrationKeyAuth blob */
    ret = TSS_checkhmac1(&tcmdata, ordinal,
                         TSS_Session_GetSeq(&sess),
                         TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                         size, TCM_DATA_OFFSET ,
                         0, 0);

    TSS_SessionClose(&sess);
    if (ret != 0)
        return ret;

    SET_TCM_BUFFER(migblob, &tcmdata.buffer[TCM_DATA_OFFSET ], size);

    return 0;
}


/****************************************************************************/
/*                                                                          */
/* Create Migration Blob                                                    */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the parent key of the key to                  */
/*           be migrated.                                                   */
/* keyauth   is the authorization data (password) for the parent key        */
/*           if null, it is assumed that the parent requires no auth        */
/* migauth   is the authorization data (password) for migration of          */
/*           the key being migrated                                         */
/*           all authorization values must be 20 bytes long                 */
/* migtype   is an integer containing 1 for normal migration and 2 for      */
/*           rewrap migration                                               */
/* migblob   is a pointer to an area to containing the migration key        */
/*           authorization blob.                                            */
/* migblen   is an integer containing the length of the migration key       */
/*           authorization blob                                             */
/* keyblob   is a pointer to an area which contains the                     */
/*           encrypted key blob of the key being migrated                   */
/* keyblen   is an integer containing the length of the encrypted key       */
/*           blob for the key being migrated                                */
/* rndblob   is a pointer to an area which will receive the random          */
/*           string for XOR decryption of the migration blob                */
/* rndblen   is a pointer to an integer which will receive the length       */
/*           of the random XOR string                                       */
/* outblob   is a pointer to an area which will receive the migrated        */
/*           key                                                            */
/* outblen   is a pointer to an integer which will receive the length       */
/*           of the migrated key                                            */
/*                                                                          */
/****************************************************************************/
uint32_t
TCM_CreateMigrationBlob(unsigned int keyhandle,
                        unsigned char *keyauth,
                        unsigned char *migauth,
                        int migtype,
                        unsigned char *migblob,
                        uint32_t migblen,
                        unsigned char *keyblob,
                        uint32_t keyblen,
                        unsigned char *rndblob,
                        uint32_t *rndblen,
                        unsigned char *outblob,
                        uint32_t *outblen
                       )
{
    uint32_t ret;

    ALLOC_TCM_BUFFER(tcmdata, 0 )
    unsigned char c = 0;
    uint32_t ordinal = htonl(TCM_ORD_CreateMigrationBlob);
    uint32_t keyhandle_no = htonl(keyhandle);
    unsigned char authdata[TCM_HASH_SIZE];
    unsigned char authdata2[TCM_HASH_SIZE];
    uint16_t migscheme = htons(migtype);
    uint32_t size1;
    uint32_t size2;
    uint32_t keyblen_no = ntohl(keyblen);
    session sess;
    session sess2;

    if (NULL == tcmdata) {
        return ERR_MEM_ERR;
    }

    /* check input arguments */
    if (migauth == NULL || migblob == NULL || keyblob == NULL) {
        FREE_TCM_BUFFER(tcmdata);
        return ERR_NULL_ARG;
    }
    if (rndblob == NULL || rndblen == NULL || outblob == NULL ||
            outblen == NULL) {
        FREE_TCM_BUFFER(tcmdata);
        return ERR_NULL_ARG;
    }

    ret = needKeysRoom(keyhandle, 0, 0, 0 );
    if (ret != 0) {
        goto exit;
    }

    /* open AP sessions*/
    ret = TSS_SessionOpen(SESSION_OSAP | SESSION_OIAP,
                          &sess,
                          keyauth, TCM_ET_KEYHANDLE, keyhandle);
    if (ret != 0) {
        goto exit;
    }


    ret = TSS_SessionOpen(SESSION_OIAP, &sess2, migauth, TCM_ET_NONE, 0);
    if (ret != 0) {
        TSS_SessionClose(&sess);
        goto exit;
    }

    /* calculate authorization HMAC value */

    ret = TSS_authhmac1(authdata, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                        TSS_Session_GetSeq(&sess), c,
                        TCM_U32_SIZE, &ordinal,
                        TCM_U16_SIZE, &migscheme,
                        migblen, migblob,
                        TCM_U32_SIZE, &keyblen_no,
                        keyblen, keyblob,
                        0, 0);

    if (ret != 0) {
        TSS_SessionClose(&sess);
        TSS_SessionClose(&sess2);
        goto exit;
    }

    ret = TSS_authhmac1(authdata2, TSS_Session_GetAuth(&sess2), TCM_HASH_SIZE,
                        TSS_Session_GetSeq(&sess2), c,
                        TCM_U32_SIZE, &ordinal,
                        TCM_U16_SIZE, &migscheme,
                        migblen, migblob,
                        TCM_U32_SIZE, &keyblen_no,
                        keyblen, keyblob,
                        0, 0);

    if (ret != 0) {
        TSS_SessionClose(&sess);
        TSS_SessionClose(&sess2);
        goto exit;
    }



    /* build the request buffer */
    ret = TSS_buildbuff("00 c3 T l l s % @ L % L %",
                        tcmdata, ordinal,
                        keyhandle_no,
                        migscheme,
                        migblen, migblob,
                        keyblen, keyblob,
                        TSS_Session_GetHandle(&sess),
                        TCM_HASH_SIZE, authdata,
                        TSS_Session_GetHandle(&sess2),
                        TCM_HASH_SIZE, authdata2);

    if ((ret & ERR_MASK) != 0) {
        TSS_SessionClose(&sess);
        TSS_SessionClose(&sess2);
        goto exit;
    }
    /* transmit the request buffer to the TPM device and read the reply */
    ret = TCM_Transmit(tcmdata, "CreateMigrationBlob - AUTH3");
    if (ret != 0) {
        TSS_SessionClose(&sess);
        TSS_SessionClose(&sess2);
        goto exit;
    }
    /* validate HMAC in response */
    ret = tcm_buffer_load32(tcmdata, TCM_DATA_OFFSET , &size1);
    if ((ret & ERR_MASK)) {
		TSS_SessionClose(&sess);
        TSS_SessionClose(&sess2);
        goto exit;
    }
    ret = tcm_buffer_load32(tcmdata,
                            TCM_DATA_OFFSET + TCM_U32_SIZE + size1 , &size2);
    if ((ret & ERR_MASK)) {
		TSS_SessionClose(&sess);
        TSS_SessionClose(&sess2);
        goto exit;
    }

    ret = TSS_checkhmac3(tcmdata, ordinal,
                         TSS_Session_GetSeq(&sess), migauth,
                         TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                         TCM_U32_SIZE + size1 + TCM_U32_SIZE + size2, TCM_DATA_OFFSET ,
                         0, 0);

    TSS_SessionClose(&sess);
    TSS_SessionClose(&sess2);
    if (ret != 0)
        goto exit;

    memcpy(rndblob,
           &tcmdata->buffer[TCM_DATA_OFFSET + TCM_U32_SIZE ], size1);
    memcpy(outblob,
           &tcmdata->buffer[TCM_DATA_OFFSET + TCM_U32_SIZE + size1 +
                            TCM_U32_SIZE ], size2);

    *rndblen = size1;
    *outblen = size2;
exit:
    FREE_TCM_BUFFER(tcmdata);
    return ret;
}

/****************************************************************************/
/*                                                                          */
/* Convert a Migration Blob                                                */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the new parent key of the key                 */
/*           being migrated                                                 */
/* keyauth   is the authorization data (password) for the parent key        */
/* rndblob   is a pointer to an area containing the random XOR data         */
/* rndblen   is an integer containing the length of the random XOR data     */
/* keyblob   is a pointer to an area containing the migration public        */
/*           encrypted key blob                                             */
/* keyblen   is an integer containing the length of the migration           */
/*           public key blob                                                */
/* encblob   is a pointer to an area which will receive the migrated        */
/*           key re-encrypted private key blob                              */
/* endblen   is a pointer to an integer which will receive size of          */
/*           the migrated key re-encrypted private key blob                 */
/*                                                                          */
/****************************************************************************/
uint32_t
TCM_ConvertMigrationBlob(unsigned int parentkeyhandle,
                         unsigned int migkeyhandle,
                         unsigned char *parentkeyauth,
                         unsigned char *migkeyauth,
                         unsigned char *rndblob,
                         uint32_t rndblen,
                         unsigned char *keyblob,
                         uint32_t keyblen,
                         unsigned char *encblob,
                         uint32_t *encblen
                        )
{
    uint32_t ret;

    STACK_TCM_BUFFER(tcmdata)
    unsigned char pubauth[TCM_HASH_SIZE];
    unsigned char keyauth[TCM_HASH_SIZE];
    unsigned char c = 0;
    uint32_t ordinal_no = htonl(TCM_ORD_ConvertMigrationBlob);
    uint32_t pkeyhandle_no;
    uint32_t mkeyhandle_no;
    uint32_t rndsize;
    uint32_t keysize;
    uint32_t size;

    /* check input arguments */
    if (rndblob == NULL ||
            keyblob == NULL || encblob == NULL || encblen == NULL)
        return ERR_NULL_ARG;

    pkeyhandle_no = htonl(parentkeyhandle);
    mkeyhandle_no = htonl(migkeyhandle);
    rndsize = htonl(rndblen);
    keysize = htonl(keyblen);

    ret = needKeysRoom(parentkeyhandle, migkeyhandle, 0, 0 );
    if (ret != 0) {
        return ret;
    }



//    TCM_dump_data("rndblob###############", rndblob, rndblen);
//    TCM_dump_data("keyblob##############", keyblob, keyblen);

    if (NULL != migkeyauth) {


        session sess;
        session sess2;

        /* Open AP Session */
        ret = TSS_SessionOpen(SESSION_OSAP | SESSION_OIAP,
                              &sess,
                              parentkeyauth, TCM_ET_KEYHANDLE, parentkeyhandle);
        if (ret != 0)
            return ret;

        ret = TSS_SessionOpen(SESSION_OIAP,
                              &sess2,
                              migkeyauth, TCM_ET_NONE, 0);
        if (ret != 0){
			TSS_SessionClose(&sess);
            return ret;
        }

        /* calculate authorization HMAC value */
        if(rndblen == 0) {
            ret = TSS_authhmac1(pubauth, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                                TSS_Session_GetSeq(&sess), c,
                                TCM_U32_SIZE, &ordinal_no,
                                TCM_U32_SIZE, &rndsize,
                                TCM_U32_SIZE, &keysize,
                                keyblen, keyblob,
                                0, 0);
        } else {
            ret = TSS_authhmac1(pubauth, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                                TSS_Session_GetSeq(&sess), c,
                                TCM_U32_SIZE, &ordinal_no,
                                TCM_U32_SIZE, &rndsize,
                                rndblen, rndblob,
                                TCM_U32_SIZE, &keysize,
                                keyblen, keyblob,
                                0, 0);
        }


        if (ret != 0) {
            TSS_SessionClose(&sess);
            TSS_SessionClose(&sess2);
            return ret;
        }

        /* calculate authorization HMAC value */

        if(rndblen == 0) {

            ret = TSS_authhmac1(keyauth, TSS_Session_GetAuth(&sess2), TCM_HASH_SIZE,
                                TSS_Session_GetSeq(&sess2), c,
                                TCM_U32_SIZE, &ordinal_no,
                                TCM_U32_SIZE, &rndsize,
                                TCM_U32_SIZE, &keysize,
                                keyblen, keyblob,
                                0, 0);

        } else {
            ret = TSS_authhmac1(keyauth, TSS_Session_GetAuth(&sess2), TCM_HASH_SIZE,
                                TSS_Session_GetSeq(&sess2), c,
                                TCM_U32_SIZE, &ordinal_no,
                                TCM_U32_SIZE, &rndsize,
                                rndblen, rndblob,
                                TCM_U32_SIZE, &keysize,
                                keyblen, keyblob,
                                0, 0);
        }

        if (ret != 0) {
            TSS_SessionClose(&sess);
            TSS_SessionClose(&sess2);
            return ret;
        }

        /* build the request buffer */


        ret = TSS_buildbuff("00 c3 T l l l @ @ L % L %", &tcmdata,
                            ordinal_no,
                            pkeyhandle_no,
                            mkeyhandle_no,
                            rndblen, rndblob,
                            keyblen, keyblob,
                            TSS_Session_GetHandle(&sess),
                            TCM_HASH_SIZE, pubauth,
                            TSS_Session_GetHandle(&sess2),
                            TCM_HASH_SIZE, keyauth);

        if ((ret & ERR_MASK) != 0) {
            TSS_SessionClose(&sess);
            TSS_SessionClose(&sess2);
            return ret;
        }

        /* transmit the request buffer to the TPM device and read the reply */
        ret = TCM_Transmit(&tcmdata, "ConvertMigrationBlob - AUTH2");

        if (ret != 0) {
			TSS_SessionClose(&sess);
            TSS_SessionClose(&sess2);
            return ret;
        }
        ret = tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET , &size);
        if ((ret & ERR_MASK)) {
			TSS_SessionClose(&sess);
            TSS_SessionClose(&sess2);
            return ret;
        }
        ret = TSS_checkhmac3(&tcmdata, ordinal_no,
                             TSS_Session_GetSeq(&sess), migkeyauth,
                             TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                             TCM_U32_SIZE + size, TCM_DATA_OFFSET ,
                             0, 0);
		
		TSS_SessionClose(&sess);
        TSS_SessionClose(&sess2);
		
        if (ret != 0){
			
            return ret;        
        }
        memcpy(encblob,
               &tcmdata.buffer[TCM_DATA_OFFSET + TCM_U32_SIZE ], size);
        *encblen = size;
    } else {
        session sess;

        /* Open AP Session */
        ret = TSS_SessionOpen(SESSION_OSAP | SESSION_OIAP,
                              &sess,
                              parentkeyauth, TCM_ET_KEYHANDLE, parentkeyhandle);
        if (ret != 0)
            return ret;

        /* calculate authorization HMAC value */
        ret = TSS_authhmac1(pubauth, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                            TSS_Session_GetSeq(&sess), c,
                            TCM_U32_SIZE, &ordinal_no,
                            TCM_U32_SIZE, &rndsize,
                            rndblen, rndblob,
                            TCM_U32_SIZE, &keysize,
                            keyblen, keyblob,
                            0, 0);

        if (ret != 0) {
            TSS_SessionClose(&sess);
            return ret;
        }

        /* build the request buffer */


        ret = TSS_buildbuff("00 c2 T l l l @ @ L  %", &tcmdata,
                            ordinal_no,
                            pkeyhandle_no,
                            mkeyhandle_no,
                            rndblen, rndblob,
                            keyblen, keyblob,
                            TSS_Session_GetHandle(&sess),
                            TCM_HASH_SIZE, pubauth);

        if ((ret & ERR_MASK) != 0) {
            TSS_SessionClose(&sess);
            return ret;
        }

        /* transmit the request buffer to the TPM device and read the reply */
        ret = TCM_Transmit(&tcmdata, "ConvertMigrationBlob - AUTH1");
        if (ret != 0) {
			TSS_SessionClose(&sess);
            return ret;
        }

        ret = tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET , &size);
        if ((ret & ERR_MASK)) {
			TSS_SessionClose(&sess);
            return ret;
        }
        ret = TSS_checkhmac1(&tcmdata, ordinal_no,
                             TSS_Session_GetSeq(&sess),
                             TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                             TCM_U32_SIZE + size, TCM_DATA_OFFSET ,
                             0, 0);
		TSS_SessionClose(&sess);
        if (ret != 0){			
            return ret;
        }

        memcpy(encblob,
               &tcmdata.buffer[TCM_DATA_OFFSET + TCM_U32_SIZE ], size);
        *encblen = size;
    }

    return 0;
}


