

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
#include <tcmkeys.h>

#include <tcmfunc.h>		/* kgold */



//encdata: used as input, would be updated after receiving response.

uint32_t
TCM_ChangeAuth(
    uint32_t keyhandle,
    unsigned char *parauth,
    unsigned char *oldauth, unsigned char *newauth,
    unsigned short etype,
    unsigned char *encdata, uint32_t encdatalen)
{
    uint32_t ret;

    STACK_TCM_BUFFER(tcmdata)
    unsigned char authdata[TCM_HASH_SIZE];
    unsigned char authdata2[TCM_HASH_SIZE];
    unsigned char encauth[TCM_HASH_SIZE];
    unsigned char c;
    uint32_t ordinal;
    uint16_t protocol;
    uint16_t entitytype;
    uint32_t keyhndl;
    uint16_t keytype;
    uint32_t reslen;
    session sess, sess2;
    uint32_t encdatalen_no = htonl(encdatalen);

    /* check input arguments */
    if (parauth == NULL || oldauth == NULL || newauth == NULL ||
            encdata == NULL)
        return ERR_NULL_ARG;

    /*	if (keyhandle == TCM_KH_SMK)
    		keytype = TCM_ET_SMK;
    	else*/
    keytype = TCM_ET_KEYHANDLE;

    ret = needKeysRoom(keyhandle, 0, 0, 0          );
    if (ret != 0) {
        return ret;
    }

    /* open OSAP session for parent key auth */
    ret = TSS_SessionOpen(SESSION_OSAP,
                          &sess,
                          parauth, keytype, keyhandle);
    if (ret != 0)
        return ret;

    /* open OIAP session for existing key auth */
    ret = TSS_SessionOpen(SESSION_OIAP,
                          &sess2,
                          oldauth, TCM_ET_NONE, 0);
    if (ret != 0) {
        TSS_SessionClose(&sess);
        return ret;
    }


    /* calculate encrypted authorization value for OSAP session */
    ret = TCM_CreateEncAuth(&sess, newauth, encauth);
	if (0 != ret) {
        TSS_SessionClose(&sess);
		 TSS_SessionClose(&sess2);
        return ret;
    }

    /* move Network byte order data to variables for HMAC calculation */
    ordinal = htonl(TCM_ORD_ChangeAuth);
    protocol = htons(0x0008);//protocol = htons(TPM_PID_ADCP);

    entitytype = htons(etype);
    keyhndl = htonl(keyhandle);
    c = 0;
    //
    /* calculate OSAP authorization HMAC value */

    ret = TSS_authhmac1(authdata, TSS_Session_GetAuth(&sess), TCM_NONCE_SIZE,
                        TSS_Session_GetSeq(&sess), c,
                        TCM_U32_SIZE, &ordinal,
                        TCM_U16_SIZE, &protocol,
                        TCM_HASH_SIZE, encauth,
                        TCM_U16_SIZE, &entitytype,
                        TCM_U32_SIZE, &encdatalen_no,
                        encdatalen, encdata,
                        0, 0);

    if (ret != 0) {
        TSS_SessionClose(&sess);
        TSS_SessionClose(&sess2);
        return ret;
    }


    ret = TSS_authhmac1(authdata2, TSS_Session_GetAuth(&sess2), TCM_NONCE_SIZE,
                        TSS_Session_GetSeq(&sess2), c,
                        TCM_U32_SIZE, &ordinal,
                        TCM_U16_SIZE, &protocol,
                        TCM_HASH_SIZE, encauth,
                        TCM_U16_SIZE, &entitytype,
                        TCM_U32_SIZE, &encdatalen_no,
                        encdatalen, encdata,
                        0, 0);

    if (ret != 0) {
        TSS_SessionClose(&sess);
        TSS_SessionClose(&sess2);
        return ret;
    }




    /* build the request buffer */

    ret = TSS_buildbuff("00 C3 T l l s % s @ L % L %", &tcmdata,
                        ordinal,
                        keyhndl,
                        protocol,
                        TCM_HASH_SIZE, encauth,
                        entitytype,
                        encdatalen, encdata,
                        TSS_Session_GetHandle(&sess),
                        TCM_HASH_SIZE, authdata,
                        TSS_Session_GetHandle(&sess2),
                        TCM_HASH_SIZE, authdata2);

    if ((ret & ERR_MASK) != 0) {
        TSS_SessionClose(&sess);
        TSS_SessionClose(&sess2);
        return ret;
    }
    /* transmit the request buffer to the TCM device and read the reply */
    ret = TCM_Transmit(&tcmdata, "ChangeAuth - AUTH2");


    if (ret != 0) {
        TSS_SessionClose(&sess);
        TSS_SessionClose(&sess2);
        return ret;
    }
    ret = tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET , &reslen);
    if ((ret & ERR_MASK)) {
        TSS_SessionClose(&sess);
        TSS_SessionClose(&sess2);
        return ret;
    }

    /* check HMAC in response */
    ret = TSS_checkhmac3(&tcmdata, ordinal,
                         TSS_Session_GetSeq(&sess), newauth,
                         TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                         TCM_U32_SIZE, TCM_DATA_OFFSET ,
                         reslen, TCM_DATA_OFFSET + TCM_U32_SIZE ,
                         0, 0);
    TSS_SessionClose(&sess);
    TSS_SessionClose(&sess2);
    if (ret != 0)
        return ret;
    /* copy updated key blob back to caller */
    memcpy(encdata,
           &tcmdata.buffer[TCM_DATA_OFFSET + TCM_U32_SIZE ], reslen);
    return 0;
}

/****************************************************************************/
/*                                                                          */
/* Change the Authorization for the Storage Root Key                        */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* ownauth   is the     authorization data (password) for the TCM Owner     */
/* newauth   is the new authorization data (password) for the SMK           */
/*           all authorization values must be 32 bytes long                 */
/*                                                                          */
/****************************************************************************/
uint32_t
TCM_ChangeAuthOwner(unsigned char *ownauth, uint16_t entityType,
                    unsigned char *oldauth, unsigned char *newauth)
{
    uint32_t ret;

    STACK_TCM_BUFFER(tcmdata)
    session sess;
    unsigned char authdata[TCM_HASH_SIZE];
    unsigned char encauth[TCM_HASH_SIZE];
    unsigned char c = 0;
    uint32_t ordinal = htonl(TCM_ORD_ChangeAuthOwner);
    uint16_t entitytype_no = htons(TCM_ET_SMK);
    uint16_t protocolID = htons(0x0008);
    /* check input arguments */
    if (ownauth == NULL || newauth == NULL)
        return ERR_NULL_ARG;

    if (entityType != TCM_ET_SMK && entityType != TCM_ET_OWNER)
        return ERR_BAD_ARG;

    entitytype_no = htons(entityType);

    /* open OSAP session for owner auth */
    ret = TSS_SessionOpen(SESSION_OSAP, &sess, ownauth, TCM_ET_OWNER, 0);

    if (ret != 0)
        return ret;

    /* calculate encrypted authorization value for OSAP session */
    ret = TCM_CreateEncAuth(&sess, newauth, encauth);
	if (0 != ret) {
        TSS_SessionClose(&sess);
        return ret;
    }



    //   TCM_dump_data("oldauth->",oldauth,TCM_NONCE_SIZE);
    /* calculate OSAP authorization HMAC value */

    ret = TSS_authhmac1(authdata, TSS_Session_GetAuth(&sess), TCM_NONCE_SIZE,
                        TSS_Session_GetSeq(&sess), c,
                        TCM_U32_SIZE, &ordinal,
                        TCM_U16_SIZE, &protocolID,
                        TCM_HASH_SIZE, encauth,
                        TCM_U16_SIZE, &entitytype_no,
                        0, 0);

    if (ret != 0) {
        TSS_SessionClose(&sess);
        return ret;
    }
    /* build the request buffer */
    ret = TSS_buildbuff("00 C2 T l 00 08 % s L  %", &tcmdata,
                        ordinal,
                        TCM_HASH_SIZE, encauth,
                        entitytype_no,
                        TSS_Session_GetHandle(&sess),
                        TCM_HASH_SIZE, authdata);

    if ((ret & ERR_MASK) != 0) {
        TSS_SessionClose(&sess);
        return ret;
    }
    /* transmit the request buffer to the TCM device and read the reply */
    ret = TCM_Transmit(&tcmdata, "ChangeAuthOwner - AUTH1");

    if (ret != 0) {
        TSS_SessionClose(&sess);
        return ret;
    }
    /* check HMAC in response */
    ret = TSS_checkhmac2(&tcmdata, ordinal,
                         TSS_Session_GetSeq(&sess),
                         newauth,
                         TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                         0, 0);

    TSS_SessionClose(&sess);
    return ret;
}

