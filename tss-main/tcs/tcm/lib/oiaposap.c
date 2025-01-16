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
#include <tcm_constants.h>
#include <tcm_structures.h>
#include <tcm_error.h>
#include "tcmfunc.h"
#include <hmac.h>
#include <oiaposap.h>

void printfHex( char *name, unsigned char *buffer, unsigned int len)
{
    unsigned int i;
    printf("%s:\r\n", name);
    for(i = 0; i < len; i++) {
        if((i % 16 == 0) && (i))
            printf("\r\n");
        printf("%02x ", buffer[i]);


    }
    printf("\r\n");



}
void TCM_DetermineSessionEncryption(const session *sess, int *use_xor)
{
    const apsess *osap = &sess->type.ap;
    *use_xor = 1;
    if (sess->sess_type == SESSION_OSAP && (osap->etype >> 8) == TCM_ET_SM4_CTR) {
        *use_xor = 0;
    }
}

uint32_t TCM_CreateEncAuth(const session *sess, const unsigned char *in, unsigned char *out)
{
    int use_xor = 0;
	uint32_t ret = 0;
	
    TCM_DetermineSessionEncryption(sess, &use_xor);
    if (!use_xor) {
        unsigned char key[TCM_SECRET_SIZE];

        memcpy(key,
               TSS_Session_GetAuth((session *)sess),
               TCM_HASH_SIZE);

       ret = TCM_SymmetricKeyData_CtrCrypt(out,
                                      in,
                                      TCM_AUTHDATA_SIZE,
                                      key,
                                      TCM_SECRET_SIZE,
                                      sess->type.ap.seq,
                                      TCM_SEQ_SIZE);
	   return ret;
	  
    } else {
        uint32_t i;
        //unsigned char xorwork[TCM_HASH_SIZE];
        unsigned char xorhash[TCM_HASH_SIZE];
        /* calculate encrypted authorization value for new key */


        TSS_SM3(xorhash, TCM_SECRET_SIZE, TSS_Session_GetAuth((session *)sess), TCM_SEQ_SIZE, TSS_Session_GetSeq((session *)sess), 0, NULL);
		if(ret) return ret;
		
		for (i = 0; i < TCM_HASH_SIZE; i++)
            out[i] = xorhash[i] ^ in[i];
		
		return ret;
    }
}

/****************************************************************************/
/*                                                                          */
/* Open an AP session                                                     */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_APopen(apsess *sess, const unsigned char *key, uint16_t etype, uint32_t evalue,   TCM_BOOL ifCreateKey)
{
    STACK_TCM_BUFFER(tcmdata)
    uint32_t ret;
    TCM_NONCE		nonceOdd;
    TCM_NONCE		nonceEven;
    TCM_HMAC		inMac;
    TCM_HMAC		outMac;
    TCM_HMAC		testMac;
    TCM_COMMAND_CODE ordinal = TCM_ORD_AP;

    TCM_RESULT		nReturnCode;	/* returnCode in network byte order */
    TCM_COMMAND_CODE	nOrdinal;	/* ordinal in network byte order */
    TCM_USER_ID 	nUserID;	/*                       in network byte order */
    TCM_USER_RES   nPrivCode; 		/* privCode in network byte order */
    TCM_ENTITY_TYPE	nEntityType;/* entityType in network byte order */
    uint32_t		nEntityValue;	/* entityvalue in network byte order */
    TCM_BOOL valid = 0;

    const char *et_sm4 = getenv("TCM_ET_ENCRYPT_SM4");
    if (et_sm4 && !strcmp("1", et_sm4)) {
        etype |= (TCM_ET_SM4_CTR << 8);
    }


    memset(inMac, 0, TCM_AUTHDATA_SIZE);
    memset(outMac, 0, TCM_AUTHDATA_SIZE);
    /* check input arguments */
    if (key == NULL || sess == NULL)
        return ERR_NULL_ARG;

    TSS_gennonce(nonceOdd);
    /*calculate inMac*/
    nOrdinal = htonl(ordinal);
    nEntityType = htons(etype);
    nEntityValue = htonl(evalue);
    if ((etype != TCM_ET_NONE) && (evalue != TCM_KH_OWNER)) {
        ret = TSS_AuthHMAC3(inMac, key, TCM_HASH_SIZE,
                            TCM_NONCE_SIZE, nonceOdd,
                            sizeof(TCM_COMMAND_CODE), (unsigned char *)&nOrdinal,
                            sizeof(TCM_ENTITY_TYPE), &nEntityType,
                            0, NULL);

        if (ret != 0)  {
            return ret;
        }
    }

    //printf("etype = %04x",nEntityType);
    ret = TSS_buildbuff("00 C2 T 00 00 80 BF s l % %", &tcmdata,
                        nEntityType,  // user 0x20
                        nEntityValue,
                        TCM_NONCE_SIZE, nonceOdd,
                        TCM_DIGEST_SIZE, inMac);

    if ((ret & ERR_MASK) != 0) {
		return ret;
    }
    ret = TCM_Transmit(&tcmdata, "AP");
    if (ret != 0)  {
        return ret;
    }

    /*get nReturnCode*/

    ret = tcm_buffer_load32N(&tcmdata, TCM_RETURN_OFFSET, &nReturnCode);

    if ((ret & ERR_MASK)) {
        return ret;
    }

    /*get handle*/
    ret = tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET, &sess->handle);

    if ((ret & ERR_MASK)) {
        return ret;
    }

    /*get nonceEven and seq*/
    sess->etype = etype;

    memcpy(nonceEven, &(tcmdata.buffer[TCM_DATA_OFFSET + TCM_U32_SIZE]), TCM_NONCE_SIZE);
    //	printfHex("nonceEven",nonceEven,32);
    memcpy(sess->seq, &(tcmdata.buffer[TCM_DATA_OFFSET + TCM_U32_SIZE + TCM_NONCE_SIZE]), TCM_SEQ_SIZE);
    //	printfHex("sess->seq",sess->seq,TCM_SEQ_SIZE);
    if ((etype != TCM_ET_NONE) && (evalue != TCM_KH_OWNER)) {
        /*get outMac*/
        memcpy(outMac, &(tcmdata.buffer[TCM_DATA_OFFSET + TCM_U32_SIZE + TCM_NONCE_SIZE + TCM_SEQ_SIZE]), TCM_HASH_SIZE);
        //		printfHex("outMac",outMac,32);
        /*calculate outMac*/
        ret = TSS_CheckHMAC3(&valid, outMac, key,
                             TCM_SEQ_SIZE, sess->seq,
                             sizeof(TCM_RESULT), &nReturnCode,
                             sizeof(TCM_COMMAND_CODE), &nOrdinal,
                             TCM_NONCE_SIZE, nonceEven,

                             0, 0);
        //		printfHex("outMac",outMac,32);

        if(!valid) {
            printf("TSS_APopen: Error, outMac not match\n");
            return ERR_HMAC_FAIL;
        }


        /*calculate sessionSecret*/
        ret = TSS_rawhmac(sess->ssecret, key, TCM_HASH_SIZE,
                          TCM_SEQ_SIZE, sess->seq,
                          0, 0);
    }
    return ret;
}

/****************************************************************************/
/*                                                                          */
/* Close an AP session                                                    */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_APclose(apsess *sess,   TCM_BOOL ifCreateKey)
{
    uint32_t ret;

    if (sess == NULL)
        return ERR_NULL_ARG;
    ret = TSS_HANDclose(sess,      ifCreateKey, TCM_RT_AUTH);
    return ret;
}

/****************************************************************************/
/*                                                                          */
/* Terminate the Handle Opened by TCM_APOpen    */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_HANDclose(apsess *sess,   TCM_BOOL ifCreateKey, TCM_RESOURCE_TYPE rt)
{
    STACK_TCM_BUFFER(tcmdata)
    uint32_t ret;
    TCM_COMMAND_CODE ordinal = TCM_ORD_APTerminate;
    TCM_HMAC		inMac;
    uint32_t handle_no = htonl(sess->handle);
    TCM_COMMAND_CODE ordinal_no = htonl(ordinal);

    memset(inMac, 0, TCM_AUTHDATA_SIZE);

    if (sess->etype != TCM_ET_NONE) {
        /*seq + 1*/
        ret = TCM_session_seqAddOne(sess->seq);
        if (ret != 0)  {
            return ret;
        }

        /*calculate inMac*/
        ret = TSS_AuthHMAC3(inMac, sess->ssecret, TCM_HASH_SIZE,
                            TCM_SEQ_SIZE, sess->seq,
                            sizeof(TCM_COMMAND_CODE), &ordinal_no,
                            0, 0);
        if (ret != 0)  {
            return ret;
        }
    }

    ret = TSS_buildbuff("00 C2 T 00 00 80 C0  l %", &tcmdata,
                        handle_no,
                        TCM_DIGEST_SIZE, inMac);


    if ((ret & ERR_MASK) != 0) return ret;
	
//#if defined(platform_C) || defined(platform_M) || defined(platform_2700)
//		system ("echo 1000 > /sys/module/httctdd/parameters/recv_mdelay");
//#endif

    ret = TCM_Transmit(&tcmdata, "Terminate Handle");

//#if defined(platform_C) || defined(platform_M) || defined(platform_2700)
//		system ("echo 500 > /sys/module/httctdd/parameters/recv_mdelay");
//#endif
    if (ret == TCM_BAD_ORDINAL) {
        ret = TCM_FlushSpecific(sess->handle, rt, 0);
    }

    return ret;
}


uint32_t TSS_Session_CreateTransport(session *sess,
                                     unsigned char *transAuth,
                                     uint32_t transHandle,
                                     unsigned char *transSeq)
{
    sess->sess_type = SESSION_TRAN;
    memcpy(sess->authdata, transAuth, TCM_AUTHDATA_SIZE);
    sess->type.tran.handle = transHandle;
    TSS_Session_SetSeq(sess, transSeq);
    return 0;
}

uint32_t TSS_SessionOpen(uint32_t allowed_type,
                         session *sess,
                         unsigned char *passHash, uint16_t etype, uint32_t evalue)
{
    char *sess_str = getenv("TCM_SESSION");
    uint32_t want = 0;
    uint32_t have = SESSION_OIAP;
    TCM_BOOL ifCreateKey = FALSE;

    if(passHash) {
        memcpy(sess->authdata, passHash, TCM_AUTHDATA_SIZE);
    }

    if (etype == TCM_ET_KEY || etype == TCM_ET_KEYHANDLE) {
        needKeysRoom(evalue, 0, 0, -1);
    }

    if (NULL == passHash) {
        allowed_type &= SESSION_OIAP;
        if (0 == allowed_type) {
            printf("Bad allowed type! Need to be able to use OIAP session.\n");
            return ERR_BAD_ARG;
        }
        have = allowed_type;
    } else {
        if (NULL != sess_str) {
            if (0 == strcasecmp("osap", sess_str)) {
                want = SESSION_OSAP;
            } else if (0 == strcasecmp("oiap", sess_str)) {
                want = SESSION_OIAP;
            }
        }
        have = want & allowed_type;

        if (0 == have) {
            have = allowed_type;
        }
    }

    if (have & SESSION_OSAP) {
        sess->sess_type = SESSION_OSAP;
        ifCreateKey = TRUE;
        //		printf("sess->sess_type =SESSION_OSAP\n");

    } else {
        sess->sess_type = SESSION_OIAP;
        //		printf("sess->sess_type =SESSION_OIAP\n");
    }

    /*
     * Open an AP session
     */
    return TSS_APopen(&sess->type.ap,
                      passHash,
                      etype,
                      evalue,

                      ifCreateKey);

    return ERR_BAD_SESSION_TYPE;
}

uint32_t TSS_SessionClose(session *sess)
{
    TCM_BOOL ifCreateKey = FALSE;

    if (sess->sess_type == SESSION_OSAP) {
        ifCreateKey = TRUE;
    }
    switch (sess->sess_type) {
    case SESSION_OIAP:
    case SESSION_OSAP:
        return TSS_APclose(&sess->type.ap,      ifCreateKey);
        break;

    case SESSION_TRAN:
        printf("%s for Transport not implemented.\n",
               __FUNCTION__);
        break;
    }

    return ERR_BAD_ARG;
}

unsigned char *TSS_Session_GetAuth(session *sess)
{
    switch (sess->sess_type) {
    case SESSION_OIAP:
    case SESSION_TRAN:
        //			TCM_dump_data("sess->authdata=>",sess->authdata,TCM_AUTHDATA_SIZE);
        return sess->authdata;
        break;

    case SESSION_OSAP:
        //			TCM_dump_data("sess->type.ap.ssecret=>",sess->type.ap.ssecret,TCM_AUTHDATA_SIZE);
        return sess->type.ap.ssecret;
        break;

    }

    return NULL;
}

unsigned char *TSS_Session_GetSeq(session *sess)
{
    switch (sess->sess_type) {
    case SESSION_OIAP:
    case SESSION_OSAP:
        return sess->type.ap.seq;
        break;

    case SESSION_TRAN:
        return sess->type.tran.seq;
        break;
    }
    return NULL;
}

void TSS_Session_SetSeq(session *sess, const unsigned char *seq)
{
    unsigned char *ptr = NULL;
    switch (sess->sess_type) {
    case SESSION_OIAP:
    case SESSION_OSAP:
        ptr = sess->type.ap.seq;
        break;

    case SESSION_TRAN:
        ptr = sess->type.tran.seq;
        break;
    }
    if (ptr) {
        memcpy(ptr, seq, TCM_SEQ_SIZE);
    }
}

void TSS_Session_UpdateSeq(session *sess)
{
    switch (sess->sess_type) {
    case SESSION_OIAP:
    case SESSION_OSAP:
        TCM_session_seqAddOne(sess->type.ap.seq);
        break;

    case SESSION_TRAN:
        TCM_session_seqAddOne(sess->type.tran.seq);
        break;

    default:
        break;
    }
    return;
}

uint32_t TSS_Session_GetHandle(session *sess)
{
    switch (sess->sess_type) {
    case SESSION_OIAP:
    case SESSION_OSAP:
        return sess->type.ap.handle;
        break;

    case SESSION_TRAN:
        return sess->type.tran.handle;
        break;
    }
    return ERR_BAD_ARG;
}

/*not used*/
#if 0
uint32_t TCM_SetOwnerPointer(uint16_t entityType,
                             uint32_t entityValue)
{
    uint32_t ret;
    uint32_t ordinal_no = htonl(TCM_ORD_SetOwnerPointer);
    uint16_t entityType_no = htons(entityType);
    uint32_t entityValue_no = htonl(entityValue);
    STACK_TCM_BUFFER(tcmdata)

    ret = TSS_buildbuff("00 c1 T l s l", &tcmdata,
                        ordinal_no,
                        entityType_no,
                        entityValue_no);
    if ((ret & ERR_MASK)) {
        return ret;
    }

    ret = TCM_Transmit(&tcmdata, "SetOwnerPointer");

    return ret;
}
#endif

#if 0
uint32_t TCM_session_seqAddOne(TCM_NONCE seq)
{
    uint32_t rc = 0;
    int irc = 0;
    BIGNUM *seqBignum = NULL;

    seqBignum = BN_new();
    BN_bin2bn(seq, TCM_NONCE_SIZE, seqBignum);

    irc = BN_add_word(seqBignum, 1);
    if (irc != 1) {
        printf("TCM_session_seqAddOne: Error performing BN_add_word()\n");
        rc = TCM_BNADDONE_FAIL;
    }

    if (rc == 0) {
        BN_bn2bin(seqBignum, seq);
    }

    if (seqBignum) BN_free(seqBignum);
    return rc;
}
#else
uint32_t TCM_session_seqAddOne(TCM_NONCE seq)
{
    int i;
    unsigned int tmp;

    for(i = TCM_SEQ_SIZE - 1; i >= 0; i--) {
        tmp = seq[i];
        tmp++;

        seq[i] = (tmp & 0xFF);

        if((tmp >> 8) == 0)
            break;
    }

    return 0;
}

#endif

