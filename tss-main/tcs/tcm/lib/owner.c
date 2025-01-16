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
#include <tcmfunc.h>
#include <tcmutil.h>
#include <tcmkeys.h>
#include <tcm_constants.h>
#include <oiaposap.h>
#include <hmac.h>
#include <sm_if.h>

/****************************************************************************/
/*                                                                          */
/*  Take Ownership of the TCM                                               */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* ownpass   is the authorization data (password) for the new owner         */
/* srkpass   is the authorization data (password) for the new root key      */
/*           if NULL, authorization required flag is turned off             */
/*           both authorization values must be 20 bytes long                */
/* key       a pointer to a keydata structure to receive the SRK public key */
/*           or NULL if this information is not required                    */
/*                                                                          */
/****************************************************************************/
uint32_t TCM_TakeOwnership(unsigned char *ownpass,
                           unsigned char *smkpass,
                           uint32_t keylen,
                           unsigned char *pcrInfoBuffer,
                           uint32_t pcrInfoSize,
                           unsigned char *iv,   //must be 16-byte long
                           keydata *key) //out
{
    uint32_t ret;
    int iret;
    STACK_TCM_BUFFER(tcmdata)                       /* request/response buffer */
    pubkeydata tcmpubkey;                           /* public endorsement key data */
    uint32_t smkparamsize;                          /* SRK parameter buffer size */
    keydata smk;                                    /* key info for SRK */
    unsigned char dummypass[TCM_HASH_SIZE];         /* dummy smk password */
    unsigned char *spass;                           /* pointer to smkpass or dummy */

    /* data to be inserted into Take Owner Request Buffer (in Network Byte Order) */
    /* the uint32_t and uint16_t values are stored in network byte order so they
    ** are in the correct format when being hashed by the HMAC calculation */
    uint32_t command;                                /* command ordinal */
    uint16_t protocol;
    uint32_t oencdatasize;                           /* owner auth data encrypted size */
    unsigned char *ownerencr = NULL;                 /* owner auth data encrypted */
    uint32_t sencdatasize;                           /* smk auth data encrypted size */
    unsigned char *smkencr = NULL;                   /* smk auth data encrypted */

    uint32_t oencdatasize_n;
    uint32_t sencdatasize_n;
    TCM_SYMMETRIC_KEY_PARMS  KeyParms;
    STACK_TCM_BUFFER(keyparamsbuf);


    STACK_TCM_BUFFER(smk_param_buff)
    unsigned char authdata[TCM_HASH_SIZE];           /* auth data */
    session sess;
    STACK_TCM_BUFFER(response);
    /* check that parameters are valid */
    if (ownpass == NULL)
        return ERR_NULL_ARG;
    if (smkpass == NULL) {
        memset(dummypass, 0, sizeof dummypass);
        spass = dummypass;
    } else {
        spass = smkpass;
    }

    /* set up command and protocol values for TakeOwnership function */
    command =  htonl(TCM_ORD_TakeOwnership);
    protocol = htons(TCM_PID_OWNER);
    /* get the TCM Endorsement Public Key */
    ret = TCM_ReadPubek(NULL, &tcmpubkey);  //
    if (ret)
        return ret;


    iret = os_sm2_encrypt_pubkey(ownpass, TCM_HASH_SIZE,
                                  tcmpubkey.pubKey.modulus, tcmpubkey.pubKey.keyLength,
                                  &ownerencr, &oencdatasize);

    if (iret != 0) {
        ret = ERR_CRYPT_ERR;
        goto failexit;
    }

    iret = os_sm2_encrypt_pubkey(spass, TCM_HASH_SIZE,
                                  tcmpubkey.pubKey.modulus, tcmpubkey.pubKey.keyLength,
                                  &smkencr, &sencdatasize);

    if (iret != 0) {
        ret = ERR_CRYPT_ERR;
        goto failexit;
    }

    /* fill the SRK-params key structure */
    memset(&smk, 0x0, sizeof(smk));
    smk.hdr.key12.tag = TCM_TAG_KEY;
    smk.hdr.key12.fill = 0;
    smk.pub.algorithmParms.algorithmID = TCM_ALG_SM4;
    /* Should be ignored, but a certain HW TCM requires the correct encScheme */
    smk.pub.algorithmParms.encScheme = TCM_ES_SM4_CBC;
    smk.pub.algorithmParms.sigScheme = 0;
    smk.pub.algorithmParms.parmSize = 28;
    smk.pub.algorithmParms.sm4para.keyLength = 128;
    smk.pub.algorithmParms.sm4para.blockSize = 128;
    smk.pub.algorithmParms.sm4para.ivSize = 16;
    memset(smk.pub.algorithmParms.sm4para.IV, 0, 16);
    smk.keyUsage = TCM_SM4KEY_STORAGE;
    smk.authDataUsage = TCM_AUTH_ALWAYS;
    smk.keyFlags =  0;



    smk.pub.pcrInfo.size = 0;
    smk.pub.pcrInfo.size = pcrInfoSize;
    memcpy(smk.pub.pcrInfo.buffer, pcrInfoBuffer, pcrInfoSize);


    /* convert to a memory buffer */
    smkparamsize =  TCM_WriteKey(&smk_param_buff, &smk);

    /* initiate the OIAP protocol */

    ret = TSS_SessionOpen(SESSION_OIAP,  /* only OIAP ! */
                          &sess,
                          ownpass, TCM_ET_NONE, 0);



    if (ret != 0) {
        goto failexit;
    }
    /* calculate the Authorization Data */
    oencdatasize_n = htonl(oencdatasize);
    sencdatasize_n = htonl(sencdatasize);

    ret = TSS_AuthHMAC3(authdata, TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                        TCM_SEQ_SIZE, TSS_Session_GetSeq(&sess),
                        TCM_U32_SIZE, &command,
                        TCM_U16_SIZE , &protocol,
                        TCM_U32_SIZE, &oencdatasize_n,
                        oencdatasize, ownerencr,
                        TCM_U32_SIZE, &sencdatasize_n,
                        sencdatasize, smkencr,
                        smkparamsize, smk_param_buff.buffer,
                        0, 0);


    if (ret != 0) {
        TSS_SessionClose(&sess);
        goto failexit;
    }

    /* insert all the calculated fields into the request buffer */
    ret = TSS_buildbuff("00 c2 T l s @ @ % L  %", &tcmdata,
                        command,
                        protocol,
                        oencdatasize, ownerencr,
                        sencdatasize, smkencr,
                        smkparamsize, smk_param_buff.buffer,
                        TSS_Session_GetHandle(&sess),
                        TCM_HASH_SIZE, authdata);


    if ((ret & ERR_MASK) != 0) {
        TSS_SessionClose(&sess);
        goto failexit;
    }
	
//#if defined(platform_C) || defined(platform_M) || defined(platform_2700)
//	system ("echo 1000 > /sys/module/httctdd/parameters/recv_mdelay");
//#endif

    /* transmit the request buffer to the TCM device and read the reply */
    ret = TCM_Transmit(&tcmdata, "Take Ownership");

//#if defined(platform_C) || defined(platform_M) || defined(platform_2700)
//	system ("echo 500 > /sys/module/httctdd/parameters/recv_mdelay");
//#endif

    if (ret != 0) {
        TSS_SessionClose(&sess);
        goto failexit;
    }
    /* check the response HMAC */

    smkparamsize = TSS_KeySize(&tcmdata, TCM_DATA_OFFSET );
    if ((smkparamsize & ERR_MASK)) {
        //		printf("11111111111111111\n");
        TSS_SessionClose(&sess);
        ret = smkparamsize;
        goto failexit;
    }

    ret = TSS_checkhmac1(&tcmdata, command,
                         TSS_Session_GetSeq(&sess),
                         TSS_Session_GetAuth(&sess), TCM_HASH_SIZE,
                         smkparamsize, TCM_DATA_OFFSET ,
                         0, 0);
    TSS_SessionClose(&sess);
    //	printf("222222222222222\n");
    if (ret != 0) {
        goto failexit;
    }
    /* convert the returned key to a structure */
    if (key == NULL) {
        goto failexit;
    }
    //TSS_KeyExtract(&tcmdata, TCM_DATA_OFFSET, key);
    TSS_KeyExtract(&tcmdata, TCM_DATA_OFFSET , key);

   // return ret;

failexit:
    if (smkencr) free(smkencr);
    if (ownerencr) free(ownerencr);

    return ret;
}




uint32_t TSC_PhysicalPresence(uint16_t ppresence)
{
    uint32_t ret;
    uint32_t ordinal_no = htonl(TSC_ORD_PhysicalPresence);
    STACK_TCM_BUFFER(tcmdata)
    uint16_t ppresence_no = htons(ppresence);

    ret = TSS_buildbuff("00 c1 T l  s", &tcmdata,
                        ordinal_no,
                        ppresence_no);
    if ((ret & ERR_MASK)) {
        return ret;
    }

    ret = TCM_Transmit(&tcmdata, "PhysicalPresence");

    if (ret == 0 && tcmdata.used != TCM_DATA_OFFSET) {
        ret = ERR_BAD_RESP;
    }

    return ret;
}
