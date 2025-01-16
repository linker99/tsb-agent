/*
 * activatepek.c
 *
 *  Created on: 2018-10-9
 *      Author: yhw
 */
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
#include <tcmkeys.h>
#include "tcm_sizedbuffer.h"
#include "sm_if.h"
#include "tcm_structures.h"
#include "tcm_key.h"
#include "tcm_store.h"

TCM_RESULT    TCM_TestSM2encrypt(void);
TCM_RESULT TCM_CreatePEKBlobCommon(TCM_SIZED_BUFFER *symData,
                                   TCM_SIZED_BUFFER *asymData,
                                   TCM_SIZED_BUFFER *symkey,
                                   unsigned char *inData,
                                   uint32_t	inDataLength);

TCM_RESULT TCM_CreatePEKBlobCommon(TCM_SIZED_BUFFER *symData,
                                   TCM_SIZED_BUFFER *asymData,
                                   TCM_SIZED_BUFFER *symkey,
                                   unsigned char *inData,
                                   uint32_t	inDataLength)
{
    TCM_RESULT	rc = 0;
    pubkeydata pubek;
    unsigned char *cipher_text;
    unsigned int cipher_text_len;

    printf("TCM_CreatePEKBlobCommon:\n");



    /*encrypt K, the key is R*/
    if (rc == 0) {
        rc = TCM_SizedBuffer_Allocate(symData, inDataLength);
    }
    if (rc == 0) {
        rc = TCM_SymmetricKeyData_CtrCrypt(symData->buffer,
                                           inData, inDataLength,
                                           symkey->buffer, symkey->size,
                                           symkey->buffer, symkey->size);
    }

    //get pub ek


    rc = TCM_ReadPubek(NULL, &pubek);
    if (rc != 0) {
        printf("Error %s from TCM_CreatePEKBlobCommon\n", TCM_GetErrMsg(rc));
        exit(-2);
    }

    TCM_dump_data("symkey######", symkey->buffer, symkey->size);
    TCM_dump_data("EK  pubek###############################", pubek.pubKey.modulus, pubek.pubKey.keyLength);

    /*encrypt symkey*/
    if (rc == 0) {
        rc = os_sm2_encrypt_pubkey(symkey->buffer, symkey->size, pubek.pubKey.modulus, pubek.pubKey.keyLength, &cipher_text, &cipher_text_len);
        TCM_SizedBuffer_Set(asymData, cipher_text_len, cipher_text);
    }

    return rc;
}





uint32_t    TCM_TestSM2encrypt(void)
{

    uint32_t  rc = 0;
    unsigned char	*d = NULL; /* private key */
    unsigned char	*P = NULL; /* public key */
    uint32_t privkey_len = 0, pubkey_len = 0;
    unsigned char data[16] = {0};
    unsigned char *cipher_text;
    unsigned int cipher_text_len;
    unsigned char *result;
    unsigned int result_len;

    memset(data, 1, 16);
    /*
    	unsigned char	d[32] = {	0xF3,0xAC,0x4B,0x23,0x2C,0x93,0x09,0xBE,0x8D,0x75,0x29,0xD1,0x97,0xD0,0x1F
    			,0xFE,0xF3,0xD1,0x99,0x56,0x13,0x4D,0x09,0x09,0x0A,0x10,0x4C,0xFB,0x7C,0xE1,0xAF,0x03};
    	unsigned char	P[64] = {0x9D,0xC0,0x5F,0x29,0x1B,0xB8,0x9B,0x11,0x7F,0x82,0xDA,0xCE,0xFE,
    			                  0xD6,0x5F,0xC4,0x16,0x92,0xA9,0x06,0x26,0xD6,0x19,0x5E,0x82,
    			                  0xC9,0x3E,0x1B,0x07,0x17,0x13,0x7C,
    			                  0xDF,0xF8,0xCC,0x33,0x27,0x2A,0xF6,0x97,0x4D,0x82,0xC9,0x3B
    			                  ,0x54,0x29,0x95,0x55,0x18,0x51,0x84,0xD5,0xDA,0x9F,0x41,0x74,0xC3
    			                  ,0xCC,0xA3,0x50,0xFA,0xA8,0x47,0x88};
    	uint32_t privkey_len = 32,pubkey_len = 64;

    */

    /* generate the key pair */
    if (rc == 0) {
        //	  rc = os_sm2_generate_key(&d,&privkey_len,&P,&pubkey_len);
    }

    if (rc == 0) {
        rc = os_sm2_encrypt_pubkey(data, 16, P, pubkey_len, &cipher_text, &cipher_text_len);
    }

    if (rc == 0) {
        TCM_dump_data("os_sm2_encrypt_pubkey  ######", cipher_text, cipher_text_len);
    }


    if (rc == 0) {
        rc = os_sm2_decrypt_prikey(cipher_text, cipher_text_len, d, privkey_len, &result, &result_len);

    }
    if (rc == 0) {
        TCM_dump_data("data  ######", result, result_len);
    }
    return 0;

}








