/********************************************************************************/

/********************************************************************************/

#ifndef OIAPOSAP_H
#define OIAPOSAP_H
#include <tcm.h>
#include <tcm_structures.h>


typedef struct apsess {
    uint32_t      handle;
    unsigned char seq[TCM_SEQ_SIZE];
    unsigned char ssecret[TCM_HASH_SIZE];
    uint16_t      etype;
} apsess;

typedef struct transess {
    uint32_t      handle;
    unsigned char seq[TCM_NONCE_SIZE];
} transess;

typedef struct session {
    uint32_t sess_type;   // see below
    union {
        apsess        ap;
        transess        tran;
    } type;
    unsigned char authdata[TCM_AUTHDATA_SIZE];
} session;

#define  SESSION_OIAP   1
#define  SESSION_OSAP   2
#define  SESSION_TRAN   4

uint32_t  TSS_HANDclose(apsess *sess,   TCM_BOOL ifCreateKey, TCM_RESOURCE_TYPE);
uint32_t  TSS_APopen(apsess *sess, const unsigned char *key, uint16_t etype, uint32_t evalue,   TCM_BOOL ifCreateKey);
uint32_t  TSS_APclose(apsess *sess,   TCM_BOOL ifCreateKey);

uint32_t TSS_SessionOpen(uint32_t allowed_type,
                         session *sess,
                         unsigned char *passHash, uint16_t etype, uint32_t evalue);
uint32_t TSS_SessionClose(session *sess);
uint32_t TSS_Session_CreateTransport(session *sess,
                                     unsigned char *transAuth,
                                     uint32_t transHandle,
                                     unsigned char *transNonce);
unsigned char *TSS_Session_GetAuth(session *sess);
unsigned char *TSS_Session_GetSeq(session *sess);
void TSS_Session_SetSeq(session *sess, const unsigned char *enonce);
void TSS_Session_UpdateSeq(session *sess);
uint32_t TSS_Session_GetHandle(session *sess);

#endif
