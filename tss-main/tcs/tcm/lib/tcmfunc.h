

#ifndef TCMFUNC_H
#define TCMFUNC_H

#include <stdarg.h>
#include <stdint.h>
#include <tcmkeys.h>
#include <tcmutil.h>
#include "crypto/sm/sm2_if.h"
#include <oiaposap.h>
#include <tcm_structures.h>


void printfHex( char *name, unsigned char *buffer, unsigned int len);


/* section 3: Admin startup and state */

uint32_t TCM_Init(void); /* just for testing */
uint32_t TCM_Startup(uint16_t type);
\
/* section 4: Testing */



/*PEK*/





/*key exchange*/





/* section 5: Admin Opt-in */


uint32_t TCM_PhysicalEnable(TCM_BOOL state);

uint32_t  TCM_PhysicalSetDeactivated(TCM_BOOL state);




/* Basic TCM_ commands */


uint32_t TCM_CreateRevocableEK(TCM_BOOL genreset,
                               unsigned char *inputekreset,
                               unsigned char *resetEKbuff);




uint32_t TCM_ReadPubek(unsigned char *ownauth, pubkeydata *k);


/* section 6: admin ownership */
uint32_t TCM_TakeOwnership(unsigned char *ownpass,
                           unsigned char *smkpass,
                           uint32_t keylen,
                           unsigned char *pcrInfoBuffer,
                           uint32_t pcrInfoSize,
                           unsigned char *iv,   //must be 16-byte long
                           keydata *key);



uint32_t TSC_PhysicalPresence(uint16_t ppresence);

/* section 8: auditing */





uint32_t TCM_CreateWrapKey(uint32_t keyhandle,
                           unsigned char *keyauth, unsigned char *newauth,
                           unsigned char *migauth,
                           keydata *keyparms,

                           keydata *key,
                           unsigned char *keyblob, unsigned int *bloblen);


uint32_t TCM_EvictKey_UseRoom(uint32_t keyhandle );

/* section 9: Administrative functions: Management */


/* section 15: Identity creation and activation */
uint32_t TCM_MakeIdentity(unsigned char *identityauth,
                          unsigned char *identitylabel,
                          keydata *keyparms,
                          keydata *key,
                          unsigned char *keyblob,
                          unsigned int  *keybloblen,
                          unsigned char *srkAuth,
                          unsigned char *ownerAuth,
                          unsigned char *idbinding,
                          uint32_t *idbsize,

                          pubkeydata *pubEK);


/* Section 16: Integrity collection and reporting */



uint32_t TCM_PcrRead(  uint32_t pcrindex, unsigned char *pcrvalue);




/* Section 17: Authorization Changing */

uint32_t TCM_ChangeAuth(
    uint32_t keyhandle,
    unsigned char *parauth,
    unsigned char *oldauth, unsigned char *newauth,
    unsigned short etype,
    unsigned char *encdata, uint32_t encdatalen);
uint32_t TCM_ChangeAuthOwner(unsigned char *ownauth, uint16_t entityType,
                             unsigned char *oldauth, unsigned char *newauth);

/* Section 18 */

uint32_t TCM_session_seqAddOne(TCM_NONCE seq);



/* Section 21: Session Management */


uint32_t TCM_SaveContext_UseRoom(uint32_t handle,
                                 uint32_t resourceType,
                                 char *label,
                                 struct tcm_buffer *context);
uint32_t TCM_LoadContext(uint32_t entityHandle,
                         TCM_BOOL keephandle,
                         struct tcm_buffer *context,
                         uint32_t *handle/*      */);

/* Section 22: Eviction */
uint32_t TCM_FlushSpecific(uint32_t handle,
                           uint32_t resourceType,
                           int allowTransport);




/* Section 24: transport commands */

uint32_t TCM_EstablishTransport_UseRoom(uint32_t keyhandle,
                                        unsigned char *usageAuth,
                                        TCM_TRANSPORT_PUBLIC *ttp,
                                        unsigned char *transAuth,
                                        struct tcm_buffer *secret,
                                        TCM_CURRENT_TICKS *currentticks,
                                        session *transSession);
uint32_t TCM_ExecuteTransport(struct tcm_buffer *tb, const char *msg);
uint32_t TCM_ReleaseTransport( session *transSession );

void *TSS_PushTransportFunction(uint32_t (*function)(struct tcm_buffer *tb,
                                const char *msg),
                                uint32_t *idx);
void *TSS_PopTransportFunction(uint32_t *idx);

uint32_t TSS_SetTransportParameters(session *transSession,
                                    uint32_t idx);



/* Section 10: Storage Functions */
uint32_t TCM_Seal(       uint32_t keyhandle,
                         unsigned char *pcrinfo, uint32_t pcrinfosize,
                         unsigned char *keyauth,
                         unsigned char *dataauth,
                         unsigned char *data, uint32_t datalen,
                         unsigned char *blob, uint32_t *bloblen);
uint32_t TCM_Unseal(       uint32_t keyhandle,
                           unsigned char *keyauth,
                           unsigned char *dataauth,
                           unsigned char *blob, uint32_t bloblen,
                           unsigned char *rawdata, uint32_t *datalen);



uint32_t TSS_SM4Encrypt(       uint32_t keyhandle,
                               unsigned char *keyauth,
                               unsigned char *data, uint32_t datalen,
                               unsigned char *blob, uint32_t *bloblen);
uint32_t TSS_SM4Decrypt(       uint32_t keyhandle,
                               unsigned char *keyauth,
                               unsigned char *data, uint32_t datalen,
                               unsigned char *blob, uint32_t *bloblen);






uint32_t TCM_LoadKey(uint32_t keyhandle, unsigned char *keyauth,
                     keydata *keyparms, uint32_t *newhandle );
#if 0
uint32_t TCM_LoadKey2(uint32_t keyhandle, unsigned char *keyauth,
                      keydata *keyparms, uint32_t *newhandle);
#endif
uint32_t TCM_GetPubKey(uint32_t keyhandle,
                       unsigned char *keyauth,
                       pubkeydata *pk
                      );
uint32_t TCM_GetPubKey_UseRoom(uint32_t keyhandle,
                               unsigned char *keyauth,
                               pubkeydata *pk);



/* section 7: capability commands */
uint32_t TCM_GetCapability(uint32_t caparea,
                           struct tcm_buffer *scap,

                           struct tcm_buffer *response);
uint32_t TCM_GetCapability_Internal(uint32_t caparea,
                                    struct tcm_buffer *scap,
                                    struct tcm_buffer *response, //out

                                    int allowTransport);
uint32_t TCM_GetCapability_NoTransport(uint32_t caparea,
                                       struct tcm_buffer *scap,

                                       struct tcm_buffer *response);






/* Section 11: Migration */
uint32_t TCM_AuthorizeMigrationKey(unsigned char *userpass,
                                   int migtype,
                                   struct tcm_buffer *keyblob,
                                   struct tcm_buffer *migblob);

uint32_t TCM_CreateMigrationBlob(unsigned int keyhandle,
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
                                );

uint32_t TCM_ConvertMigrationBlob(unsigned int parentkeyhandle,
                                  unsigned int migkeyhandle,
                                  unsigned char *parentkeyauth,
                                  unsigned char *migkeyauth,
                                  unsigned char *rndblob,
                                  uint32_t rndblen,
                                  unsigned char *keyblob,
                                  uint32_t keyblen,
                                  unsigned char *encblob,
                                  uint32_t *encblen
                                 );







/* Section 20: NV storage related functions */
uint32_t TCM_NV_DefineSpace(unsigned char *ownauth,  // HMAC key
                            unsigned char *pubInfo, uint32_t pubInfoSize,
                            unsigned char *keyauth   // used to create  encAuth
                           );
uint32_t TCM_NV_DefineSpace2(unsigned char *ownauth,  // HMAC key
                             uint32_t index,
                             uint32_t size,
                             uint32_t permissions,
                             unsigned char *areaauth,
                             TCM_PCR_INFO_SHORT *pcrInfoRead,
                             TCM_PCR_INFO_SHORT *pcrInfoWrite);

uint32_t TCM_NV_WriteValueAuth( uint32_t nvIndex,
                                uint32_t offset,
                                unsigned char *data, uint32_t datalen,
                                unsigned char *areaauth) ;

uint32_t TCM_NV_ReadValueAuth(
    uint32_t nvIndex,
    uint32_t offset,
    uint32_t datasize,
    unsigned char *buffer, uint32_t *buffersize,
    unsigned char *areaauth) ;


/* Section 25: Counter related functions */





/* Section 13: crypto functions */



uint32_t TCM_Sign(uint32_t keyhandle, unsigned char *keyauth,
                  unsigned char *data, uint32_t datalen,
                  unsigned char *sig, uint32_t *siglen      );
uint32_t TCM_GetRandom(  uint32_t bytesreq,
                         unsigned char *buffer, uint32_t *bytesret);


/* virtual TCM Management functions */

/* TCM helper functions */


char *TCM_GetErrMsg(uint32_t code);



uint32_t TCM_CreateEncAuth(const struct session *sess,
                       const unsigned char *in, unsigned char *out);






uint32_t TCM_WritePCRComposite(struct tcm_buffer *tb, TCM_PCR_COMPOSITE *comp);




uint32_t TCM_WritePCRInfo(struct tcm_buffer *buffer, TCM_PCR_INFO *info);




uint32_t TCM_HashPCRComposite(TCM_PCR_COMPOSITE *comp, unsigned char *digest      );


uint32_t TCM_ReadKeyfile(const char *filename, keydata *k);



uint32_t TCM_ReadFile(const char *filename, unsigned char **buffer, uint32_t *buffersize);
uint32_t TCM_WriteFile(const char *filename, unsigned char *buffer, uint32_t buffersize);

//uint32_t TCM_WriteQuoteInfo(struct tcm_buffer *buffer, TCM_QUOTE_INFO * info);
//uint32_t TCM_WriteQuoteInfo2(struct tcm_buffer *buffer, TCM_QUOTE_INFO2 * info2);

//uint32_t TCM_WriteCMKAuth(struct tcm_buffer *buffer, TCM_CMK_AUTH * auth) ;
//uint32_t TCM_HashCMKAuth(TCM_CMK_AUTH * auth, unsigned char * hash);

uint32_t TCM_WritePubInfo(TCM_NV_DATA_PUBLIC *pub, struct tcm_buffer *buffer);






uint32_t  TSS_KeyExtract(const struct tcm_buffer *tb, uint32_t offset, keydata *k);
uint32_t  TSS_PubKeyExtract(const struct tcm_buffer *tb, uint32_t offset, pubkeydata *k);
//RSA      *TSS_convpubkey(pubkeydata *k);
uint32_t  TCM_WriteKey(struct tcm_buffer *tb, keydata *k);
uint32_t  TCM_ReadKey(const struct tcm_buffer *tb, uint32_t offset, keydata *k);
uint32_t TCM_WritePubKeyData(struct tcm_buffer *buffer, keydata *k);



uint32_t  TCM_WriteKeyInfo(struct tcm_buffer *tp, keydata *k);



int       TSS_KeySize(const struct tcm_buffer *tb, unsigned int offset);
int       TSS_PubKeySize(const struct tcm_buffer *, unsigned int offset, int pcrpresent);

uint32_t TCM_ReadNVDataPublic(const struct tcm_buffer *buffer, uint32_t offset, TCM_NV_DATA_PUBLIC *ndp);

//struct tcm_buffer *TSS_AllocTCMBuffer(int len);
void TSS_FreeTCMBuffer(struct tcm_buffer *buf);
uint32_t TSS_SetTCMBuffer(struct tcm_buffer *tb,
                          const unsigned char *buffer,
                          uint32_t len);
#if 0
uint32_t TCM_WriteTCMFamilyLabel(struct tcm_buffer *buffer,
                                 TCM_FAMILY_LABEL l);
uint32_t TCM_ReadTCMFamilyLabel(const unsigned char *buffer,
                                TCM_FAMILY_LABEL *l);
uint32_t TCM_WriteTCMDelegations(struct tcm_buffer *buffer,
                                 TCM_DELEGATIONS *td);
uint32_t TCM_WriteTCMDelegatePublic(struct tcm_buffer *buffer,
                                    TCM_DELEGATE_PUBLIC *tdp);
uint32_t TCM_WriteTCMDelegateOwnerBlob(struct tcm_buffer *buffer,
                                       TCM_DELEGATE_OWNER_BLOB *tdob);
uint32_t TCM_WriteTCMDelegateKeyBlob(struct tcm_buffer *buffer,
                                     TCM_DELEGATE_KEY_BLOB *tdob);
uint32_t TCM_WriteDelegateOwnerBlob(struct tcm_buffer *buffer, TCM_DELEGATE_OWNER_BLOB *blob);

uint32_t TCM_ReadFamilyTableEntry(struct tcm_buffer *buffer,
                                  uint32_t offset,
                                  TCM_FAMILY_TABLE_ENTRY *fte);
uint32_t TCM_ReadDelegatePublic(struct tcm_buffer *buffer,
                                uint32_t offset,
                                TCM_DELEGATE_PUBLIC *dp);
uint32_t TCM_ReadTCMDelegations(const struct tcm_buffer *buffer, uint32_t offset,
                                TCM_DELEGATIONS *td);
#endif
uint32_t TCM_WriteTransportPublic(struct tcm_buffer *tb,
                                  TCM_TRANSPORT_PUBLIC *ttp);
uint32_t TCM_WriteTransportAuth(struct tcm_buffer *tb,
                                TCM_TRANSPORT_AUTH *tta);
uint32_t TCM_WriteAuditEventIn(struct tcm_buffer *buffer,
                               TCM_AUDIT_EVENT_IN *aei);
uint32_t TCM_WriteAuditEventOut(struct tcm_buffer *buffer,
                                TCM_AUDIT_EVENT_OUT *aeo);
uint32_t TCM_WriteTransportLogIn(struct tcm_buffer *buffer,
                                 TCM_TRANSPORT_LOG_IN *ttli);
uint32_t TCM_WriteTransportLogOut(struct tcm_buffer *buffer,
                                  TCM_TRANSPORT_LOG_OUT *ttlo);
uint32_t TCM_ReadCurrentTicks(struct tcm_buffer *buffer,
                              uint32_t offset,
                              TCM_CURRENT_TICKS *tct);
void print_array(const char *name, const unsigned char *data, unsigned int len);
void  TCM_dump_data(const char *name, const void *s, size_t len);

uint32_t TCM_Open(void);
uint32_t TCM_Close(void);
#endif
