#ifndef TCMKEYS_H
#define TCMKEYS_H
#include "tcm.h"
#include "tcm_structures.h"

#ifndef TCM_MAXIMUM_KEY_SIZE
#define TCM_MAXIMUM_KEY_SIZE  4096
#endif


#define TCM_SIZED_BUFFER_EMB(SIZE_OF_BUFFER,uniq,name) \
struct uniq { \
    uint32_t size; \
    BYTE buffer[SIZE_OF_BUFFER]; \
} name






typedef struct tdTCM_STORE_PUBKEY_EMB {
    uint32_t keyLength;
    BYTE   modulus[TCM_MAXIMUM_KEY_SIZE / 8];
} TCM_STORE_PUBKEY_EMB;




typedef struct tdTCM_KEY_EMB {
    TCM_STRUCTURE_TAG tag;
    uint16_t fill;
    TCM_KEY_USAGE keyUsage;
    TCM_KEY_FLAGS keyFlags;
    TCM_AUTH_DATA_USAGE authDataUsage;
    TCM_KEY_PARMS algorithmParms;
    TCM_SIZED_BUFFER_EMB(256,
                         pcrInfo_TCM_KEY_EMB, pcrInfo);
    TCM_STORE_PUBKEY_EMB pubKey;
    TCM_SIZED_BUFFER_EMB(1024, encData_TCM_KEY_EMB, encData);
} TCM_KEY_EMB;


typedef struct pubkeydata {
    TCM_KEY_PARMS algorithmParms;
    TCM_STORE_PUBKEY_EMB pubKey;
    TCM_SIZED_BUFFER_EMB(256,
                         pcrInfo_pubkeydata, pcrInfo);
} pubkeydata;


//
typedef struct tdTSS_KEY11_HDR {
    TCM_STRUCT_VER ver;
} TSS_KEY11_HDR;

//
typedef struct tdTSS_KEY12_HDR {
    TCM_STRUCTURE_TAG tag;
    uint16_t fill;
} TSS_KEY12_HDR;

typedef struct keydata {
    union {
        TSS_KEY11_HDR key11;
        TSS_KEY12_HDR key12;
    } hdr;
    TCM_KEY_USAGE       keyUsage;      // 2
    TCM_KEY_FLAGS       keyFlags;      // 3
    TCM_AUTH_DATA_USAGE authDataUsage; // 4
    pubkeydata     pub;
    TCM_SIZED_BUFFER_EMB(1024, encData_keydata, encData);
} keydata;


#endif
