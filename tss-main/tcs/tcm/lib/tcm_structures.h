#ifndef TCM_STRUCTURES_H
#define TCM_STRUCTURES_H


#include "tcm_types.h"
#include "tcm_constants.h"


enum
{
	EX_CHANGE_FLAG_REQUESTOR = 0,
	EX_CHANGE_FLAG_RESPONSER = 1
};

#ifdef TCM_MIN_USER_INFOS
#if (TCM_MIN_USER_INFOS < 4)
#error "TCM_MIN_USER_INFOS minimum is 4"
#endif
#else
#define TCM_MIN_USER_INFOS 4
#endif


#ifdef TCM_MIN_AUTH_SESSIONS
#if (TCM_MIN_AUTH_SESSIONS < 3)
#error "TCM_MIN_AUTH_SESSIONS minimum is 3"
#endif
#endif


#ifndef TCM_MIN_AUTH_SESSIONS
#define TCM_MIN_AUTH_SESSIONS 3
#endif

#ifdef TCM_MIN_TRANS_SESSIONS
#if (TCM_MIN_TRANS_SESSIONS < 3)
#error "TCM_MIN_TRANS_SESSIONS minimum is 3"
#endif
#endif

#ifndef TCM_MIN_TRANS_SESSIONS
#define TCM_MIN_TRANS_SESSIONS 3
#endif

#ifdef TCM_KEY_HANDLES
#if (TCM_KEY_HANDLES < 2)
#error "TCM_KEY_HANDLES minimum is 2"
#endif
#endif


/* Set the default to 3 so that there can be one owner evict key */

#ifndef TCM_KEY_HANDLES
#define TCM_KEY_HANDLES 3     /* entries in global TCM_KEY_HANDLE_ENTRY array */
#endif

#ifndef TCM_OWNER_EVICT_KEY_HANDLES
#define TCM_OWNER_EVICT_KEY_HANDLES 1
#endif

#if (TCM_OWNER_EVICT_KEY_HANDLES > (TCM_KEY_HANDLES - 2))
#error "TCM_OWNER_EVICT_KEY_HANDLES too large for TCM_KEY_HANDLES"
#endif

#ifdef TCM_MIN_COUNTERS
#if (TCM_MIN_COUNTERS < 4)
#error "TCM_MIN_COUNTERS minumum is 4"
#endif
#endif

#ifndef TCM_MIN_COUNTERS
#define TCM_MIN_COUNTERS 4 /* the minimum number of counters is 4 */
#endif


#ifdef TCM_MIN_SESSION_LIST
#if (TCM_MIN_SESSION_LIST < 16)
#error "TCM_MIN_SESSION_LIST minimum is 16"
#endif
#endif

#ifndef TCM_MIN_SESSION_LIST
#define TCM_MIN_SESSION_LIST 16
#endif

#ifdef TCM_MIN_USER_LIST
#if (TCM_MIN_USER_LIST < 16)
#error "TCM_MIN_USER_LIST minimum is 16"
#endif
#endif

#ifndef TCM_MIN_USER_LIST
#define TCM_MIN_USER_LIST 16
#endif


#define TCM_NUM_PCR 27          /* Use PC Client specification values */



#define TCM_SECRET_SIZE 32
typedef BYTE TCM_SECRET[TCM_SECRET_SIZE];

#define TCM_NONCE_SIZE 32
typedef BYTE TCM_NONCE[TCM_NONCE_SIZE];


#define TCM_IV_SIZE 16
typedef BYTE TCM_IV[TCM_IV_SIZE];

#define TCM_SEQ_SIZE 4
typedef BYTE TCM_SEQ[TCM_SEQ_SIZE];

#define TCM_AUTHDATA_SIZE 32
typedef BYTE TCM_AUTHDATA[TCM_AUTHDATA_SIZE];

#define TCM_DIGEST_SIZE 32
typedef BYTE TCM_DIGEST[TCM_DIGEST_SIZE];

#define TCM_PRIVILEGE_TABLE_SIZE 12
typedef BYTE TCM_PRIVILEGE_TABLE[TCM_PRIVILEGE_TABLE_SIZE];

#define TCM_ORD_PRIV_SET_SIZE 4
typedef BYTE TCM_ORD_PRI_SET[TCM_ORD_PRIV_SET_SIZE];
#define TCM_ORD_PRIV_UNUSED 0xFF

typedef TCM_DIGEST TCM_CHOSENID_HASH;   /* This SHALL be the digest of the chosen identityLabel and
                                           privacyCA for a new TPM identity.*/
typedef TCM_DIGEST TCM_PCRVALUE;        /* The value inside of the PCR */
typedef TCM_DIGEST TCM_COMPOSITE_HASH;  /* This SHALL be the hash of a list of PCR indexes and PCR
                                           values that a key or data is bound to. */
typedef TCM_DIGEST TCM_HMAC;            /* This shall be the output of the HMAC algorithm */
typedef BYTE TCM_LOCALITY_SELECTION;

typedef struct tdTCM_PCR_SELECTION {
    uint16_t sizeOfSelect;			/* The size in bytes of the pcrSelect structure */
    BYTE pcrSelect[TCM_NUM_PCR / CHAR_BIT + 1];       /* This SHALL be a bit map that indicates if a PCR
                                                   is active or not */
} TCM_PCR_SELECTION;

#define TCM_LOC_FOUR    0x10    /* Locality 4 */
#define TCM_LOC_THREE   0x08    /* Locality 3  */
#define TCM_LOC_TWO     0x04    /* Locality 2  */
#define TCM_LOC_ONE     0x02    /* Locality 1  */
#define TCM_LOC_ZERO    0x01    /* Locality 0. This is the same as the legacy interface.  */

#define TCM_LOC_ALL     0x1f    /* kgold - added all localities */
#define TCM_LOC_MAX     4       /* kgold - maximum value for TCM_MODIFIER_INDICATOR */


/* This structure is typically a cast from a subset of a larger TCM structure.  Two members - a 4
   bytes size followed by a 4 bytes pointer to the data is a common TCM structure idiom. */

typedef struct tdTCM_SIZED_BUFFER {
    uint32_t size;
    BYTE *buffer;
} TCM_SIZED_BUFFER;

/* This structure implements a safe storage buffer, used throughout the code when serializing
   structures to a stream.
*/

typedef struct tdTCM_STORE_BUFFER {
    unsigned char *buffer;              /* beginning of buffer */
    unsigned char *buffer_current;      /* first empty position in buffer */
    unsigned char *buffer_end;          /* one past last valid position in buffer */
} TCM_STORE_BUFFER;


/* 5.1 TCM_STRUCT_VER rev 100

   This indicates the version of the structure or TCM.

   Version 1.2 deprecates the use of this structure in all other structures. The structure is not
   deprecated as many of the structures that contain this structure are not deprecated.
*/

#define TCM_MAJOR       0x01

#if defined TCM_V12
#define TCM_MINOR       0x02
#endif

#if defined TCM_V11
#define TCM_MINOR       0x01
#endif

typedef struct tdTCM_STRUCT_VER {
    BYTE major;         /* This SHALL indicate the major version of the structure. MUST be 0x01 */
    BYTE minor;         /* This SHALL indicate the minor version of the structure. MUST be 0x01 */
    BYTE revMajor;      /* This MUST be 0x00 on output, ignored on input */
    BYTE revMinor;      /* This MUST be 0x00 on output, ignored on input */
} TCM_STRUCT_VER;


/*******************************Key**********************************/

typedef struct tdTCM_SM2_DOT {
    TCM_SIZED_BUFFER x;
    TCM_SIZED_BUFFER y;
} TCM_SM2_DOT;



typedef struct tdTCM_SM2_PUB_PARAMS {
    TCM_SM2_FIELD_TYPE fieldType;
    TCM_SIZED_BUFFER p;
    TCM_SIZED_BUFFER a;
    TCM_SIZED_BUFFER b;
#if 0
    TCM_SM2_DOT G;
#else
    TCM_SIZED_BUFFER G;//use compress or uncompress format
#endif
    TCM_SIZED_BUFFER n;
    TCM_SIZED_BUFFER seed;
    TCM_SIZED_BUFFER h;
} TCM_SM2_PUB_PARAMS;

typedef struct tdTCM_SM4_PUB_PARAMS {
    TCM_SIZED_BUFFER IV;
} TCM_SM4_PUB_PARAMS;





typedef struct tdTCM_PCR_INFO {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;			 /* MUST be TCM_TAG_PCR_INFO */
#endif
    TCM_LOCALITY_SELECTION localityAtCreation;
    TCM_LOCALITY_SELECTION localityAtRelease;
    TCM_PCR_SELECTION PcrAtCreation;
    TCM_PCR_SELECTION PcrAtRelease;
    TCM_COMPOSITE_HASH digestAtCreation;
    TCM_COMPOSITE_HASH digestAtRelease;
} TCM_PCR_INFO;





typedef struct tdTCM_SM2_ASYMKEY_PARAMETERS {
    uint32_t keyLength;
} TCM_SM2_ASYMKEY_PARAMETERS;


typedef struct tdTCM_SYMMETRIC_KEY_PARMS {
    uint32_t keyLength;
    uint32_t blockSize;
    uint32_t ivSize;
    TCM_IV   IV;
} TCM_SYMMETRIC_KEY_PARMS;



typedef struct tdTCM_ALG_PUB_PARAMS {
    TCM_ALGORITHM_ID algorithmID;
    union {
        TCM_SM2_ASYMKEY_PARAMETERS  SM2_PUB_PARAMS;
        TCM_SYMMETRIC_KEY_PARMS  SM4_PUB_PARAMS;
    };
} TCM_ALG_PUB_PARAMS;


typedef struct tdTCM_CIPH_SCHM_ALG {
    TCM_ALGORITHM_ID algID;
    TCM_SIZED_BUFFER algPubParams;
    TCM_ALG_PUB_PARAMS tcm_alg_pub_params;
} TCM_CIPH_SCHM_ALG;


typedef struct tdTCM_CIPHER_SCHEME {
    TCM_CIPH_SCHM_ALG algorithm;
    TCM_ENC_SCHEME mode;
    uint32_t keyLength;
} TCM_CIPHER_SCHEME;





typedef struct tdTCM_KEY_PARMS {
    TCM_ALGORITHM_ID algorithmID; 	/* This SHALL be the key algorithm in use */
    TCM_ENC_SCHEME encScheme; 	/* This SHALL be the encryption scheme that the key uses to encrypt
                                   information */
    TCM_SIG_SCHEME sigScheme; 	/* This SHALL be the signature scheme that the key uses to perform
                                   digital signatures */

    uint32_t      parmSize;
    union {
        TCM_SM2_ASYMKEY_PARAMETERS  sm2para;
        TCM_SYMMETRIC_KEY_PARMS  sm4para;
    };
    // BYTE         *parms;
} TCM_KEY_PARMS;


typedef struct tdTCM_KEY_PUB {
    TCM_STRUCTURE_TAG tag;
    uint16_t  fill;
    TCM_KEY_USAGE keyUsage;
    TCM_KEY_FLAGS keyFlags;
    TCM_AUTH_DATA_USAGE authDataUsage;
    TCM_KEY_PARMS algorithmParms;
    TCM_SIZED_BUFFER pcrInfo;
    TCM_SIZED_BUFFER pubKey;
    TCM_SIZED_BUFFER encData;
    TCM_PCR_INFO *tcm_pcr_info;
} TCM_KEY_PUB;



typedef struct tdTCM_NATIVE_KEY {
    TCM_SIZED_BUFFER keyData;
    //to extend
} TCM_NATIVE_KEY;

typedef void TCM_ALG_PRIV_PARAMS;
typedef void TCM_SM2_PRIV_PARAMS;//cause SM2 has no private parameter
typedef void TCM_SM4_PRIV_PARAMS;//cause SM4 has no private parameter

typedef struct tdTCM_KEY_INFO_PRIV {
    TCM_PAYLOAD_TYPE payloadType;
    TCM_SECRET usageSecret;
    TCM_SECRET migrationSecret;//When migrated, sets it to zero
    TCM_DIGEST pubDataDigest;
    TCM_NATIVE_KEY nativeKey;
    TCM_SIZED_BUFFER algPrivParams;
    TCM_ALG_PRIV_PARAMS *tcm_alg_priv_params; //The default type is void *, to use TCM_SM4_PRIV_PARAMS or TCM_SM2_PRIV_PARAMS structure depends on keyType
} TCM_KEY_PRIV;



typedef TCM_KEY_PRIV TCM_KEY_INFO_MIGRATE;

typedef struct tdTCM_KEY {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* MUST be TCM_TAG_KEY */
#endif
    TCM_KEY_PUB tcm_key_pub;
    TCM_KEY_PRIV *tcm_key_priv;
} TCM_KEY;







typedef struct tdTCM_KEY_SHORT {
    TCM_CIPHER_SCHEME cipherScheme;
    TCM_SIZED_BUFFER pubKey;
} TCM_KEY_PUB_SHORT;

typedef TCM_KEY_PUB_SHORT TCM_KEY_INFO_IN;
typedef TCM_KEY_PUB_SHORT TCM_KEY_INFO_OUT;

/************************************************************/

#ifdef TCM_MIN_AUTH_SESSIONS
#if (TCM_MIN_AUTH_SESSIONS < 3)
#error "TCM_MIN_AUTH_SESSIONS minimum is 3"
#endif
#endif

#ifndef TCM_MIN_AUTH_SESSIONS
#define TCM_MIN_AUTH_SESSIONS 3
#endif

/* NOTE: Vendor specific */

typedef struct tdTCM_AUTH_SESSION_DATA {
    /* vendor specific */
    TCM_AUTHHANDLE handle;      /* Handle for a session */
    TCM_PROTOCOL_ID subProtocolID; /* TCM_PID_OIAP, TCM_PID_OSAP */
    TCM_ENT_TYPE entityTypeByte;        /* The type of entity in use (TCM_ET_SMK, TCM_ET_OWNER,
                                           TCM_ET_KEYHANDLE ... */
    TCM_AP_ENC_SCHEME apEncScheme;  /* AP encryption scheme */
    TCM_SECRET sharedSecret;
    TCM_DIGEST entityDigest;    /* tracks which entity established the  session */
    TCM_NONCE seq;
    TCM_BOOL valid;             /* added kgold: array entry is valid */
} TCM_AUTH_SESSION_DATA;

typedef TCM_AUTHDATA TCM_ENCAUTH; /* A cipher text (encrypted) version of authorization data. The
                                     encryption mechanism depends on the context. */

/*
18. Context structures
*/

/* 18.1 TCM_CONTEXT_BLOB rev 102

*/

#define TCM_CONTEXT_LABEL_SIZE 16

typedef struct tdTCM_CONTEXT_BLOB {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag; 			 /* MUST be TCM_TAG_CONTEXTBLOB */
#endif
    TCM_RESOURCE_TYPE resourceType;	 /* The resource type */
    TCM_HANDLE handle; 				 /* Previous handle of the resource */
    BYTE label[TCM_CONTEXT_LABEL_SIZE]; /* Label for identification of the blob. Free format
											area. */
    uint32_t contextCount; 	 /* MUST be TCM_STANY_DATA -> contextCount when creating the
											structure.	This value is ignored for context blobs that
											reference a key. */
    TCM_DIGEST integrityDigest;		 /* The integrity of the entire blob including the sensitive
											area. This is a HMAC calculation with the entire
											structure (including sensitiveData) being the hash and
											tcmProof is the secret */
#if 0
    uint32_t additionalSize;
    [size_is(additionalSize)] BYTE *additionalData;
    uint32_t sensitiveSize;
    [size_is(sensitiveSize)] BYTE *sensitiveData;
#endif
    TCM_SIZED_BUFFER additionalData;	 /* Additional information set by the TCM that helps define
											and reload the context. The information held in this area
											MUST NOT expose any information held in shielded
											locations. This should include any IV for symmetric
											encryption */
    TCM_SIZED_BUFFER sensitiveData;	 /* The normal information for the resource that can be
											exported */
} TCM_CONTEXT_BLOB;

/* 18.2 TCM_CONTEXT_SENSITIVE rev 87

The internal areas that the TCM needs to encrypt and store off the TCM.

This is an informative structure and the TCM can implement in any manner they wish.
*/

typedef struct tdTCM_CONTEXT_SENSITIVE {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag; 			 /* MUST be TCM_TAG_CONTEXT_SENSITIVE */
#endif
    TCM_NONCE contextNonce;			 /* On context blobs other than keys this MUST be
											TCM_STANY_DATA - > contextNonceSession For keys the value
											is TCM_STCLEAR_DATA -> contextNonceKey */
#if 0
    uint32_t internalSize;
    [size_is(internalSize)] BYTE *internalData;
#endif
    TCM_SIZED_BUFFER internalData; 	 /* The internal data area */
} TCM_CONTEXT_SENSITIVE;


typedef struct tdTCM_UINT64 {
    uint32_t sec;
    uint32_t usec;
} TCM_UINT64;

typedef struct tdTCM_CURRENT_TICKS {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_CURRENT_TICKS */
#endif
    TCM_UINT64 currentTicks;    /* The number of ticks since the start of this tick session */
    /* upper is seconds, lower is useconds */
    uint16_t tickRate;		/* The number of microseconds per tick. The maximum resolution of
                                   the TCM tick counter is thus 1 microsecond. The minimum
                                   resolution SHOULD be 1 millisecond. */
    TCM_NONCE tickNonce;        /* TCM_NONCE tickNonce The nonce created by the TCM when resetting
                                   the currentTicks to 0.  This indicates the beginning of a time
                                   session.  This value MUST be valid before the first use of
                                   TCM_CURRENT_TICKS. The value can be set at TCM_Startup or just
                                   prior to first use. */
    /* NOTE Added */
    TCM_UINT64 initialTime;     /* Time from TCM_GetTimeOfDay() */
} TCM_CURRENT_TICKS;


/*TCM_MIGRATIONKEYAUTH

   This structure provides the proof that the associated public key has TCM Owner authorization to
   be a migration key.
*/

typedef struct tdTCM_MIGRATIONKEYAUTH {
    TCM_KEY_PUB_SHORT migrationKey;
    //	TCM_UINT64 expirationTime;
    TCM_MIGRATE_SCHEME migrationScheme;
    TCM_DIGEST digest;
} TCM_MIGRATIONKEYAUTH;
typedef struct tdTCM_TRANSPORT_PUBLIC {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG	tag;					/* TCM_TAG_TRANSPORT_PUBLIC */
#endif
    TCM_TRANSPORT_ATTRIBUTES transAttributes;   /* The attributes of this session */
    TCM_ALGORITHM_ID algId;                     /* This SHALL be the algorithm identifier of the
                                                   symmetric key. */
    TCM_ENC_SCHEME encMode;                   /* This SHALL fully identify the manner in which the
                                                   key will be used for encryption operations. */
} TCM_TRANSPORT_PUBLIC;


typedef struct tdTCM_TRANSPORT_INTERNAL {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;				/* TCM_TAG_TRANSPORT_INTERNAL */
#endif
    TCM_AUTHDATA authData;              /* The shared secret for this session */
    TCM_TRANSPORT_PUBLIC transPublic;   /* The public information of this session */
    TCM_TRANSHANDLE transHandle;        /* The handle for this session */
    //    TCM_NONCE transNonceEven;           /* The even nonce for the rolling protocol , replaced by transSeq*/
    TCM_SEQ	transSeq;
    TCM_DIGEST transDigest;             /* The log of transport events */
    /* added kgold */
    TCM_BOOL valid;                     /* entry is valid */

} TCM_TRANSPORT_INTERNAL;


typedef struct tdTCM_TRANSPORT_LOG_IN {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG	tag;	/* TCM_TAG_TRANSPORT_LOG_IN */
#endif
    TCM_DIGEST parameters;      /* The actual parameters contained in the digest are subject to the
                                   rules of the command using this structure. To find the exact
                                   calculation refer to the actions in the command using this
                                   structure. */
    TCM_DIGEST pubKeyHash;      /* The hash of any keys in the transport command */
} TCM_TRANSPORT_LOG_IN;


typedef struct tdTCM_TRANSPORT_LOG_OUT {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;				/* TCM_TAG_TRANSPORT_LOG_OUT */
#endif
    //    TCM_CURRENT_TICKS currentTicks;     /* The current tick count. This SHALL be the value of the
    //                                           current TCM tick counter.  */
    TCM_UINT64 currentTicks;
    TCM_DIGEST parameters;              /* The actual parameters contained in the digest are subject
                                           to the rules of the command using this structure. To find
                                           the exact calculation refer to the actions in the command
                                           using this structure. */
    TCM_MODIFIER_INDICATOR locality;    /* The locality that called TCM_ExecuteTransport */
} TCM_TRANSPORT_LOG_OUT;

typedef struct tdTCM_TRANSPORT_AUTH {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG	tag;	/* TCM_TAG_TRANSPORT_AUTH */
#endif
    TCM_AUTHDATA authData;      /* The AuthData value */
} TCM_TRANSPORT_AUTH;

typedef struct tdTCM_KEY_HANDLE_ENTRY {
    TCM_KEY_HANDLE handle;      /* Handles for a key currently loaded in the TCM */
    TCM_KEY *key;               /* Pointer to the key object */
    TCM_BOOL parentPCRStatus;   /* TRUE if parent of this key uses PCR's */
    TCM_KEY_CONTROL keyControl; /* Attributes that can control various aspects of key usage and
                                   manipulation. */
} TCM_KEY_HANDLE_ENTRY;


typedef struct tdTCM_PCR_ATTRIBUTES {
    TCM_BOOL pcrReset;          /* A value of TRUE SHALL indicate that the PCR register can be reset
                                   using the TCM_PCR_RESET command. */
    TCM_LOCALITY_SELECTION pcrExtendLocal;      /* An indication of which localities can perform
                                                   extends on the PCR. */
    TCM_LOCALITY_SELECTION pcrResetLocal;       /* An indication of which localities can reset the
                                                   PCR */
} TCM_PCR_ATTRIBUTES;

#define TCM_COUNTER_LABEL_SIZE  4
#define TCM_COUNT_ID_NULL 0xffffffff    /* unused value TCM_CAP_PROP_ACTIVE_COUNTER expects this
                                           value if no counter is active */
#define TCM_COUNT_ID_ILLEGAL 0xfffffffe /* after releasing an active counter */

typedef struct tdTCM_COUNTER_VALUE {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* TCM_TAG_COUNTER_VALUE */
#endif
    BYTE label[TCM_COUNTER_LABEL_SIZE]; /* The label for the counter */
    TCM_ACTUAL_COUNT counter;           /* The 32-bit counter value. */
    /* NOTE: Added.  TCMWG email says the specification structure is the public part, but these are
       vendor specific private members. */
    TCM_SECRET authData;                /* Authorization secret for counter */
    TCM_BOOL valid;
    TCM_DIGEST digest;                  /* for OSAP comparison */
} TCM_COUNTER_VALUE;





typedef struct tdTCM_PERMANENT_FLAGS {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_PERMANENT_FLAGS */
#endif
    TCM_BOOL disable;           /* single or multiple user mode. The default mode is TRUE
                                   */
    TCM_BOOL ownership;         /* The ability to install an owner. The default state is TRUE. */
    TCM_BOOL deactivated;       /* The state of the inactive flag. The default state is TRUE. */
    TCM_BOOL readPubek;         /* The ability to read the PUBEK without owner authorization. The
                                   default state is TRUE.

                                   set TRUE on owner clear
                                   set FALSE on take owner, disablePubekRead//JSJ
                                */
    TCM_BOOL disableOwnerClear; /* Whether the owner authorized clear commands are active. The
                                   default state is TRUE. */

    TCM_BOOL physicalPresenceLifetimeLock; //physicalPresenceLifetimeLock
    TCM_BOOL physicalPresenceHWEnable;  /* FALSE: Disable the hardware signal indicating physical
                                           presence. (DEFAULT)

                                           TRUE: Enables the hardware signal indicating physical
                                           presence. */
    TCM_BOOL physicalPresenceCMDEnable;         /* FALSE: Disable the command indicating physical
                                           presence. (DEFAULT)

                                           TRUE: Enables the command indicating physical
                                           presence. */
    TCM_BOOL CEKPUsed;
    TCM_BOOL TCMpost;
    TCM_BOOL TCMpostLock;
    TCM_BOOL operator;

    TCM_BOOL enableRevokeEK;    /* TRUE: The TCM_RevokeTrust command is active
                                   FALSE: the TCM RevokeTrust command is disabled */
    TCM_BOOL nvLocked;          /* TRUE: All NV area authorization checks are active
                                   FALSE: No NV area checks are performed, except for maxNVWrites.
                                   FALSE is the default value */

    TCM_BOOL tcmEstablished;    /* TRUE: TCM_HASH_START has been executed at some time
                                   FALSE: TCM_HASH_START has not been executed at any time
                                   Default is FALSE - resets using TCM_ResetEstablishmentBit */

} TCM_PERMANENT_FLAGS;

typedef struct tdTCM_STCLEAR_FLAGS {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* TCM_TAG_STCLEAR_FLAGS */
#endif

    TCM_BOOL deactivated;       /* The state of the inactive flag. The default state is TRUE. */
    TCM_BOOL disableForceClear;         /* Prevents the operation of TCM_ForceClear when TRUE. The
                                           default state is TRUE.  TCM_DisableForceClear sets it to
                                           FALSE. */
    TCM_BOOL physicalPresence;          /* Command assertion of physical presence. The default state
                                           is FALSE.  This flag is affected by the
                                           TSC_PhysicalPresence command but not by the hardware
                                           signal.  */
    TCM_BOOL physicalPresenceLock;      /* Indicates whether changes to the TCM_STCLEAR_FLAGS ->
                                           physicalPresence flag are permitted.
                                           TCM_Startup(ST_CLEAR) sets PhysicalPresenceLock to its
                                           default state of FALSE (allow changes to the
                                           physicalPresence flag). When TRUE, the physicalPresence
                                           flag is FALSE. TSC_PhysicalPresence can change the state
                                           of physicalPresenceLock.  */
    TCM_BOOL bGlobalLock;               /* Set to FALSE on each TCM_Startup(ST_CLEAR). Set to TRUE
                                           when a write to NV_Index =0 is successful */

} TCM_STCLEAR_FLAGS;

typedef struct tdTCM_STANY_FLAGS {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_STANY_FLAGS   */
#endif
    TCM_BOOL postInitialise;    /* Prevents the operation of most capabilities. There is no default
                                   state. It is initialized by TCM_Init to TRUE. TCM_Startup sets it
                                   to FALSE.  */
    TCM_MODIFIER_INDICATOR localityModifier; /*This SHALL indicate for each command the presence of
                                               a locality modifier for the command. It MUST be set
                                               to NULL after the TCM executes each command.  */
    TCM_MODIFIER_INDICATOR privilegeModifier;/*This SHALL indicate for each command the presence of
                                               a privilege modifier for the command. It MUST be set
                                               to NULL after the TCM executes each command.  */
#if 0
    TCM_BOOL transportExclusive; /* Defaults to FALSE. TRUE when there is an exclusive transport
                                    session active. Execution of ANY command other than
                                    TCM_ExecuteTransport or TCM_ReleaseTransportSigned MUST
                                    invalidate the exclusive transport session. */
#endif
    TCM_TRANSHANDLE transportExclusive; /* Defaults to 0x00000000, Set to the handle when an
                                           exclusive transport session is active */
    TCM_BOOL TOSPresent;        /* Defaults to FALSE
                                   Set to TRUE on TCM_HASH_START
                                   set to FALSE using setCapability */
    /* NOTE: Added kgold */
    TCM_BOOL stateSaved;        /* Defaults to FALSE
                                   Set to TRUE on TCM_SaveState
                                   Set to FALSE on any other ordinal

                                   This is an optimization flag, so the file need not be deleted if
                                   it does not exist.
                                */
} TCM_STANY_FLAGS;


#define TCM_MAX_NV_WRITE_NOOWNER 64

#define TCM_ORDINALS_MAX        256     /* assumes a multiple of CHAR_BIT */


typedef struct tdTCM_PERMANENT_DATA {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_PERMANENT_DATA */
#endif
    BYTE revMajor;              /* This is the TCM major revision indicator. This SHALL be set by
                                   the TCME, only. The default value is manufacturer-specific. */
    BYTE revMinor;              /* This is the TCM minor revision indicator. This SHALL be set by
                                   the TCME, only. The default value is manufacturer-specific. */
    TCM_SECRET tcmProof;        /* This is a random number that each TCM maintains to validate blobs
                                   in the SEAL and other processes. The default value is
                                   manufacturer-specific. */
    TCM_NONCE EKReset;          /* Nonce held by TCM to validate TCM_RevokeTrust. This value is set
                                   as the next 32 bytes from the TCM RNG when the EK is set
                                   (was fipsReset - kgold) */
    TCM_SECRET ownerAuth;
    TCM_SECRET operatorAuth;
    //   TCM_KEY endorsementKey;     /* This is the TCM's endorsement key pair. */
    //    TCM_KEY smk;                /* This is the TCM's StorageMasterKey. */
    TCM_SYMMETRIC_KEY_TOKEN contextKey;  /* This is the key in use to perform context saves.  The key size is
					    predicated by the algorithm in use. */
    TCM_COUNTER_VALUE auditMonotonicCounter;    /* This SHALL be the audit monotonic counter for the
                                                   TCM. This value starts at 0 and increments
                                                   according to the rules of auditing,add */
    TCM_COUNTER_VALUE monotonicCounter[TCM_MIN_COUNTERS];       /* This SHALL be the monotonic
                                                                   counters for the TCM. The
                                                                   individual counters start and
                                                                   increment according to the rules
                                                                   of monotonic counters. */
    TCM_PCR_ATTRIBUTES pcrAttrib[TCM_NUM_PCR];  /* The attributes for all of the PCR registers
                                                   supported by the TCM. */
    BYTE ordinalAuditStatus[TCM_ORDINALS_MAX / CHAR_BIT]; /* Table indicating which ordinals are being
                                                           audited. add*/
    BYTE *rngState;
    uint32_t maxNVBufSize;

    uint32_t noOwnerNVWrite;	/* The count of NV writes that have occurred when there is no TCM
                                   Owner.

                                   This value starts at 0 in manufacturing and after each
                                   TCM_OwnerClear. If the value exceeds 64 the TCM returns
                                   TCM_MAXNVWRITES to any command attempting to manipulate the NV
                                   storage. */
    TCM_BOOL ownerInstalled;            /* TRUE: The TCM has an owner installed.
                                           FALSE: The TCM has no owner installed. (default) */
} TCM_PERMANENT_DATA;

typedef struct tdTCM_STCLEAR_DATA {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_STCLEAR_DATA */
#endif
    TCM_NONCE contextNonceKey;  /* This is the nonce in use to properly identify saved key context
                                   blobs This SHALL be set to all zeros on each TCM_Startup
                                   (ST_Clear).
                                */
    TCM_COUNT_ID countID;       /* This is the handle for the current monotonic counter.  This SHALL
                                   be set to zero on each TCM_Startup(ST_Clear). */
    uint32_t ownerReference;	/* Points to where to obtain the owner secret in OIAP and OSAP
                                   commands. This allows a TSS to manage 1.1 applications on a 1.2
                                   TCM where delegation is in operation. */
    TCM_BOOL disableResetLock;  /* Disables TCM_ResetLockValue upon authorization failure.
                                   The value remains TRUE for the timeout period.

                                   Default is FALSE.

                                   The value is in the STCLEAR_DATA structure as the
                                   implementation of this flag is TCM vendor specific. */

    TCM_PCRVALUE PCRS[TCM_NUM_PCR];     /* Platform configuration registers */
    /* NOTE: Added for dictionary attack mitigation */
    uint32_t authFailCount;	/* number of authorization failures without a TCM_ResetLockValue */
    uint32_t authFailTime;	/* time of threshold failure in seconds */
    /* NOTE: Moved from TCM_STANY_DATA.  Saving this state is optional.  This implementation
      does. */
    TCM_AUTH_SESSION_DATA authSessions[TCM_MIN_AUTH_SESSIONS];  /* List of current
																  sessions. Sessions can be OSAP,
																  OIAP, DSAP and Transport */
    /* NOTE: Added for transport */
    TCM_TRANSPORT_INTERNAL transSessions[TCM_MIN_TRANS_SESSIONS];
    /* 22.7 TCM_STANY_DATA Additions (for DAA) - moved to TCM_STCLEAR_DATA for startup state */

    TCM_NONCE contextNonceSession;      /* This is the nonce in use to properly identify saved
										  session context blobs.  This MUST be set to all zeros on
										  each TCM_Startup (ST_Clear).  The nonce MAY be set to
										  null on TCM_Startup( any). */
    uint32_t contextCount;		/* This is the counter to avoid session context blob replay
										  attacks.  This MUST be set to 0 on each TCM_Startup
										  (ST_Clear).  The value MAY be set to 0 on TCM_Startup
										  (any). */
    uint32_t contextList[TCM_MIN_SESSION_LIST];	/* This is the list of outstanding session blobs.
												  All elements of this array MUST be set to 0 on
												  each TCM_Startup (ST_Clear).  The values MAY be
												  set to 0 on TCM_Startup (any). */
    /* NOTE Added auditDigest effect, saved with ST_STATE */
    TCM_DIGEST auditDigest;             /* This is the extended value that is the audit log. This
										  SHALL be set to all zeros at the start of each audit
										  session. */

    /* NOTE Storage for the ordinal response */
    TCM_STORE_BUFFER ordinalResponse;           /* outgoing response buffer for this ordinal */
} TCM_STCLEAR_DATA;

typedef struct tdTCM_STANY_DATA {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* TCM_TAG_STANY_DATA */
#endif
    TCM_CURRENT_TICKS currentTicks;     /* This is the current tick counter.  This is reset to 0
                                           according to the rules when the TCM can tick. See the
                                           section on the tick counter for details. */
} TCM_STANY_DATA;


typedef struct tdTCM_NV_ATTRIBUTES {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_NV_ATTRIBUTES */
#endif
    uint32_t attributes;	/* The attribute area */
} TCM_NV_ATTRIBUTES;


typedef struct tdTCM_PCR_COMPOSITE {
    TCM_PCR_SELECTION select;   /* This SHALL be the indication of which PCR values are active */
#if 0
    uint32_t valueSize;           /* This SHALL be the size of the pcrValue field (not the number of
				     PCR's) */
    TCM_PCRVALUE *pcrValue;     /* This SHALL be an array of TCM_PCRVALUE structures. The values
                                   come in the order specified by the select parameter and are
                                   concatenated into a single blob */
#endif
    TCM_SIZED_BUFFER pcrValue;
} TCM_PCR_COMPOSITE;

typedef struct tdTCM_PCR_INFO_SHORT {
    TCM_PCR_SELECTION pcrSelection;     /* This SHALL be the selection of PCRs that specifies the
                                           digestAtRelease */
    TCM_LOCALITY_SELECTION localityAtRelease;   /* This SHALL be the locality modifier required to
                                                   release the information.  This value must not be
                                                   zero (0). */
    TCM_COMPOSITE_HASH digestAtRelease;         /* This SHALL be the digest of the PCR indices and
                                                   PCR values to verify when revealing auth data */
} TCM_PCR_INFO_SHORT;




/*
5.14 TCM_SIGN_INFO Structure
*/
typedef struct tdTCM_KEYSIG_BLOB {
    TCM_KEY_USAGE keyUsage;
    TCM_KEY_FLAGS keyFlags;
    TCM_AUTH_DATA_USAGE authDataUsage;
    TCM_KEY_INFO_OUT outKeyInfo;
    TCM_BOOL parentPCRStatus;

    TCM_SIZED_BUFFER pcrInfo;
    TCM_PCR_INFO *tcmPCRInfo;
} TCM_KEYSIG_BLOB;


typedef struct tdTCM_PCRSIG_BLOB {
    TCM_LOCALITY_SELECTION currentLocality;
    TCM_PCR_COMPOSITE pcrsComposite;
} TCM_PCRSIG_BLOB;


typedef struct tdTCM_AUDITSIG_BLOB {
    TCM_DIGEST digest;
    TCM_AUDIT_ORDINAL_SET auditOridinalSet;
} TCM_AUDITSIG_BLOB;


typedef struct tdTCM_TICKSTAMPSIG_BLOB {
    TCM_DIGEST digestToStamp;
    TCM_CURRENT_TICKS currentTicks;
} TCM_TICKSTAMPSIG_BLOB;



#define TCM_SIGN_INFO_FIXED_SIZE 4

typedef struct tdTCM_SIGN_INFO {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_SIGNINFO */
#endif
    BYTE fixed[TCM_SIGN_INFO_FIXED_SIZE];       /* The ASCII text that identifies what function was
                                                   performing the signing operation*/
    TCM_NONCE replay;           /* Nonce provided by caller to prevent replay attacks */
    TCM_SIZED_BUFFER data;      /* The data that is being signed */
} TCM_SIGN_INFO;






/*
  9. Storage Structures
*/

/* 9.1 TCM_SEALED_PAYLOAD_PUB

   The definition of this structure is necessary to ensure the enforcement of security properties.

   This structure is in use by the TCM_Seal and TCM_Unseal commands to identify the PCR index and
   values that must be present to properly unseal the data.

   1. This structure is created during the TCM_Seal process. The confidential data is encrypted
   using a nonmigratable key. When the TCM_Unseal decrypts this structure the TCM_Unseal uses the
   public information in the structure to validate the current configuration and release the
   decrypted data

   2. When sealInfoSize is not 0 sealInfo MUST be TCM_PCR_INFO
*/

typedef struct tdTCM_SEALED_PAYLOAD_PUB {
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_SEALED_PAYLOAD_PUB */
    TCM_ENTITY_TYPE et;
    TCM_SIZED_BUFFER pcrInfo;   /* This SHALL be the serialization of  TCM_PCR_INFO structure*/
    TCM_SIZED_BUFFER encData;  /* This SHALL be the encryption of TCM_SEALED_PAYLOAD_PRIV */
    TCM_PCR_INFO *tcmPCRInfo;
} TCM_SEALED_PAYLOAD_PUB;



/* 9.3 TCM_SEALED_PAYLOAD_PRIV

   This structure contains confidential information related to sealed data, including the data
   itself.

   1. To tie the TCM_SEALED_PAYLOAD_PUB structure to the TCM_SEALED_PAYLOAD_PRIV structure this structure contains
   a digest of the containing TCM_SEALED_PAYLOAD_PUB structure.

   2. The digest calculation does not include the encDataSize and encData parameters.
*/

typedef struct tdTCM_SEALED_PAYLOAD_PRIV {
    TCM_PAYLOAD_TYPE payload;   /* This SHALL indicate the payload type of TCM_PT_SEAL */
    TCM_SECRET dataSecret;        /* This SHALL be the authorization data for this value */
    TCM_SECRET tcmProof;        /* This SHALL be a copy of TCM_PERMANENT_DATA -> tcmProof */
    TCM_DIGEST storedDigest;    /* This SHALL be a digest of the TCM_SEALED_PAYLOAD_PUB structure,
                                   excluding the fields TCM_SEALED_PAYLOAD_PUB -> encDataSize and
                                   TCM_SEALED_PAYLOAD_PUB -> encData.  */
    TCM_SIZED_BUFFER rawData;      /* This SHALL be the data to be sealed */
} TCM_SEALED_PAYLOAD_PRIV;








/*
9.5 TCM_BOUND_DATA
*/
typedef struct tdTCM_BOUND_DATA {
    TCM_PAYLOAD_TYPE payload;           /* This SHALL be the value TCM_PT_BIND  */
    uint32_t payloadDataSize;		/* NOTE: added, not part of serialization */
    BYTE *payloadData;                  /* The bound data */
} TCM_BOUND_DATA;






/*
  14. Audit Structures
*/

/* 14.1 TCM_AUDIT_EVENT_IN rev 87

   This structure provides the auditing of the command upon receipt of the command. It provides the
   information regarding the input parameters.
*/

typedef struct tdTCM_AUDIT_EVENT_IN {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG   tag;            /* TCM_TAG_AUDIT_EVENT_IN */
#endif
    TCM_DIGEST inputParms;              /* Digest value according to the HMAC digest rules of the
                                           "above the line" parameters (i.e. the first HMAC digest
                                           calculation). When there are no HMAC rules, the input
                                           digest includes all parameters including and after the
                                           ordinal. */
    TCM_COUNTER_VALUE auditCount;       /* The current value of the audit monotonic counter */
} TCM_AUDIT_EVENT_IN;

/* 14.2 TCM_AUDIT_EVENT_OUT rev 87

  This structure reports the results of the command execution. It includes the return code and the
  output parameters.
*/

typedef struct tdTCM_AUDIT_EVENT_OUT {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* TCM_TAG_AUDIT_EVENT_OUT */
#endif
    TCM_DIGEST outputParms;             /* Digest value according to the HMAC digest rules of the
                                           "above the line" parameters (i.e. the first HMAC digest
                                           calculation). When there are no HMAC rules, the output
                                           digest includes the return code, the ordinal, and all
                                           parameters after the return code. */
    TCM_COUNTER_VALUE auditCount;       /* The current value of the audit monotonic counter */
} TCM_AUDIT_EVENT_OUT;





/* 19.3 TCM_NV_DATA_PUBLIC rev 110

   This structure represents the public description and controls on the NV area.

   bReadSTClear and bWriteSTClear are volatile, in that they are set FALSE at TCM_Startup(ST_Clear).
   bWriteDefine is persistent, in that it remains TRUE through startup.

   A pcrSelect of 0 indicates that the digestAsRelease is not checked.  In this case, the TCM is not
   required to consume NVRAM space to store the digest, although it may do so.  When
   TCM_GetCapability (TCM_CAP_NV_INDEX) returns the structure, a TCM that does not store the digest
   can return zero.  A TCM that does store the digest may return either the digest or zero.
*/

typedef struct tdTCM_NV_DATA_PUBLIC {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* This SHALL be TCM_TAG_NV_DATA_PUBLIC */
#endif
    TCM_NV_INDEX nvIndex;               /* The index of the data area */
    TCM_PCR_INFO_SHORT pcrInfoRead;     /* The PCR selection that allows reading of the area */
    TCM_PCR_INFO_SHORT pcrInfoWrite;    /* The PCR selection that allows writing of the area */
    TCM_NV_ATTRIBUTES permission;       /* The permissions for manipulating the area */
    TCM_BOOL bReadSTClear;              /* Set to FALSE on each TCM_Startup(ST_Clear) and set to
                                           TRUE after a ReadValuexxx with datasize of 0 */
    TCM_BOOL bWriteSTClear;             /* Set to FALSE on each TCM_Startup(ST_CLEAR) and set to
                                           TRUE after a WriteValuexxx with a datasize of 0. */
    TCM_BOOL bWriteDefine;              /* Set to FALSE after TCM_NV_DefineSpace and set to TRUE
                                           after a successful WriteValuexxx with a datasize of 0 */
    uint32_t dataSize;			/* The size of the data area in bytes */
} TCM_NV_DATA_PUBLIC;

/*  19.4 TCM_NV_DATA_SENSITIVE rev 101

    This is an internal structure that the TCM uses to keep the actual NV data and the controls
    regarding the area.
*/

typedef struct tdTCM_NV_DATA_SENSITIVE {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* This SHALL be TCM_TAG_NV_DATA_SENSITIVE */
#endif
    TCM_NV_DATA_PUBLIC pubInfo; /* The public information regarding this area */
    TCM_SECRET authValue;     /* The authorization value to manipulate the value */
    BYTE *data;                 /* The data area. This MUST not contain any sensitive information as
                                   the TCM does not provide any confidentiality on the data. */
    /* NOTE Added kg */
    TCM_DIGEST digest;          /* for OSAP comparison */
} TCM_NV_DATA_SENSITIVE;

typedef struct tdTCM_NV_INDEX_ENTRIES {
    uint32_t nvIndexCount;			/* number of entries */
    TCM_NV_DATA_SENSITIVE *tcm_nvindex_entry;	/* array of TCM_NV_DATA_SENSITIVE */
} TCM_NV_INDEX_ENTRIES;


/* TCM_NV_DATA_ST

   This is a cache of the the NV defined space volatile flags, used during error rollback
*/

typedef struct tdTCM_NV_DATA_ST {
    TCM_NV_INDEX nvIndex;               /* The index of the data area */
    TCM_BOOL bReadSTClear;
    TCM_BOOL bWriteSTClear;
} TCM_NV_DATA_ST;

/*  TPM_SYMMETRIC_KEY

   This structure describes a symmetric key, used during the process "Collating a Request for a
   Trusted Platform Module Identity".
*/

typedef struct tdTCM_SYMMETRIC_KEY {
    TCM_ALGORITHM_ID algId; 	/* This SHALL be the algorithm identifier of the symmetric key. */
    TCM_ENC_SCHEME encScheme;  /* This SHALL fully identify the manner in which the key will be
                                   used for encryption operations.  */
    uint16_t size;				/* This SHALL be the size of the data parameter in bytes */
    BYTE *data;                 /* This SHALL be the symmetric key data */
} TCM_SYMMETRIC_KEY;

/* TCM_EK_BLOB

  This structure provides a wrapper to each type of structure that will be in use when the
  endorsement key is in use.
*/

typedef struct tdTCM_EK_BLOB {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_EK_BLOB */
#endif
    TCM_EK_TYPE ekType;         /* This SHALL be set to reflect the type of blob in use */
    TCM_SIZED_BUFFER    blob;   /* The blob of information depending on the type */
} TCM_EK_BLOB;

/* TCM_EK_BLOB_ACTIVATE

   This structure contains the symmetric key to encrypt the identity credential.  This structure
   always is contained in a TCM_EK_BLOB.
*/

typedef struct tdTCM_EK_BLOB_ACTIVATE {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* TCM_TAG_EK_BLOB_ACTIVATE */
#endif
    TCM_SYMMETRIC_KEY sessionKey;       /* This SHALL be the session key used by the CA to encrypt
                                           the TCM_IDENTITY_CREDENTIAL */
    TCM_DIGEST idDigest;                /* This SHALL be the digest of the TPM identity public key
                                           that is being certified by the CA */
    TCM_PCR_INFO_SHORT pcrInfo;         /* This SHALL indicate the PCR's and localities */
} TCM_EK_BLOB_ACTIVATE;

/* TCM_IDENTITY_CONTENTS

   TCM_MakeIdentity uses this structure and the signature of this structure goes to a privacy CA
   during the certification process.
*/

typedef struct tdTCM_IDENTITY_CONTENTS {
    uint32_t ordinal;			/* This SHALL be the ordinal of the TCM_MakeIdentity
                                           command. */
    TCM_CHOSENID_HASH labelPrivCADigest;        /* This SHALL be the result of hashing the chosen
                                                   identityLabel and privacyCA for the new TPM
                                                   identity */
    TCM_KEY_PUB_SHORT identityPubKey;      /* This SHALL be the public key structure of the identity
                                          	  key */
} TCM_IDENTITY_CONTENTS;

/* TCM_ASYM_CA_CONTENTS

   This structure contains the symmetric key to encrypt the identity credential.
*/

typedef struct tdTCM_ASYM_CA_CONTENTS {
    TCM_SYMMETRIC_KEY sessionKey;       /* This SHALL be the session key used by the CA to encrypt
                                           the TPM_IDENTITY_CREDENTIAL */
    TCM_DIGEST idDigest;                /* This SHALL be the digest of the TCM_PUBKEY of the key
                                           that is being certified by the CA */
} TCM_ASYM_CA_CONTENTS;

typedef struct tdTCM_CAP_VERSION_INFO {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* MUST be TCM_TAG_CAP_VERSION_INFO */
#endif
    TCM_MANUFACTURER_IDENTITY tcmID;
    TCM_PLATFORM_IDENTITY platformID;
    BYTE revision;
    /* NOTE Cannot be TCM_SIZED_BUFFER, because of uint16_t */
} TCM_CAP_VERSION_INFO;


typedef struct tdTCM_DA_ACTION_TYPE {
    TCM_STRUCTURE_TAG tag;      /* MUST be TCM_TAG_DA_ACTION_TYPE */
    uint32_t actions;		/* The action taken when TCM_DA_STATE is TCM_DA_STATE_ACTIVE. */
} TCM_DA_ACTION_TYPE;


typedef struct tdTCM_DA_INFO {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* MUST be TCM_TAG_DA_INFO */
#endif
    TCM_DA_STATE state;         /* Dynamic.  The actual state of the dictionary attack mitigation
                                   logic.  See 21.9. */
    uint16_t currentCount;	/* Dynamic.  The actual count of the authorization failure counter
                                   for the selected entity type */
    uint16_t thresholdCount;	/* Static.  Dictionary attack mitigation threshold count for the
                                   selected entity type */
    TCM_DA_ACTION_TYPE actionAtThreshold;       /* Static Action of the TCM when currentCount passes
                                                   thresholdCount. See 21.10. */
    uint32_t actionDependValue;	/* Dynamic.  Action being taken when the dictionary attack
                                   mitigation logic is active.  E.g., when actionAtThreshold is
                                   TCM_DA_ACTION_TIMEOUT, this is the lockout time remaining in
                                   seconds. */
    TCM_SIZED_BUFFER vendorData;        /* Vendor specific data field */
} TCM_DA_INFO;

/* 21.8 TCM_DA_INFO_LIMITED rev 100

   This structure is an output from a TCM_GetCapability -> TCM_CAP_DA_LOGIC request if
   TCM_PERMANENT_FLAGS -> disableFullDALogicInfo is TRUE.

   It returns static information describing the TCM response to authorization failures that might
   indicate a dictionary attack and dynamic information regarding the current state of the
   dictionary attack mitigation logic. This structure omits information that might aid an attacker.
*/

typedef struct tdTCM_DA_INFO_LIMITED {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* MUST be TCM_TAG_DA_INFO_LIMITED */
#endif
    TCM_DA_STATE state;         /* Dynamic.  The actual state of the dictionary attack mitigation
                                   logic.  See 21.9. */
    TCM_DA_ACTION_TYPE actionAtThreshold;       /* Static Action of the TCM when currentCount passes
                                                   thresholdCount. See 21.10. */
    TCM_SIZED_BUFFER vendorData;        /* Vendor specific data field */
} TCM_DA_INFO_LIMITED;

/*some cert message:pubkey, certificate structure, signature*/
typedef struct tdTCM_CERTINFO {
    TCM_KEY_PUB_SHORT pubKey;
    TCM_SIZED_BUFFER certificate;
    TCM_SIZED_BUFFER signature;
} TCM_CERTINFO;





#endif
