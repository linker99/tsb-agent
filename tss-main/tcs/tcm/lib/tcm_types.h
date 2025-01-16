/********************************************************************************/

/********************************************************************************/

#ifndef TCM_TYPES_H
#define TCM_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

#ifdef TCM_WINDOWS
#include <windows.h>
#endif
#if defined (TCM_POSIX) || defined (TCM_SYSTEM_P)
#include <netinet/in.h>         /* for byte order conversions */
#endif

typedef unsigned char  BYTE;
typedef unsigned char TCM_BOOL;

#undef TRUE
#define TRUE 0x01
#undef FALSE
#define FALSE 0x00


typedef BYTE  TCM_DA_STATE;             /* The state of the dictionary attack mitigation logic */

/* added kgold */
typedef BYTE  TCM_ENT_TYPE;             /* LSB of TCM_ENTITY_TYPE */
typedef BYTE  TCM_AP_ENC_SCHEME;      /* MSB of TCM_ENTITY_TYPE */
typedef uint16_t  TCM_ENTITY_TYPE;	/* Indicates the types of entity that are supported by the
                                           TCM. */
//typedef uint32_t TCM_SEQ;
typedef uint32_t TCM_RESULT;
typedef uint16_t  TCM_TAG;		/* The command and response tags */
typedef uint16_t  TCM_STRUCTURE_TAG;	/* The tag for the structure */
typedef uint32_t TCM_USER_RES;   /*the response of user error code */
typedef uint32_t TCM_COMMAND_CODE; /* the ordinal */
typedef uint32_t TCM_USER_ID; /*the                      */
typedef unsigned char 	*TCM_SYMMETRIC_KEY_TOKEN;	/* abstract symmetric key token */
typedef uint32_t  TCM_ACTUAL_COUNT;	/* The actual number of a counter.  */
typedef uint32_t TCM_MANUFACTURER_IDENTITY; /* deviceId(2) || vendorId(2) */
typedef uint32_t TCM_PLATFORM_IDENTITY;
typedef uint32_t TCM_AUDIT_SET_TYPE; /* The audit ordinal set the ordinal belongs to */
typedef uint32_t TCM_AUDIT_ORDINAL_SET; /* The bit map of audit ordinal set */
typedef uint32_t TCM_KEY_HANDLE;
typedef uint32_t  TCM_KEY_CONTROL;	/* Allows for controlling of the key when loaded and how to
                                           handle TCM_Startup issues  */
typedef uint32_t  TCM_MODIFIER_INDICATOR; /* The locality modifier  */
typedef uint32_t  TCM_TRANSHANDLE;	/* A transport session handle  */
typedef uint32_t  TCM_HANDLE;		/* A generic handle could be key, transport etc.  */
typedef uint32_t  TCM_COUNT_ID;		/* The ID value of a monotonic counter  */
typedef uint32_t  TCM_NV_INDEX;		/* The index into the NV storage area  */

typedef uint32_t  TCM_TRANSPORT_ATTRIBUTES;	/* Attributes that define what options are in use
                                                   for a transport session */

typedef uint32_t  TCM_AUTHHANDLE;   /* Handle to an authorization session  */

typedef uint32_t  TCM_ALGORITHM_ID;	/* Indicates the type of algorithm.  */
typedef uint16_t  TCM_KEY_TYPE;	/* Indicates the type of a key. */
typedef uint16_t  TCM_KEY_USAGE;	/* Indicates the permitted usage of the key.  */
typedef uint32_t  TCM_KEY_FLAGS;	/* Indicates information regarding a key. */
typedef uint32_t  TCM_RESOURCE_TYPE;	/* The types of resources that a TCM may have using internal
                                           resources */
typedef uint32_t  TCM_PCRINDEX;	   /* Index to a PCR register  */
//typedef uint32_t TCM_CIPH_SCHM_MODE;/*Indicates information regarding the sm2 alogrithm params*/
typedef BYTE TCM_SM2_FIELD_TYPE; /*Indicates information regarding the sm2 base field*/

typedef BYTE TCM_AUTH_DATA_USAGE; /* Indicates the conditions where it is required that
                                           authorization be presented.  */
typedef BYTE TCM_PAYLOAD_TYPE; /* The information as to what the payload is in an encrypted
                                           structure */
typedef uint16_t  TCM_STARTUP_TYPE; /* Indicates the start state.  */
typedef uint16_t  TCM_MIGRATE_SCHEME;   /* The definition of the migration scheme */
typedef uint16_t  TCM_PHYSICAL_PRESENCE; /* Sets the state of the physical presence mechanism. */
typedef uint16_t  TCM_PROTOCOL_ID;	/* The protocol in use.  */
typedef unsigned char 	*TCM_BIGNUM;			/* abstract bignum */
typedef uint16_t  TCM_EK_TYPE;		/* The type of asymmetric encrypted structure in use by the
                                           endorsement key  */
typedef uint32_t  TCM_CAPABILITY_AREA;	/* Identifies a TCM capability area. */
typedef uint16_t  TCM_ENC_SCHEME;	/* The definition of the encryption scheme. */
typedef uint16_t  TCM_SIG_SCHEME;	/* The definition of the signature scheme. */



#endif
