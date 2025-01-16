#ifndef TCM_CONSTANTS_H
#define TCM_CONSTANTS_H

#ifndef TCM_CURVE_P
#define TCM_CURVE_P 0  //lyf 0--->1
#endif

#define TCM_REVISION_MAX 9999
#ifndef TCM_REVISION
#define TCM_REVISION TCM_REVISION_MAX
#endif

/* dictionary attack mitigation */

#define TCM_LOCKOUT_THRESHOLD 5         /* successive failures to trigger lockout, must be greater
                                           than 0 */


#ifndef TCM_BUFFER_MAX
#define TCM_BUFFER_MAX  0x1000  /* 4k bytes */
#endif

/* Timeouts in microseconds.  These are for the platform specific interface (e.g. the LPC bus
   registers in the PC Client TCM).  They are most likely not applicable to a software TCM.  */
#define TCM_TIMEOUT_A   1000000
#define TCM_TIMEOUT_B   1000000
#define TCM_TIMEOUT_C   1000000
#define TCM_TIMEOUT_D   1000000

/* Denotes the duration value in microseconds of the duration of the three classes of commands:
   Small, Medium and Long.  The command types are in the Part 2 Ordinal Table.  Essentially:

   Long - creating an SM2 key pair
   Medium - using an SM2 key
   Short  - anything else
*/

#ifndef TCM_SMALL_DURATION
#define TCM_SMALL_DURATION      2000000
#endif

#ifndef TCM_MEDIUM_DURATION
#define TCM_MEDIUM_DURATION     5000000
#endif

#ifndef TCM_LONG_DURATION
#define TCM_LONG_DURATION      60000000
#endif

/* startup effects */

#define    TCM_STARTUP_EFFECTS_VALUE   \
(TCM_STARTUP_EFFECTS_ST_ANY_RT_KEY |    /* key resources init by TCM_Startup(ST_ANY) */ \
 TCM_STARTUP_EFFECTS_ST_STATE_RT_HASH | /* hash resources are init by TCM_Startup(ST_STATE) */ \
 TCM_STARTUP_EFFECTS_ST_CLEAR_AUDITDIGEST) /* auditDigest nulled on TCM_Startup(ST_CLEAR) */


#ifndef TCM_ALLOC_MAX
#define TCM_ALLOC_MAX  0x10000  /* 64k bytes */
#endif

#define TCM_STORE_BUFFER_INCREMENT (TCM_ALLOC_MAX / 64)


/*
  SW TCM Tags
*/

/*
  These tags are used to describe the format of serialized TCM non-volatile state
*/

/* These describe the overall format */

/* V1 state is the sequence permanent data, permanent flags, owner evict keys, NV defined space */

#define TCM_TAG_NVSTATE_V1		0x0001

/* These tags describe the TCM_PERMANENT_DATA format */

/* For the first release, use the standard TCM_TAG_PERMANENT_DATA tag.  Since this tag is never
   visible outside the TCM, the tag value can be changed if the format changes.
*/

/* These tags describe the TCM_PERMANENT_FLAGS format */

/* The TCM_PERMANENT_FLAGS structure changed from rev 94 to 103.  Unfortunately, the standard TCM
   tag did not change.  Define distinguishing values here.
*/

#define TCM_TAG_NVSTATE_PF94		0x0001
#define TCM_TAG_NVSTATE_PF103		0x0002

/* This tag describes the owner evict key format */

#define TCM_TAG_NVSTATE_OE_V1		0x0001

/* This tag describes the NV defined space format */

#define TCM_TAG_NVSTATE_NV_V1		0x0001

/* V2 added the NV public optimization */

#define TCM_TAG_NVSTATE_NV_V2		0x0002



/*
  These tags are used to describe the format of serialized TCM volatile state
*/

/* These describe the overall format */

/* V1 state is the sequence TCM Parameters, TCM_STCLEAR_FLAGS, TCM_STANY_FLAGS, TCM_STCLEAR_DATA,
   TCM_STANY_DATA, TCM_KEY_HANDLE_ENTRY, SHA1 context(s), TCM_TRANSHANDLE, testState, NV volatile
   flags */

#define TCM_TAG_VSTATE_V1		0x0001

/* This tag defines the TCM Parameters format */

#define TCM_TAG_TCM_PARAMETERS_V1	0x0001

/* This tag defines the TCM_STCLEAR_FLAGS format */

/* V1 is the TCG standard returned by the getcap.  It's unlikely that this will change */

#define TCM_TAG_STCLEAR_FLAGS_V1	0x0001

/* These tags describe the TCM_STANY_FLAGS format */

/* For the first release, use the standard TCM_TAG_STANY_FLAGS tag.  Since this tag is never visible
   outside the TCM, the tag value can be changed if the format changes.
*/

/* This tag defines the TCM_STCLEAR_DATA format */

/* V2 deleted the ordinalResponse, responseCount */

#define TCM_TAG_STCLEAR_DATA_V2         0X0024

/* These tags describe the TCM_STANY_DATA format */

/* For the first release, use the standard TCM_TAG_STANY_DATA tag.  Since this tag is never visible
   outside the TCM, the tag value can be changed if the format changes.
*/

/* This tag defines the key handle entries format */

#define TCM_TAG_KEY_HANDLE_ENTRIES_V1	0x0001

/* This tag defines the SM3 context format */
//ToDo:


/* This tag defines the NV index entries volatile format */

#define TCM_TAG_NV_INDEX_ENTRIES_VOLATILE_V1	0x0001




/* 4.1 TPM_RESOURCE_TYPE rev 87 */

#define TCM_RT_KEY      0x00000001  /* The handle is a key handle and is the result of a LoadKey
                                       type operation */
#define TCM_RT_AUTH      0x00000002 /* The handle is an authorization handle. Auth handles come from
                                       TCM_OIAP, TCM_OSAP */

#define TCM_RT_TRANS      0x00000003 /* The handle is for a transport session. Transport handles come
                                       from TCM_EstablishTransport */

#define TCM_RT_CONTEXT  0x00000005  /* Resource wrapped and held outside the TPM using the context
                                       save/restore commands */

#define TCM_RT_COUNTER  0x00000006  /* Reserved for counters */

#define TCM_RT_USER	 0x00000007  /* Reserved for users */


/* 4.2 TCM_PAYLOAD_TYPE rev 87
   This structure specifies the type of payload in various messages.
*/

#define TCM_PT_KEY             0x01    /* The entity is key priv structure*/
#define TCM_PT_BIND             0x02    /* The entity is bound data */
#define TCM_PT_MIGRATE          0x03    /* The entity is a migration blob */
//#define TCM_PT_MAINT            0x04    /* The entity is a maintenance blob */
#define TCM_PT_SEAL             0x05    /* The entity is sealed data */
//#define TCM_PT_MIGRATE_RESTRICTED 0x06  /* The entity is a restricted-migration asymmetric key */
//#define TCM_PT_MIGRATE_EXTERNAL 0x07    /* The entity is a external migratable key */
//#define TCM_PT_CMK_MIGRATE      0x08    /* The entity is a CMK migratable blob */
/* 0x09 - 0x7F Reserved for future use by TCM */
/* 0x80 - 0xFF Vendor specific payloads */
/* 4.4 Handles rev 88

*/

/* 4.4.1 Reserved Key Handles rev 87

   The reserved key handles. These values specify specific keys or specific actions for the TCM.

   TCM_KH_TRANSPORT indicates to TCM_EstablishTransport that there is no encryption key, and that
   the "secret" wrapped parameters are actually passed unencrypted.
*/

#define TCM_KH_SMK              0x40000000 /* The handle points to the SMK */
#define TCM_KH_OWNER            0x40000001 /* The handle points to the TCM Owner */
#define TCM_KH_REVOKE           0x40000002 /* The handle points to the RevokeTrust value */
#define TCM_KH_TRANSPORT        0x40000003 /* The handle points to the TCM_EstablishTransport static
												  authorization */
#define TCM_KH_EK               0x40000006 /* The handle points to the PUBEK*/


/* 4.10 TCM_MIGRATE_SCHEME rev 103

   The scheme indicates how the StartMigrate command should handle the migration of the encrypted
   blob.
*/

#define TCM_MS_MIGRATE                  0x0001
#define TCM_MS_REWRAP                   0x0002
#define TCM_MS_EXTREWRAP				 0x0003


/* 4.7 TCM_PROTOCOL_ID

   This value identifies the protocol in use.
*/


#define TCM_PID_NONE            0x0000  /* kgold - added */
#define TCM_PID_OIAP            0x0001  /* The OIAP protocol. need abandon */
#define TCM_PID_OSAP            0x0002  /* The OSAP protocol. need abandon */
#define TCM_PID_OWNER           0X0005  /* The protocol for taking ownership of a TCM. */
#define TCM_PID_TRANSPORT       0x0007  /*The transport protocol */
#define TCM_PID_AP              0X0008  /* The protocol for taking ownership of a TCM. */






/* 4.9 TCM_PHYSICAL_PRESENCE rev 87

*/

#define TCM_PHYSICAL_PRESENCE_HW_DISABLE        0x0200 /* Sets the physicalPresenceHWEnable to FALSE
                                                        */
#define TCM_PHYSICAL_PRESENCE_CMD_DISABLE       0x0100 /* Sets the physicalPresenceCMDEnable to
                                                          FALSE */
#define TCM_PHYSICAL_PRESENCE_LIFETIME_LOCK     0x0080 /* Sets the physicalPresenceLifetimeLock to
                                                          TRUE */
#define TCM_PHYSICAL_PRESENCE_HW_ENABLE         0x0040 /* Sets the physicalPresenceHWEnable to TRUE
                                                        */
#define TCM_PHYSICAL_PRESENCE_CMD_ENABLE        0x0020 /* Sets the physicalPresenceCMDEnable to TRUE
                                                        */
#define TCM_PHYSICAL_PRESENCE_NOTPRESENT        0x0010 /* Sets PhysicalPresence = FALSE */
#define TCM_PHYSICAL_PRESENCE_PRESENT           0x0008 /* Sets PhysicalPresence = TRUE */
#define TCM_PHYSICAL_PRESENCE_LOCK              0x0004 /* Sets PhysicalPresenceLock = TRUE */

#define TCM_PHYSICAL_PRESENCE_MASK              0xfc03  /* ~ OR of all above bits */







/* Audit Set default bit map */
#define TCM_DEFAULT_AUDIT_BITMAP  0x3FFFFE  /* The lowest bit must be 0 for the TCM_AUD_NEVER */

/* Audit Set:  used by TCM_ORDINAL_TABLE 'auditSetType'*/
#define TCM_AUD_NEVER		0 /* The ordinal can never be audited*/
#define TCM_AUD_ADMIN		1
#define TCM_AUD_CAP		2
#define TCM_AUD_KEY		3
#define TCM_AUD_AUTH		4
#define TCM_AUD_MIGRATION	5
#define TCM_AUD_HASH		6
#define TCM_AUD_RANDOM		7
#define TCM_AUD_SIGN		8
#define TCM_AUD_EK			9
#define TCM_AUD_INIT	10
#define TCM_AUD_PCR		11
#define TCM_AUD_SESSION	12
#define TCM_AUD_NV			13
#define TCM_AUD_CONTEXT	14
#define TCM_AUD_TICK		15
#define TCM_AUD_COUNTER	16
#define TCM_AUD_SECRET		17
#define TCM_AUD_TRANSPORT	18
#define TCM_AUD_USER		19
#define TCM_AUD_ENCRYPTION 20
#define TCM_AUD_TSC		21 /* TSC_ORD_PhysicalPresence & TSC_ORD_ResetEstablishmentBit  used */

/* Notice! Must update if new audition set is added!*/
#define TCM_AUD_MAX		22/*Must be less than 32*/




#define TCM_TAG_RQU_COMMAND             0x00C1 /* A command with no authentication.  */
#define TCM_TAG_RQU_PROTECT_COMMAND       0x00C2 /* An authenticated command with one authentication
                                                  handle */
#define TCM_TAG_RQU_PROTECT_COMMAND_forTCM       0x00C3	 //lyf add  

#define TCM_TAG_RSP_COMMAND             0x00C4 /* A response from a command with no authentication
                                                */
#define TCM_TAG_RSP_PROTECT_COMMAND       0x00C5 /* An authenticated response with one authentication
                                                  handle */
#define TCM_TAG_RSP_PROTECT_COMMAND_forTCM       0x00C6 /* An authenticated response with one authentication
                                                  handle */
#define TCM_TAG_RSP_IO_FAULT 0x00C6 /*A response for reporting fault in outputting buffer */


/* 10.9 TCM_KEY_CONTROL

   Attributes that can control various aspects of key usage and manipulation.

   Allows for controlling of the key when loaded and how to handle TCM_Startup issues.
*/

#define TCM_KEY_CONTROL_OWNER_EVICT     0x00000001      /* Owner controls when the key is evicted
                                                           from the TCM. When set the TCM MUST
                                                           preserve key the key across all TCM_Init
                                                           invocations. */



/* 13.1.1 TCM_TRANSPORT_ATTRIBUTES Definitions */

#define TCM_TRANSPORT_ENCRYPT           0x00000001      /* The session will provide encryption using
                                                           the internal encryption algorithm */
#define TCM_TRANSPORT_LOG               0x00000002      /* The session will provide a log of all
                                                           operations that occur in the session */
#define TCM_TRANSPORT_EXCLUSIVE         0X00000004      /* The transport session is exclusive and
                                                           any command executed outside the
                                                           transport session causes the invalidation
                                                           of the session */


/* 21.1 TCM_CAPABILITY_AREA rev 115

   To identify a capability to be queried.
*/

#define TCM_CAP_ORD             0x00000001 /* Boolean value. TRUE indicates that the TCM supports
                                              the ordinal. FALSE indicates that the TCM does not
                                              support the ordinal.  Unimplemented optional ordinals
                                              and unused (unassigned) ordinals return FALSE. */
#define TCM_CAP_ALG             0x00000002 /* Boolean value. TRUE means that the TCM supports the
                                              asymmetric & symmetic algorithm for TCM_Sign, TCM_Seal,
                                              TCM_UnSeal and TCM_UnBind and related commands. FALSE
                                              indicates that the algorithm is not
                                              supported for these types of commands. The TCM MAY
                                              return TRUE or FALSE for other than 
                                              algoroithms that it supports. Unassigned and
                                              unsupported algorithm IDs return FALSE.*/

#define TCM_CAP_PID             0x00000003 /* Boolean value. TRUE indicates that the TCM supports
                                              the protocol, FALSE indicates that the TCM does not
                                              support the protocol.  */
#define TCM_CAP_FLAG            0x00000004 /* Return the TCM_PERMANENT_FLAGS structure or Return the
                                              TCM_STCLEAR_FLAGS structure */
#define TCM_CAP_PROPERTY        0x00000005 /* See following table for the subcaps */
#define TCM_CAP_VERSION         0x00000006 /* TCM_STRUCT_VER structure. The Major and Minor must
                                              indicate 1.1. The firmware revision MUST indicate
                                              0.0 */
#define TCM_CAP_KEY_HANDLE      0x00000007 /* A TCM_KEY_HANDLE_LIST structure that enumerates all
                                              key handles loaded on the TCM.  */
#define TCM_CAP_CHECK_LOADED    0x00000008 /* A Boolean value. TRUE indicates that the TCM has
                                              enough memory available to load a key of the type
                                              specified by TCM_KEY_PARMS. FALSE indicates that the
                                              TCM does not have enough memory.  */
#define TCM_CAP_SYM_MODE        0x00000009 /* Subcap TCM_SYM_MODE
                                              A Boolean value. TRUE indicates that the TCM supports
                                              the TCM_SYM_MODE, FALSE indicates the TCM does not
                                              support the mode. */
#define TCM_CAP_KEY_STATUS      0x0000000C /* Boolean value of ownerEvict. The handle MUST point to
                                              a valid key handle.*/
#define TCM_CAP_NV_LIST         0x0000000D /* A list of TCM_NV_INDEX values that are currently
                                              allocated NV storage through TCM_NV_DefineSpace. */
#define TCM_CAP_NV_INDEX        0x00000011 /* A TCM_NV_DATA_PUBLIC structure that indicates the
                                              values for the TCM_NV_INDEX.  Returns TCM_BADINDEX if
                                              the index is not in the TCM_CAP_NV_LIST list. */
#define TCM_CAP_TRANS_ALG       0x00000012 /* Boolean value. TRUE means that the TCM supports the
                                              algorithm for TCM_EstablishTransport,
                                              TCM_ExecuteTransport and
                                              TCM_ReleaseTransportSigned. FALSE indicates that for
                                              these three commands the algorithm is not supported."
                                              */
#define TCM_CAP_HANDLE          0x00000014 /* A TCM_KEY_HANDLE_LIST structure that enumerates all
                                              handles currently loaded in the TCM for the given
                                              resource type.  */
#define TCM_CAP_TRANS_ES        0x00000015 /* Boolean value. TRUE means the TCM supports the
                                              encryption scheme in a transport session for at least
                                              one algorithm..  */
#define TCM_CAP_AUTH_ENCRYPT    0x00000017 /* Boolean value. TRUE indicates that the TCM supports
                                              the encryption algorithm in OSAP encryption of
                                              AuthData values */
#define TCM_CAP_DA_LOGIC        0x00000019 /* (OPTIONAL)
												  A TCM_DA_INFO or TCM_DA_INFO_LIMITED structure that
												  returns data according to the selected entity type
												  (e.g., TCM_ET_KEYHANDLE, TCM_ET_OWNER, TCM_ET_SMK,
												  TCM_ET_COUNTER, TCM_ET_OPERATOR, etc.). If the
												  implemented dictionary attack logic does not support
												  different secret types, the entity type can be
												  ignored. */

#define TCM_CAP_VERSION_VAL     0x0000001A /* TCM_CAP_VERSION_INFO structure. The TCM fills in the
                                              structure and returns the information indicating what
                                              the TCM currently supports. */

#define TCM_CAP_FLAG_PERMANENT  0x00000108 /* Return the TCM_PERMANENT_FLAGS structure */
#define TCM_CAP_FLAG_VOLATILE   0x00000109 /* Return the TCM_STCLEAR_FLAGS structure */
#define TCM_CAP_MEMORY_STATUS	 0x00000018 /*ONLY FOR CCORE CHIP. RETURN THE HEAP STATUS */	//lyf
#if 0
#define TCM_CAP_SELECT_SIZE     0x00000018 /* Boolean value. TRUE indicates that the TCM supports
												  the size for the given version. For instance a request
												  could ask for version 1.1 size 2 and the TCM would
												  indicate TRUE. For 1.1 size 3 the TCM would indicate
												  FALSE. For 1.2 size 3 the TCM would indicate TRUE. */
#define TCM_CAP_MFR             0x00000010 /* Manufacturer specific. The manufacturer may provide
												  any additional information regarding the TCM and the
												  TCM state but MUST not expose any sensitive
												  information.	*/

#endif


/* 21.2 CAP_PROPERTY Subcap values for CAP_PROPERTY rev 105

   The TCM_CAP_PROPERTY capability has numerous subcap values.  The definition for all subcap values
   occurs in this table.

   TCM_CAP_PROP_MANUFACTURER returns a vendor ID unique to each manufacturer. The same value is
   returned as the TCM_CAP_VERSION_INFO -> tcmVendorID.  A company abbreviation such as a null
   terminated stock ticker is a typical choice. However, there is no requirement that the value
   contain printable characters.  The document "TCG Vendor Naming" lists the vendor ID values.

   TCM_CAP_PROP_MAX_xxxSESS is a constant.  At TCM_Startup(ST_CLEAR) TCM_CAP_PROP_xxxSESS ==
   TCM_CAP_PROP_MAX_xxxSESS.  As sessions are created on the TCM, TCM_CAP_PROP_xxxSESS decreases
   toward zero.  As sessions are terminated, TCM_CAP_PROP_xxxSESS increases toward
   TCM_CAP_PROP_MAX_xxxSESS.

   There is a similar relationship between the constants TCM_CAP_PROP_MAX_COUNTERS and
   TCM_CAP_PROP_MAX_CONTEXT and the varying TCM_CAP_PROP_COUNTERS and TCM_CAP_PROP_CONTEXT.

   In one typical implementation where authorization and transport sessions reside in separate
   pools, TCM_CAP_PROP_SESSIONS will be the sum of TCM_CAP_PROP_AUTHSESS and TCM_CAP_PROP_TRANSESS.
   In another typical implementation where authorization and transport sessions share the same pool,
   TCM_CAP_PROP_SESSIONS, TCM_CAP_PROP_AUTHSESS, and TCM_CAP_PROP_TRANSESS will all be equal.
*/

#define TCM_CAP_PROP_PCR                0x00000101    /* uint32_t value. Returns the number of PCR
                                                         registers supported by the TCM */
#define TCM_CAP_PROP_MANUFACTURER       0x00000103    /* uint32_t value.  Returns the vendor ID
                                                         unique to each TCM manufacturer (the lower 2 bytes
                                                         of tcmID).*/
#define TCM_CAP_PROP_KEYS               0x00000104    /* uint32_t value. Returns the number of keys
									that can be loaded. This may
                                                         vary with time and circumstances. */
#define TCM_CAP_PROP_USERS				 0x00000105	   /* uint32_t value. Returns the number of 
									users that can be logged in. */
#define TCM_CAP_PROP_MAX_USERS			 0x00000106    /* uint32_t value. Returns the max number of 
									users that can be logged in. */

#define TCM_CAP_PROP_MIN_COUNTER        0x00000107    /* uint32_t. The minimum amount of time in
                                                         10ths of a second that must pass between
                                                         invocations of incrementing the monotonic
                                                         counter. */
#define TCM_CAP_PROP_AUTHSESS           0x0000010A    /* uint32_t. The number of available
                                                         authorization sessions. This may vary with
                                                         time and circumstances. */
#define TCM_CAP_PROP_TRANSESS           0x0000010B    /* uint32_t. The number of available transport
                                                         sessions. This may vary with time and
                                                         circumstances.  */
#define TCM_CAP_PROP_COUNTERS           0x0000010C    /* uint32_t. The number of available monotonic
                                                         counters. This may vary with time and
                                                         circumstances. */
#define TCM_CAP_PROP_MAX_AUTHSESS       0x0000010D    /* uint32_t. The maximum number of loaded
                                                         authorization sessions the TCM supports */
#define TCM_CAP_PROP_MAX_TRANSESS       0x0000010E    /* uint32_t. The maximum number of loaded
                                                         transport sessions the TCM supports. */
#define TCM_CAP_PROP_MAX_COUNTERS       0x0000010F    /* uint32_t. The maximum number of monotonic
                                                         counters under control of TCM_CreateCounter
                                                         */
#define TCM_CAP_PROP_MAX_KEYS           0x00000110    /* uint32_t. The maximum number of 
                                                         keys that the TCM can support. The number
                                                         does not include the EK or SMK. */
#define TCM_CAP_PROP_OWNER              0x00000111    /* BOOL. A value of TRUE indicates that the
                                                         TCM has successfully installed an owner. */
#define TCM_CAP_PROP_CONTEXT            0x00000112    /* uint32_t. The number of available saved
                                                         session slots. This may vary with time and
                                                         circumstances. */
#define TCM_CAP_PROP_MAX_CONTEXT        0x00000113    /* uint32_t. The maximum number of saved
                                                         session slots. */
#define TCM_CAP_PROP_TIS_TIMEOUT        0x00000115    /* A 4 element array of uint32_t values each
                                                         denoting the timeout value in microseconds
                                                         for the following in this order:

TIMEOUT_A, TIMEOUT_B, TIMEOUT_C, TIMEOUT_D

Where these timeouts are to be used is
determined by the platform specific TCM
Interface Specification. */
#define TCM_CAP_PROP_STARTUP_EFFECT     0x00000116    /* The TCM_STARTUP_EFFECTS structure */
#define TCM_CAP_PROP_SESSIONS           0X0000011D    /* uint32_t. The number of available sessions
                                                         from the pool. This MAY vary with time and
                                                         circumstances. Pool sessions include
                                                         authorization and transport sessions. */
#define TCM_CAP_PROP_MAX_SESSIONS       0x0000011E    /* uint32_t. The maximum number of sessions
                                                         the TCM supports. */

#define TCM_CAP_PROP_DURATION           0x00000120    /* A 3 element array of uint32_t values each
																 denoting the duration value in microseconds
																 of the duration of the three classes of
																 commands: Small, Medium and Long in the
																 following in this order: SMALL_DURATION,
																 MEDIUM_DURATION, LONG_DURATION */

#define TCM_CAP_PROP_ACTIVE_COUNTER     0x00000122      /* TCM_COUNT_ID. The id of the current
                                                           counter. 0xff..ff if no counter is active
                                                        */
#define TCM_CAP_PROP_MAX_NV_AVAILABLE   0x00000123      /*uint32_t. Deprecated.  The maximum number
                                                          of NV space that can be allocated, MAY
                                                          vary with time and circumstances.  This
                                                          capability was not implemented
                                                          consistently, and is replaced by
                                                          TCM_NV_INDEX_TRIAL. */
#define TCM_CAP_PROP_INPUT_BUFFER       0x00000124      /* uint32_t. The maximum size of the TCM
                                                           input buffer or output buffer in
                                                           bytes. */

#if 0
#define TCM_CAP_PROP_DIR                0x00000102    /* uint32_t. Deprecated. Returns the number of
                                                         DIR, which is now fixed at 1 */

#define TCM_CAP_PROP_FAMILYROWS         0x00000114    /* uint32_t. The maximum number of rows in the
                                                         family table */
#define TCM_CAP_PROP_DELEGATE_ROW       0x00000117    /* uint32_t. The maximum size of the delegate
															 table in rows. */
#define TCM_CAP_PROP_MAX_DAASESS        0x00000119    /* uint32_t. The maximum number of loaded DAA
															 sessions (join or sign) that the TCM
															 supports */
#define TCM_CAP_PROP_DAASESS            0x0000011A    /* uint32_t. The number of available DAA
															 sessions. This may vary with time and
															 circumstances */
#define TCM_CAP_PROP_CONTEXT_DIST       0x0000011B    /* uint32_t. The maximum distance between
															 context count values. This MUST be at least
															 2^16-1. */
#define TCM_CAP_PROP_DAA_INTERRUPT      0x0000011C    /* BOOL. A value of TRUE indicates that the
															 TCM will accept ANY command while executing
															 a DAA Join or Sign.

A value of FALSE indicates that the TCM
will invalidate the DAA Join or Sign upon
the receipt of any command other than the
next join/sign in the session or a
TCM_SaveContext */
#define TCM_CAP_PROP_CMK_RESTRICTION    0x0000011F    /* uint32_t TCM_Permanent_Data ->
															 restrictDelegate
														   */
#endif

/* 21.4 Set_Capability Values rev 107
 */

#define TCM_SET_PERM_FLAGS      0x00000001      /* The ability to set a value is field specific and
                                                   a review of the structure will disclose the
                                                   ability and requirements to set a value */
#define TCM_SET_PERM_DATA       0x00000002      /* The ability to set a value is field specific and
                                                   a review of the structure will disclose the
                                                   ability and requirements to set a value */
#define TCM_SET_STCLEAR_FLAGS   0x00000003      /* The ability to set a value is field specific and
                                                   a review of the structure will disclose the
                                                   ability and requirements to set a value */
#define TCM_SET_STCLEAR_DATA    0x00000004      /* The ability to set a value is field specific and
                                                   a review of the structure will disclose the
                                                   ability and requirements to set a value */
#define TCM_SET_STANY_FLAGS     0x00000005      /* The ability to set a value is field specific and
                                                   a review of the structure will disclose the
                                                   ability and requirements to set a value */
#define TCM_SET_STANY_DATA      0x00000006      /* The ability to set a value is field specific and
                                                   a review of the structure will disclose the
                                                   ability and requirements to set a value */
#define TCM_SET_VENDOR          0x00000007      /* This area allows the vendor to set specific areas
                                                   in the TCM according to the normal shielded
                                                   location requirements */

/* Set Capability sub caps */

/* TCM_PERMANENT_FLAGS */

#define  TCM_PF_DISABLE                         1
#define  TCM_PF_OWNERSHIP                       2
#define  TCM_PF_DEACTIVATED                     3
#define  TCM_PF_READPUBEK                       4
#define  TCM_PF_DISABLEOWNERCLEAR               5
#define  TCM_PF_PHYSICALPRESENCELIFETIMELOCK    6
#define  TCM_PF_PHYSICALPRESENCEHWENABLE        7
#define  TCM_PF_PHYSICALPRESENCECMDENABLE       8
#define  TCM_PF_CEKPUSED                        9
#define  TCM_PF_TCMPOST                         10
#define  TCM_PF_TCMPOSTLOCK                     11
#define  TCM_PF_OPERATOR                        12
#define  TCM_PF_ENABLEREVOKEEK                  13
#define  TCM_PF_NV_LOCKED                       14
#define  TCM_PF_TCMESTABLISHED                  15

/* TCM_STCLEAR_FLAGS */

#define  TCM_SF_DEACTIVATED                     1
#define  TCM_SF_DISABLEFORCECLEAR               2
#define  TCM_SF_PHYSICALPRESENCE                3
#define  TCM_SF_PHYSICALPRESENCELOCK            4
#define  TCM_SF_BGLOBALLOCK                     5

/* TCM_STANY_FLAGS */

#define  TCM_AF_POSTINITIALISE                  1
#define  TCM_AF_LOCALITYMODIFIER                2
#define  TCM_AF_PRIVILEGEMODIFIER				 3
#define  TCM_AF_TRANSPORTEXCLUSIVE              4
#define  TCM_AF_TOSPRESENT                      5

/* TCM_PERMANENT_DATA */

#define  TCM_PD_TCMID                          1
#define  TCM_PD_REVISION                        2
#define  TCM_PD_TCMPROOF                       3
#define  TCM_PD_POWERSUPPLYSTATE                4
#define  TCM_PD_GLOBALSTATE                     5
#define  TCM_PD_PLATFORM                        6
#define	 TCM_PD_EKRESET                         7
#define  TCM_PD_ENDORSEMENTKEY                  8
#define  TCM_PD_SRK                             9
#define  TCM_PD_CONTEXTKEY                      10
#define  TCM_PD_MULTIPLESHAREKEY                11
#define  TCM_PD_MONOTONICCOUNTER                12
#define  TCM_PD_PCRATTRIB                       13
#define  TCM_PD_USERINFO                        14
#define  TCM_PD_NOOWNERNVWRITE                  15

/* TCM_STCLEAR_DATA */

#define  TCM_SD_CONTEXTNONCEKEY                 1
#define  TCM_SD_COUNTID                         2
#define  TCM_SD_PCR                             3
#define  TCM_SD_DEFERREDPHYSICALPRESENCE        4

/* TCM_STCLEAR_DATA -> deferredPhysicalPresence bits */

#define  TCM_DPP_UNOWNED_FIELD_UPGRADE  0x00000001      /* bit 0 TCM_FieldUpgrade */

/* TCM_STANY_DATA */

#define  TCM_AD_CONTEXTNONCESESSION             1
#define  TCM_AD_AUDITDIGEST                     2
#define  TCM_AD_CURRENTTICKS                    3
#define  TCM_AD_CONTEXTCOUNT                    4
#define  TCM_AD_CONTEXTLIST                     5
#define  TCM_AD_SESSIONS                        6



/*  TCM_STRUCTURE_TAG */

/*                                              Structure   */
#define TCM_TAG_CONTEXTBLOB             0x0001 /*  TCM_CONTEXT_BLOB */
#define TCM_TAG_CONTEXT_SENSITIVE       0x0002 /*  TCM_CONTEXT_SENSITIVE */
#define TCM_TAG_CONTEXTPOINTER          0x0003 /*  TCM_CONTEXT_POINTER */
#define TCM_TAG_CONTEXTLIST             0x0004 /*  TCM_CONTEXT_LIST */
#define TCM_TAG_SIGNINFO                0x0005 /*  TCM_SIGN_INFO */
#define TCM_TAG_PCR_INFO           	 0x0006 /*  TCM_PCR_INFO */
#define TCM_TAG_EK_BLOB                 0x000C /*  TCM_EK_BLOB */
#define TCM_TAG_COUNTER_VALUE           0x000E /*  TCM_COUNTER_VALUE */
#define TCM_TAG_TRANSPORT_INTERNAL      0x000F /*  TCM_TRANSPORT_INTERNAL */
#define TCM_TAG_TRANSPORT_LOG_IN        0x0010 /*  TCM_TRANSPORT_LOG_IN */
#define TCM_TAG_TRANSPORT_LOG_OUT       0x0011 /*  TCM_TRANSPORT_LOG_OUT */
#define TCM_TAG_AUDIT_EVENT_IN          0x0012 /*  TCM_AUDIT_EVENT_IN */
#define TCM_TAG_AUDIT_EVENT_OUT         0X0013 /*  TCM_AUDIT_EVENT_OUT */
#define TCM_TAG_CURRENT_TICKS           0x0014 /*  TCM_CURRENT_TICKS */
#define TCM_TAG_KEY                     0x0015 /*  TCM_KEY */
#define TCM_TAG_SEALED_PAYLOAD_PUB      0x0016 /*  TCM_SEALED_PAYLOAD_PUB */
#define TCM_TAG_NV_ATTRIBUTES           0x0017 /*  TCM_NV_ATTRIBUTES */
#define TCM_TAG_NV_DATA_PUBLIC          0x0018 /*  TCM_NV_DATA_PUBLIC */
#define TCM_TAG_NV_DATA_SENSITIVE       0x0019 /*  TCM_NV_DATA_SENSITIVE */
#define TCM_TAG_TRANSPORT_AUTH          0x001D /*  TCM_TRANSPORT_AUTH */
#define TCM_TAG_TRANSPORT_PUBLIC        0X001E /*  TCM_TRANSPORT_PUBLIC */
#define TCM_TAG_PERMANENT_FLAGS         0X001F /*  TCM_PERMANENT_FLAGS */
#define TCM_TAG_STCLEAR_FLAGS           0X0020 /*  TCM_STCLEAR_FLAGS */
#define TCM_TAG_STANY_FLAGS             0X0021 /*  TCM_STANY_FLAGS */
#define TCM_TAG_PERMANENT_DATA          0X0022 /*  TCM_PERMANENT_DATA */
#define TCM_TAG_STCLEAR_DATA            0X0023 /*  TCM_STCLEAR_DATA */
#define TCM_TAG_STANY_DATA              0X0024 /*  TCM_STANY_DATA */
#define TCM_TAG_EK_BLOB_ACTIVATE        0X002B /*  TCM_EK_BLOB_ACTIVATE */
#define TCM_TAG_CAP_VERSION_INFO        0X0030 /*  TCM_CAP_VERSION_INFO */
#define TCM_TAG_DA_INFO                 0x0037 /*  TCM_DA_INFO */
#define TCM_TAG_DA_INFO_LIMITED         0x0038 /*  TCM_DA_INFO_LIMITED */
#define TCM_TAG_DA_ACTION_TYPE          0x0039 /*  TCM_DA_ACTION_TYPE */
#define TCM_TAG_USER_INFO				 0x003A /*  TCM_USER_INFO */
#define TCM_TAG_PRIV_TABLE				 0x003B /*  TCM_PRIVILEGE_TABLE */
#define TCM_TAG_USER_DIGEST			 0x003C /*  TCM_USER_DIGEST */



/* 4.5 TCM_STARTUP_TYPE rev 87

   To specify what type of startup is occurring.
*/

#define TCM_ST_CLEAR            0x0001 /* The TCM is starting up from a clean state */
#define TCM_ST_STATE            0x0002 /* The TCM is starting up from a saved state */
#define TCM_ST_DEACTIVATED      0x0003 /* The TCM is to startup and set the deactivated flag to
                                          TRUE */


/* 4.6 TCM_STARTUP_EFFECTS rev 101

   This structure lists for the various resources and sessions on a TCM the affect that TCM_Startup
   has on the values.

   There are three ST_STATE options for keys (restore all, restore non-volatile, or restore none)
   and two ST_CLEAR options (restore non-volatile or restore none).  As bit 4 was insufficient to
   describe the possibilities, it is deprecated.  Software should use TCM_CAP_KEY_HANDLE to
   determine which keys are loaded after TCM_Startup.

   31-9 No information and MUST be FALSE

   8 TCM_RT_DAA_TCM resources are initialized by TCM_Startup(ST_STATE)
   7 TCM_Startup has no effect on auditDigest
   6 auditDigest is set to all zeros on TCM_Startup(ST_CLEAR) but not on other types of TCM_Startup
   5 auditDigest is set to all zeros on TCM_Startup(any)
   4 TCM_RT_KEY Deprecated, as the meaning was subject to interpretation.  (Was:TCM_RT_KEY resources
     are initialized by TCM_Startup(ST_ANY))
   3 TCM_RT_AUTH resources are initialized by TCM_Startup(ST_STATE)
   2 TCM_RT_HASH resources are initialized by TCM_Startup(ST_STATE)
   1 TCM_RT_TRANS resources are initialized by TCM_Startup(ST_STATE)
   0 TCM_RT_CONTEXT session (but not key) resources are initialized by TCM_Startup(ST_STATE)
*/


//#define TCM_STARTUP_EFFECTS_ST_STATE_RT_DAA             0x00000100      /* bit 8 */
#define TCM_STARTUP_EFFECTS_STARTUP_NO_AUDITDIGEST      0x00000080      /* bit 7 */
#define TCM_STARTUP_EFFECTS_ST_CLEAR_AUDITDIGEST        0x00000040      /* bit 6 */
#define TCM_STARTUP_EFFECTS_STARTUP_AUDITDIGEST         0x00000020      /* bit 5 */
#define TCM_STARTUP_EFFECTS_ST_ANY_RT_KEY               0x00000010      /* bit 4 */
#define TCM_STARTUP_EFFECTS_ST_STATE_RT_AUTH            0x00000008      /* bit 3 */
#define TCM_STARTUP_EFFECTS_ST_STATE_RT_HASH            0x00000004      /* bit 2 */
#define TCM_STARTUP_EFFECTS_ST_STATE_RT_TRANS           0x00000002      /* bit 1 */
#define TCM_STARTUP_EFFECTS_ST_STATE_RT_CONTEXT         0x00000001      /* bit 0 */



/* 4.3 TCM_ENTITY_TYPE rev 100

   This specifies the types of entity that are supported by the TCM.

   The LSB is used to indicate the entity type.  The MSB is used to indicate the AP
   encryption scheme when applicable.


   0x0001 specifies a keyHandle entity with XOR encryption
   0x0002 specifies an owner entity with XOR encryption
   0x0003 specifies some data entity with XOR encryption
   0x0004 specifies the SMK entity with XOR encryption
   0x0005 specifies a key entity with XOR encryption

   When the entity is not being used for AP encryption, the MSB MUST be 0x00.
*/

/* TCM_ENTITY_TYPE LSB Values (entity type) */

#define TCM_ET_KEYHANDLE        0x01    /* The entity is a keyHandle or key */
#define TCM_ET_OWNER			     0x02	 /* The entity is the TCM User*/
#define TCM_ET_DATA             0x03    /* The entity is some data */
#define TCM_ET_SMK              0x04    /* The entity is the SMK */
#define TCM_ET_KEY              0x05    /* The entity is a key or keyHandle */
#define TCM_ET_REVOKE           0x06    /* The entity is the RevokeTrust value */
#define TCM_ET_COUNTER          0x0A    /* The entity is a counter */
#define TCM_ET_NV               0x0B    /* The entity is a NV index */
#define TCM_ET_NONE				   0x12
#define TCM_ET_RESERVED_HANDLE  0x40    /* Reserved. This value avoids collisions with the handle
                                           MSB setting.*/






/* TCM_ENTITY_TYPE MSB Values (AP encryption scheme) */

#define TCM_ET_XOR              0x00    /* XOR  */
#define TCM_ET_SM4_CTR       	 0x06    /* SM4 in CTR mode */


/* PCR Attributes*/

#define TCM_DEBUG_PCR 		16
#define TCM_LOCALITY_4_PCR	17
#define TCM_LOCALITY_3_PCR	18
#define TCM_LOCALITY_2_PCR	19
#define TCM_LOCALITY_1_PCR	20


/*TCM Command Ordinals: must less than TCM_ORDINALS_MAX*/
#define TCM_ORD_ContinueSelfTest					    0x00008053 //lyf


#define TCM_ORD_PhysicalSetDeactivated  			   0x00008072
#define  TCM_ORD_SetOperatorAuth                   0X00008074


#define TCM_ORD_AP                            	 0x000080BF
#define TCM_ORD_AuthorizeMigrationKey           0x000080C3
#define TCM_ORD_CreateMigrationBlob			      0x000080C1
#define TCM_ORD_ChangeAuth                      0x0000800C
#define TCM_ORD_ChangeAuthOwner                 0x00008010
#define TCM_ORD_ConvertMigrationBlob			   0x000080C2
#define TCM_ORD_CreateWrapKey                   0x0000801F
#define TCM_ORD_LoadKey                         0x000080EF
#define TCM_ORD_GetPubKey                       0x00008021
#define TCM_ORD_WrapKey                       	0x000080BD
#define TCM_ORD_CreateCounter                   0x000080DC
#define TCM_ORD_EstablishTransport              0x000080E6
#define TCM_ORD_ExecuteTransport                0x000080E7
#define TCM_ORD_Extend   			               0x00008014
#define TCM_ORD_GetAuditDigest                  0x00008085
#define TCM_ORD_GetAuditDigestSigned            0x00008086
#define TCM_ORD_GetCapability                   0x00008065
#define TCM_ORD_GetTicks                        0x000080F1
#define TCM_ORD_NV_DefineSpace                  0x000080CC
#define TCM_ORD_NV_ReadValue                    0x000080CF
#define TCM_ORD_NV_ReadValueAuth                0x000080D0
#define TCM_ORD_NV_WriteValue                   0x000080CD
#define TCM_ORD_NV_WriteValueAuth               0x000080CE
#define TCM_ORD_IncrementCounter                0x000080DD
#define TCM_ORD_Init                            0x00008097
#define TCM_ORD_OwnerClear                      0x0000805B
#define TCM_ORD_ResetLockValue		            0x00008040
#define TCM_ORD_DisableOwnerClear               0x0000805C
#define TCM_ORD_PhysicalDisable					   0x00008070
#define TCM_ORD_DisableForceClear               0x0000805E
#define TCM_ORD_ForceClear                       0x0000805D
#define TCM_ORD_PhysicalEnable                  0x0000806F
#define TCM_ORD_SetOwnerInstall                 0x00008071
#define TCM_ORD_CreateEndorsementKeyPair	      0x00008078
#define TCM_ORD_CreateRevocableEK               0x0000807F
#define TCM_ORD_RevokeTrust                     0x00008080
#define TCM_ORD_ReadCounter                     0x000080DE
#define TCM_ORD_PCRRead                         0x00008015
#define TCM_ORD_OwnerSetDisable                  0x0000806E
#define TCM_ORD_SetTempDeactivated               0x00008073
#define TCM_ORD_Quote                           0x00008016

#define TCM_ORD_ReadPubek                       0x0000807C
#define TCM_ORD_PCR_Reset                        0x000080C8
#define TCM_ORD_ReleaseCounter                  0x000080DF
#define TCM_ORD_ReleaseCounterOwner             0x000080E0
#define TCM_ORD_ReleaseTransport                0x000080E8
#define TCM_ORD_SaveState                       0x00008098

#define TCM_ORD_SetCapability                   0x0000803F
#define TCM_ORD_SetOrdinalAuditStatus           0x0000808D

#define TCM_ORD_Startup                         0x00008099
#define TCM_ORD_SM3Update                       0x000080EB
#define TCM_ORD_SM3Complete                     0x000080EC
#define TCM_ORD_SM3CompleteExtend               0x000080ED
#define TCM_ORD_Sign                            0x0000803C
#define TCM_ORD_TakeOwnership                   0x0000800D
#define TCM_ORD_FlushSpecific                   0x000080BA
#define TCM_ORD_APTerminate                     0x000080C0
#define TCM_ORD_TickStampBlob                   0x000080F2
#define TCM_ORD_CertifyKey                      0x00008032
#define TCM_ORD_SM3Start                        0x000080EA
#define TCM_ORD_GetRandom                       0x00008046
#define TCM_ORD_SaveContext                     0x000080B8
#define TCM_ORD_LoadContext                     0x000080B9
#define TCM_ORD_GetTestResult                   0x00008054
#define TCM_ORD_SelfTestFull                    0x00008050
#define TCM_ORD_Seal                            0x00008017
#define TCM_ORD_Unseal                          0x00008018
#define TCM_ORD_MakeIdentity                    0x00008079
#define TCM_ORD_ActivateIdentity                0x0000807A
#define TCM_ORD_SM2Decrypt                      0x000080EE
#define TCM_ORD_SM4Decrypt                      0x000080C6
#define TCM_ORD_SM4Encrypt                      0x000080C5
#define TCM_ORD_OwnerReadInternalPub            0x00008081
#define TCM_ORD_ActivatePEKCert                 0x400080DA
#define TCM_ORD_ActivatePEK                     0x400080D9
#define TCM_ORD_TestActivatePEK                 0x0000809A
#define TCM_ORD_CreateKeyExchange               0x000080AF
#define TCM_ORD_GetKeyExchange                  0x000080B0
#define TCM_ORD_ReleaseExchangeSession			0x000080AE
/*TSC Commands: both are bigger than TCM_ORDINALS_MAX*/
#define TSC_ORD_PhysicalPresence                0x4000000A
#define TSC_ORD_ResetEstablishmentBit           0x4000000B





/* define a value for an illegal instance handle */
#define TCM_ILLEGAL_INSTANCE_HANDLE     0xffffffff

/*TCM_KEY_USAGE*/
//#define TCM_KEY_USG_UNINITIALIZED    				0x0000
//#define TCM_KEY_USG_STORAGE         	  				0x0001
//#define TCM_KEY_USG_SIGN         							0x0002
//#define TCM_KEY_USG_IDENTITY        					0x0003
//#define TCM_KEY_USG_ENCRYPTION      				0x0004
//#define TCM_KEY_USG_SIGNENCRYPTION            	0x0005
//#define TCM_KEY_USG_MIGRATION          				0x0006
//#define TCM_KEY_USG_SECRETTRANS					0x0007


#define TCM_KEY_USG_UNINITIALIZED   0x0000
#define TCM_SM2KEY_SIGNING         0x0010
#define TCM_SM2KEY_STORAGE         0x0011
#define TCM_SM2KEY_IDENTITY         0x0012
#define TCM_SM2KEY_BIND            0x0014
#define TCM_SM2KEY_MIGRATION       0x0016
#define TCM_SM2KEY_PEK             0x0017
#define TCM_SM4KEY_STORAGE        0x0018
#define TCM_SM4KEY_BIND            0x0019
#define TCM_SM4KEY_MIGRATION       0x001A


/*  TCM_CIPH_SCHM_MODE

   The TCM MUST check that the encryption mode and signature mode defined for use with the key is a valid mode for
   the key type, as follows:
*/
#define TCM_EM_MASK								0x000000ff
#define TCM_SM_MASK								0x0000ff00
#define TCM_MAC_MASK						0x00ff0000
#define TCM_MODE_UNINITIALIZED     	0x00000000
#define TCM_EM_NONE                      0x00000000
#define TCM_EM_DROP						0x00000001
#define TCM_EM_SYM_ECB				0x00000002
#define TCM_EM_SYM_CBC				0x00000003
#define TCM_EM_SYM_CTR            	0x00000004
#define TCM_EM_SYM_OFB      			0x00000005
#define TCM_EM_SYM_CFB				0x00000006
#define TCM_EM_ASYM_PKCS			0x00000007//to extend 
#define TCM_MAC_HMAC					0x00010000//to extend
#define TCM_SM_NONE		                0x00000000
#define TCM_SM_DROP						0x00000100
#define TCM_SM_SM3      					0x00000200
#define TCM_SM_ENCODE					0x00000300//to extend
#define TCM_SM_INFO						0x00000400//to extend
#define TCM_SM_PKCS						0x00000500//to extend


/*   Cipher algorithm  */
#define TCM_SM2_FILED_UNINITIALIZED 0x0
#define TCM_SM2_FIELD_PRIME	0x01
#define TCM_SM2_FIELD_EXTENSION 0x02

/* 19. NV storage structures */

/* 19.1 TCM_NV_INDEX rev 110

     The index provides the handle to identify the area of storage. The reserved bits allow for a


     segregation of the index name space to avoid name collisions.

     The TCM may check the resvd bits for zero.  Thus, applications should set the bits to zero.

     The TCG defines the space where the high order bits (T, P, U) are 0. The other spaces are
     controlled by the indicated entity.

     T is the TCM manufacturer reserved bit. 0 indicates a TCG defined value. 1 indicates a TCM
     manufacturer specific value.

     P is the platform manufacturer reserved bit. 0 indicates a TCG defined value. 1 indicates that
     the index is controlled by the platform manufacturer.

     U is for the platform user. 0 indicates a TCG defined value. 1 indicates that the index is
     controlled by the platform user.

     The TCM_NV_INDEX is a 32-bit value.
     3                   2                   1
     1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |T|P|U|D| resvd |   Purview      |         Index                |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

     Where:

     1. The TCM MAY return an error if the reserved area bits are not set to 0.

     2. The TCM MUST accept all values for T, P, and U

     3. D indicates defined. 1 indicates that the index is permanently defined and that any
        TCM_NV_DefineSpace operation will fail after nvLocked is set TRUE.

     a. TCG reserved areas MAY have D set to 0 or 1

     4. Purview is the value used to indicate the platform specific area. This value is the
     same as used for command ordinals.

     a. The TCM MUST reject purview values that the TCM cannot support. This means that an
     index value for a PDA MUST be rejected by a TCM designed to work only on the PC Client.
*/

#define TCM_NV_INDEX_T_BIT              0x80000000
#define TCM_NV_INDEX_P_BIT              0x40000000
#define TCM_NV_INDEX_U_BIT              0x20000000
#define TCM_NV_INDEX_D_BIT              0x10000000
/* added kgold */
#define TCM_NV_INDEX_RESVD              0x0f000000
#define TCM_NV_INDEX_PURVIEW_BIT        16
#define TCM_NV_INDEX_PURVIEW_MASK       0x00ff0000

/* 19.1.1 Required TCM_NV_INDEX values rev 97

   The required index values must be found on each TCM regardless of platform. These areas are
   always present and do not require a TCM_DefineSpace command to allocate.

   A platform specific specification may add additional required index values for the platform.

   The TCM MUST reserve the space as indicated for the required index values
*/
#define TCM_NV_INDEX_LOCK  0xFFFFFFFF   /* This value turns on the NV authorization
                                           protections. Once executed all NV areas use the
                                           protections as defined. This value never resets.

Attempting to execute TCM_NV_DefineSpace on this value
with non-zero size MAY result in a TCM_BADINDEX
response.
*/

#define TCM_NV_INDEX0      0x00000000   /* This value allows for the setting of the bGlobalLock
                                           flag, which is only reset on TCM_Startup(ST_Clear)

than zero MAY result in the TCM_BADINDEX error code.
*/

#if 0
#define TCM_NV_INDEX_DIR   0x10000001   /* Size MUST be 20. This index points to the deprecated DIR
                                           command area from 1.1.  The TCM MUST map this reserved
                                           space to be the area operated on by the 1.1 DIR commands.
                                           */

#endif

/* 19.1.2 Reserved Index values rev 116

  The reserved values are defined to avoid index collisions. These values are not in each and every
  TCM.

  1. The reserved index values are to avoid index value collisions.
  2. These index values require a TCM_DefineSpace to have the area for the index allocated
  3. A platform specific specification MAY indicate that reserved values are required.
  4. The reserved index values MAY have their D bit set by the TCM vendor to permanently
*/

#define TCM_NV_INDEX_TCM                0x0000Fxxx      /* Reserved for TCM use */
#define TCM_NV_INDEX_EKCert             0x0000F000      /* The Endorsement credential */

#define TCM_NV_INDEX_TCM_CC             0x0000F001      /* The TCM Conformance credential */
#define TCM_NV_INDEX_PlatformCert       0x0000F002      /* The platform credential */
#define TCM_NV_INDEX_Platform_CC        0x0000F003      /* The Platform conformance credential */
#define TCM_NV_INDEX_TRIAL              0x0000F004      /* To try TCM_NV_DefineSpace without
                                                           actually allocating NV space */

#define TCM_NV_INDEX_GPIO_00            0x00011600      /* GPIO-Express-00 */

#define TCM_NV_INDEX_GPIO_START         0x00011600      /* Reserved for GPIO pins */
#define TCM_NV_INDEX_GPIO_END           0x000116ff      /* Reserved for GPIO pins */

/* 19.2 TCM_NV_ATTRIBUTES rev 99

   The attributes TCM_NV_PER_AUTHREAD and TCM_NV_PER_OWNERREAD cannot both be set to TRUE.
   Similarly, the attributes TCM_NV_PER_AUTHWRITE and TCM_NV_PER_OWNERWRITE cannot both be set to
   TRUE.
*/

#define TCM_NV_PER_READ_STCLEAR         0x80000000 /* 31: The value can be read until locked by a
                                                      read with a data size of 0.  It can only be
                                                      unlocked by TCM_Startup(ST_Clear) or a
                                                      successful write. Lock held for each area in
                                                      bReadSTClear. */
/* #define 30:19 Reserved */
#define TCM_NV_PER_AUTHREAD             0x00040000 /* 18: The value requires authorization to read
                                                      */
#define TCM_NV_PER_OWNERREAD            0x00020000 /* 17: The value requires TCM Owner authorization
                                                      to read. */
#define TCM_NV_PER_PPREAD               0x00010000 /* 16: The value requires physical presence to
                                                      read */
#define TCM_NV_PER_GLOBALLOCK           0x00008000 /* 15: The value is writable until a write to
                                                      index 0 is successful. The lock of this
                                                      attribute is reset by
                                                      TCM_Startup(ST_CLEAR). Lock held by SF ->
                                                      bGlobalLock */
#define TCM_NV_PER_WRITE_STCLEAR        0x00004000 /* 14: The value is writable until a write to
                                                      the specified index with a datasize of 0 is
                                                      successful. The lock of this attribute is
                                                      reset by TCM_Startup(ST_CLEAR). Lock held for
                                                      each area in bWriteSTClear. */
#define TCM_NV_PER_WRITEDEFINE          0x00002000 /* 13: Lock set by writing to the index with a
                                                      datasize of 0. Lock held for each area in
                                                      bWriteDefine.  This is a persistent lock. */
#define TCM_NV_PER_WRITEALL             0x00001000 /* 12: The value must be written in a single
                                                      operation */
/* #define 11:3 Reserved for write additions */
#define TCM_NV_PER_AUTHWRITE            0x00000004 /* 2: The value requires authorization to write
                                                      */
#define TCM_NV_PER_OWNERWRITE           0x00000002 /* 1: The value requires TCM Owner authorization
                                                      to write */
#define TCM_NV_PER_PPWRITE              0x00000001 /* 0: The value requires physical presence to
                                                      write */

/* 5.9 TCM_AUTH_DATA_USAGE rev 110

   The indication to the TCM when authorization sessions for an entity are required.  Future
   versions may allow for more complex decisions regarding AuthData checking.
*/

#define TCM_AUTH_NEVER         0x00 /* This SHALL indicate that usage of the key without
                                       authorization is permitted. */

#define TCM_AUTH_ALWAYS        0x01 /* This SHALL indicate that on each usage of the key the
                                       authorization MUST be performed. */

#define TCM_NO_READ_PUBKEY_AUTH 0x02 /* This SHALL indicate that on commands that require the TCM to
                                       use the the key, the authorization MUST be performed. For
                                       commands that cause the TCM to read the public portion of the
                                       key, but not to use the key (e.g. TCM_GetPubKey), the
                                       authorization may be omitted. */

/* 5.10 TCM_KEY_FLAGS rev 110

   This table defines the meanings of the bits in a TCM_KEY_FLAGS structure, used in
   TCM_STORE_ASYMKEY and TCM_CERTIFY_INFO.

   The value of TCM_KEY_FLAGS MUST be decomposed into individual mask values. The presence of a mask
   value SHALL have the effect described in the above table

   On input, all undefined bits MUST be zero. The TCM MUST return an error if any undefined bit is
   set. On output, the TCM MUST set all undefined bits to zero.
*/
#define TCM_KEY_FLG_MASK						0x00000007
#define TCM_KEY_FLG_NOT_REQUIRED	 0x80000000				/* for requireKeyFlags Value, notice that until now our requirement is limited in single bit annocement */
#define TCM_KEY_FLG_UNINITIALIZED			0x00000000 /* non-migratable && pcr_check */
#define TCM_KEY_FLG_MIGRATABLE          0x00000002 /* This mask value SHALL indicate that the key is
                                              migratable. */

#define TCM_KEY_FLG_ISVOLATILE          0x00000004 /* This mask value SHALL indicate that the key MUST be
                                              unloaded upon execution of the
                                              TCM_Startup(ST_Clear). This does not indicate that a
                                              non-volatile key will remain loaded across
                                              TCM_Startup(ST_Clear) events. */

#define TCM_KEY_FLG_PCRIGNOREDONREAD    0x00000008 /* When TRUE the TCM MUST NOT check digestAtRelease or
                                              localityAtRelease for commands that read the public
                                              portion of the key (e.g., TCM_GetPubKey) and MAY NOT
                                              check digestAtRelease or localityAtRelease for
                                              commands that use the public portion of the key
                                              (e.g. TCM_Seal) */

/*
	TCM_KEY_TYPE 16 bits
*/
#define TCM_KEY_TYP_UNINITIALIZED		0x0000
#define TCM_KEY_TYP_SYMMETRIC			0x0001
#define TCM_KEY_TYP_ASYMMETRIC		0x0002

/* 21.9 TCM_DA_STATE rev 100

   TCM_DA_STATE enumerates the possible states of the dictionary attack mitigation logic.
*/

#define TCM_DA_STATE_INACTIVE   0x00    /* The dictionary attack mitigation logic is currently
                                           inactive */
#define TCM_DA_STATE_ACTIVE     0x01    /* The dictionary attack mitigation logic is
                                           active. TCM_DA_ACTION_TYPE (21.10) is in progress. */


#define TCM_DA_ACTION_FAILURE_MODE      0x00000008 /* bit 3: The TCM is in failure mode. */
#define TCM_DA_ACTION_DEACTIVATE        0x00000004 /* bit 2: The TCM is in the deactivated state. */
#define TCM_DA_ACTION_DISABLE           0x00000002 /* bit 1: The TCM is in the disabled state. */
#define TCM_DA_ACTION_TIMEOUT           0x00000001 /* bit 0: The TCM will be in a locked state for
                                                      TCM_DA_INFO -> actionDependValue seconds. This
                                                      value is dynamic, depending on the time the
                                                      lock has been active.  */

/*
	TCM_ALGORITHM_ID 32 bits
*/

#define TCM_ALG_UNINITIALIZED		      0x00000000
#define TCM_ALG_SM2					  0x0000000B
#define TCM_ALG_SM3					  0x0000000D
#define TCM_ALG_SM4					  0x0000000C
#define TCM_ALG_HMAC					  0x00000004
#define TCM_ALG_KDF1					  0x00000007
#define TCM_ALG_XOR					  0x0000000A

/*
	TCM_KEY_LENGTH
*/
#define TCM_SM2_KEY_LENGTH_MAX		1024
#define TCM_SM2_KEY_LENGTH_MIN			256
#define TCM_SM4_KEY_LENGTH					128

/*
	TCM_KEY_SIZE
*/
#define TCM_SM4_KEY_SIZE			16


/*
 * TCM_ENC_SCHEME
 */
#define TCM_ES_NONE          0x0000
#define TCM_ES_SM2           0x0006      /*ECC encrypt encode*/
#define TCM_ES_SM2NONE       0x0004      /*can't use to encrypt*/
#define TCM_ES_SM4_CBC       0x0008      /*SM4 symmetric CBC encode*/
#define TCM_ES_SM4_ECB       0x000A      /*SM4 symmetric ECB encode*/
#define TCM_ES_SM4_CTR       0x000C      /*SM4 symmetric CBC encode*/
#define TCM_ES_SM4_OFB       0x000E      /*SM4 symmetric ECB encode*/


/*
 * TCM_SIG_SCHEME
 */

#define TCM_SS_SM2           0x0005      /*SM2 sign*/
#define TCM_SS_SM2NONE       0x0001      /*can't use to sign*/


#endif
