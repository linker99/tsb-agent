/********************************************************************************/
/*
	Changlelog:
*/
/********************************************************************************/

#ifndef TCM_ERROR_H
#define TCM_ERROR_H

/* 16. Return codes rev 99

   The TCM has five types of return code. One indicates successful operation and four indicate
   failure. TCM_SUCCESS (00000000) indicates successful execution. The failure reports are:
   TCM defined fatal errors (00000001 to 000003FF), vendor defined fatal errors (00000400 to
   000007FF), TCM defined non-fatal errors (00000800 to 00000BFF), and vendor defined
   non-fatal errors (00000C00 to 00000FFF).

   The range of vendor defined non-fatal errors was determined by the TSS-WG, which defined
   XXXX YCCC with XXXX as OS specific and Y defining the TSS SW stack layer (0: TCM layer)

   All failure cases return only a non-authenticated fixed set of information. This is because
   the failure may have been due to authentication or other factors, and there is no possibility
   of producing an authenticated response.

   Fatal errors also terminate any authorization sessions. This is a result of returning only the
   error code, as there is no way to return the nonces necessary to maintain an authorization
   session. Non-fatal errors do not terminate authorization sessions.

   The return code MUST use the following base. The return code MAY be TCG defined or vendor
   defined. */

#define TCM_BASE                0x0             /*  The start of TCM return codes */
#define TCM_SUCCESS             TCM_BASE        /* Successful completion of the operation */
#define TCM_VENDOR_ERROR        TCM_Vendor_Specific32   /* Mask to indicate that the error code is
                                                           vendor specific for vendor specific
                                                           commands. */
#define TCM_NON_FATAL           0x00000800 /* Mask to indicate that the error code is a non-fatal
                                              failure. */

/* TCM-defined fatal error codes */

#define TCM_AUTHFAIL            TCM_BASE + 1  /* Authentication failed */
#define TCM_BADINDEX            TCM_BASE + 2  /* The index to a PCR, DIR or other register is
                                                 incorrect */
#define TCM_BAD_PARAMETER       TCM_BASE + 3  /* One or more parameter is bad */
#define TCM_AUDITFAILURE        TCM_BASE + 4  /* An operation completed successfully but the auditing
                                                 of that operation failed.  */
#define TCM_CLEAR_DISABLED      TCM_BASE + 5  /* The clear disable flag is set and all clear
                                                 operations now require physical access */
//#define TCM_DEACTIVATED         TCM_BASE + 6  /* The TCM is deactivated */
//#define TCM_DISABLED            TCM_BASE + 7  /* The TCM is disabled */
#define TCM_OFFLINED			 TCM_BASE + 6	/* The TCM is offlined */
#define TCM_ONLINED			 TCM_BASE + 7  /* The TCM is onlined */

#define TCM_DISABLED_CMD        TCM_BASE + 8  /* The target command has been disabled */
#define TCM_FAIL                TCM_BASE + 9  /* The operation failed */
#define TCM_BAD_ORDINAL         TCM_BASE + 10 /* The ordinal was unknown or inconsistent */
#define TCM_INSTALL_DISABLED    TCM_BASE + 11 /* The ability to install an owner is disabled */
#define TCM_INVALID_KEYHANDLE   TCM_BASE + 12 /* The key handle presented was invalid */
#define TCM_KEYNOTFOUND         TCM_BASE + 13 /* The target key was not found */
#define TCM_INAPPROPRIATE_ENC   TCM_BASE + 14 /* Unacceptable encryption scheme */
#define TCM_MIGRATEFAIL         TCM_BASE + 15 /* Migration authorization failed */
#define TCM_INVALID_PCR_INFO    TCM_BASE + 16 /* PCR information could not be interpreted */
#define TCM_NOSPACE             TCM_BASE + 17 /* No room to load key.  */
#define TCM_NOSMK               TCM_BASE + 18 /* There is no SMK set */
#define TCM_NOTSEALED_BLOB      TCM_BASE + 19 /* An encrypted blob is invalid or was not created by
                                                 this TCM */
#define TCM_OWNER_SET           TCM_BASE + 20 /* There is already an Owner */
#define TCM_RESOURCES           TCM_BASE + 21 /* The TCM has insufficient internal resources to
                                                 perform the requested action.  */
#define TCM_SHORTRANDOM         TCM_BASE + 22 /* A random string was too short */
#define TCM_SIZE                TCM_BASE + 23 /* The TCM does not have the space to perform the
                                                 operation. */
#define TCM_WRONGPCRVAL         TCM_BASE + 24 /* The named PCR value does not match the current PCR
                                                 value. */
#define TCM_BAD_PARAM_SIZE      TCM_BASE + 25 /* The paramSize argument to the command has the
                                                 incorrect value */
#define TCM_SM3_THREAD          TCM_BASE + 26 /* There is no existing SM3 thread.  */
#define TCM_SM3_ERROR           TCM_BASE + 27 /* The calculation is unable to proceed because the
                                                 existing SM3 thread has already encountered an
                                                 error.  */
#define TCM_FAILEDSELFTEST      TCM_BASE + 28 /* Self-test has failed and the TCM has shutdown.  */
#define TCM_AUTH2FAIL           TCM_BASE + 29 /* The authorization for the second key in a 2 key
                                                 function failed authorization */
#define TCM_BADTAG              TCM_BASE + 30 /* The tag value sent to for a command is invalid */
#define TCM_IOERROR             TCM_BASE + 31 /* An IO error occurred transmitting information to
                                                 the TCM */
#define TCM_ENCRYPT_ERROR       TCM_BASE + 32 /* The encryption process had a problem.  */
#define TCM_DECRYPT_ERROR       TCM_BASE + 33 /* The decryption process did not complete.  */
#define TCM_INVALID_AUTHHANDLE  TCM_BASE + 34 /* An invalid handle was used.  */
#define TCM_NO_ENDORSEMENT      TCM_BASE + 35 /* The TCM does not a EK installed */
#define TCM_INVALID_KEYUSAGE    TCM_BASE + 36 /* The usage of a key is not allowed */
#define TCM_WRONG_ENTITYTYPE    TCM_BASE + 37 /* The submitted entity type is not allowed */
#define TCM_INVALID_POSTINIT    TCM_BASE + 38 /* The command was received in the wrong sequence
                                                 relative to TCM_Init and a subsequent TCM_Startup
                                                 */
#define TCM_INAPPROPRIATE_SIG   TCM_BASE + 39 /* Signed data cannot include additional DER
                                                 information */
#define TCM_BAD_KEY_PROPERTY    TCM_BASE + 40 /* The key properties in TCM_KEY_PARMs are not
                                                 supported by this TCM */
#define TCM_BAD_MIGRATION       TCM_BASE + 41 /* The migration properties of this key are incorrect.
                                               */
#define TCM_BAD_SCHEME          TCM_BASE + 42 /* The signature or encryption scheme for this key is
                                                 incorrect or not permitted in this situation.  */
#define TCM_BAD_DATASIZE        TCM_BASE + 43 /* The size of the data (or blob) parameter is bad or
                                                 inconsistent with the referenced key */
#define TCM_BAD_MODE            TCM_BASE + 44 /* A mode parameter is bad, such as capArea or
                                                 subCapArea for TCM_GetCapability, physicalPresence
                                                 parameter for TCM_PhysicalPresence, or
                                                 migrationType for TCM_CreateMigrationBlob.  */
#define TCM_BAD_PRESENCE        TCM_BASE + 45 /* Either the physicalPresence or physicalPresenceLock
                                                 bits have the wrong value */
#define TCM_BAD_VERSION         TCM_BASE + 46 /* The TCM cannot perform this version of the
                                                 capability */
#define TCM_NO_WRAP_TRANSPORT   TCM_BASE + 47 /* The TCM does not allow for wrapped transport
                                                 sessions */
#define TCM_AUDITFAIL_UNSUCCESSFUL TCM_BASE + 48 /* TCM audit construction failed and the
                                                    underlying command was returning a failure
                                                    code also */
#define TCM_AUDITFAIL_SUCCESSFUL   TCM_BASE + 49 /* TCM audit construction failed and the underlying
                                                    command was returning success */
#define TCM_NOTRESETABLE        TCM_BASE + 50 /* Attempt to reset a PCR register that does not have
                                                 the resettable attribute */
#define TCM_NOTLOCAL            TCM_BASE + 51 /* Attempt to reset a PCR register that requires
                                                 locality and locality modifier not part of command
                                                 transport */
#define TCM_BAD_TYPE            TCM_BASE + 52 /* Make identity blob not properly typed */
#define TCM_INVALID_RESOURCE    TCM_BASE + 53 /* When saving context identified resource type does
                                                 not match actual resource */
#define TCM_NOTFIPS             TCM_BASE + 54 /* The TCM is attempting to execute a command only
                                                 available when in FIPS mode */
#define TCM_INVALID_FAMILY      TCM_BASE + 55 /* The command is attempting to use an invalid family
                                                 ID */
#define TCM_NO_NV_PERMISSION    TCM_BASE + 56 /* The permission to manipulate the NV storage is not
                                                 available */
#define TCM_REQUIRES_SIGN       TCM_BASE + 57 /* The operation requires a signed command */
#define TCM_KEY_NOTSUPPORTED    TCM_BASE + 58 /* Wrong operation to load an NV key */
#define TCM_AUTH_CONFLICT       TCM_BASE + 59 /* NV_LoadKey blob requires both owner and blob
                                                 authorization */
#define TCM_AREA_LOCKED         TCM_BASE + 60 /* The NV area is locked and not writable */
#define TCM_BAD_LOCALITY        TCM_BASE + 61 /* The locality is incorrect for the attempted
                                                 operation */
#define TCM_READ_ONLY           TCM_BASE + 62 /* The NV area is read only and can't be written to
                                               */
#define TCM_PER_NOWRITE         TCM_BASE + 63 /* There is no protection on the write to the NV area
                                               */
#define TCM_FAMILYCOUNT         TCM_BASE + 64 /* The family count value does not match */
#define TCM_WRITE_LOCKED        TCM_BASE + 65 /* The NV area has already been written to */
#define TCM_BAD_ATTRIBUTES      TCM_BASE + 66 /* The NV area attributes conflict */
#define TCM_INVALID_STRUCTURE   TCM_BASE + 67 /* The structure tag and version are invalid or
                                                 inconsistent */
#define TCM_KEY_OWNER_CONTROL   TCM_BASE + 68 /* The key is under control of the TCM Owner and can
                                                 only be evicted by the TCM Owner.  */
#define TCM_BAD_COUNTER         TCM_BASE + 69 /* The counter handle is incorrect */
#define TCM_NOT_FULLWRITE       TCM_BASE + 70 /* The write is not a complete write of the area */
#define TCM_CONTEXT_GAP         TCM_BASE + 71 /* The gap between saved context counts is too large
                                               */
#define TCM_MAXNVWRITES         TCM_BASE + 72 /* The maximum number of NV writes without an owner
                                                 has been exceeded */
#define TCM_NOOPERATOR          TCM_BASE + 73 /* No operator authorization value is set */
#define TCM_RESOURCEMISSING     TCM_BASE + 74 /* The resource pointed to by context is not loaded
                                               */
/* remove Delegate code */
#if 0
#define TCM_DELEGATE_LOCK       TCM_BASE + 75 /* The delegate administration is locked */
#define TCM_DELEGATE_FAMILY     TCM_BASE + 76 /* Attempt to manage a family other then the delegated
                                                 family */
#define TCM_DELEGATE_ADMIN      TCM_BASE + 77 /* Delegation table management not enabled */
#endif

#define TCM_TRANSPORT_NOTEXCLUSIVE TCM_BASE + 78 /* There was a command executed outside of an
                                                 exclusive transport session */
#define TCM_OWNER_CONTROL       TCM_BASE + 79 /* Attempt to context save a owner evict controlled
                                                 key */
/* remove DAA code */
#if 0
#define TCM_DAA_RESOURCES       TCM_BASE + 80 /* The DAA command has no resources available to
                                                 execute the command */
#define TCM_DAA_INPUT_DATA0     TCM_BASE + 81 /* The consistency check on DAA parameter inputData0
                                                 has failed. */
#define TCM_DAA_INPUT_DATA1     TCM_BASE + 82 /* The consistency check on DAA parameter inputData1
                                                 has failed. */
#define TCM_DAA_ISSUER_SETTINGS TCM_BASE + 83 /* The consistency check on DAA_issuerSettings has
                                                 failed. */
#define TCM_DAA_TCM_SETTINGS    TCM_BASE + 84 /* The consistency check on DAA_tcmSpecific has
                                                 failed. */
#define TCM_DAA_STAGE           TCM_BASE + 85 /* The atomic process indicated by the submitted DAA
                                                 command is not the expected process. */
#define TCM_DAA_ISSUER_VALIDITY TCM_BASE + 86 /* The issuer's validity check has detected an
                                                 inconsistency */
#endif
#define TCM_DAA_WRONG_W         TCM_BASE + 87 /* The consistency check on w has failed. */
#define TCM_BAD_HANDLE          TCM_BASE + 88 /* The handle is incorrect */
#define TCM_BAD_DELEGATE        TCM_BASE + 89 /* Delegation is not correct */
#define TCM_BADCONTEXT          TCM_BASE + 90 /* The context blob is invalid */
#define TCM_TOOMANYCONTEXTS     TCM_BASE + 91 /* Too many contexts held by the TCM */

/* remove MA related code */
#if 0
#define TCM_MA_TICKET_SIGNATURE TCM_BASE + 92 /* Migration authority signature validation failure
                                               */
#define TCM_MA_DESTINATION      TCM_BASE + 93 /* Migration destination not authenticated */
#define TCM_MA_SOURCE           TCM_BASE + 94 /* Migration source incorrect */
#define TCM_MA_AUTHORITY        TCM_BASE + 95 /* Incorrect migration authority */
#endif

#define TCM_PERMANENTEK         TCM_BASE + 97 /* Attempt to revoke the EK and the EK is not revocable */
#define TCM_BAD_SIGNATURE       TCM_BASE + 98 /* Bad signature of CMK ticket */
#define TCM_NOCONTEXTSPACE      TCM_BASE + 99 /* There is no room in the context list for additional
                                                 contexts */
#define TCM_INVALID_USERID		 TCM_BASE + 100 /* UserID is invalid when executing the command */
#define TCM_USER_NO_PRIVILEGE	 TCM_BASE + 101 /* User has no privilege using the required resource*/
#define TCM_UNSUPPORT_ALG		TCM_BASE + 102 /* the algorithm is not supported yet */
#define TCM_BAD_EXPIRATIONTIME TCM_BASE + 103 /*the migrationAuth is expiration*/
#define TCM_BNADDONE_FAIL		TCM_BASE + 104 /*bignum add one fail*/
#define TCM_USER_NO_ACTIVE	 	TCM_BASE + 105 /* User has no active*/
#define TCM_BAD_AUTHLENGTH	 	TCM_BASE + 106
#define TCM_BAD_RANDOMSIZE		TCM_BASE + 107

#define TCM_BAD_MAX			TCM_BASE + 108

/* As error codes are added here, they should also be added to lib/miscfunc.c */

/* TCM-defined non-fatal errors */

#define TCM_RETRY               TCM_BASE + TCM_NON_FATAL /* The TCM is too busy to respond to the
                                                            command immediately, but the command
                                                            could be submitted at a later time */
#define TCM_NEEDS_SELFTEST      TCM_BASE + TCM_NON_FATAL + 1 /* TCM_ContinueSelfTest has has not
                                                                been run*/
#define TCM_DOING_SELFTEST      TCM_BASE + TCM_NON_FATAL + 2 /* The TCM is currently executing the
                                                                actions of TCM_ContinueSelfTest
                                                                because the ordinal required
                                                                resources that have not been
                                                                tested. */
#define TCM_DEFEND_LOCK_RUNNING TCM_BASE + TCM_NON_FATAL + 3
/* The TCM is defending against dictionary
   attacks and is in some time-out
   period. */


/* error code of missing privilege of resource, 96 kinds in total*/
#define TCM_PRI_BASE		(TCM_BAD_MAX)

#define TCM_PRI_SUCCESS 	TCM_PRI_BASE
#define TCM_PRI_NV			TCM_PRI_BASE + 1
#define TCM_PRI_SM2		TCM_PRI_BASE + 2
#define TCM_PRI_SM4		TCM_PRI_BASE + 3
#define TCM_PRI_PCR_0		TCM_PRI_BASE + 4
#define TCM_PRI_PCR_1		TCM_PRI_BASE + 5
#define TCM_PRI_PCR_2		TCM_PRI_BASE + 6
#define TCM_PRI_PCR_3		TCM_PRI_BASE + 7
#define TCM_PRI_PCR_4		TCM_PRI_BASE + 8
#define TCM_PRI_PCR_5		TCM_PRI_BASE + 9
#define TCM_PRI_PCR_6		TCM_PRI_BASE + 10
#define TCM_PRI_PCR_7		TCM_PRI_BASE + 11
#define TCM_PRI_PCR_8		TCM_PRI_BASE + 12
#define TCM_PRI_PCR_9		TCM_PRI_BASE + 13
#define TCM_PRI_PCR_10		TCM_PRI_BASE + 14
#define TCM_PRI_PCR_11		TCM_PRI_BASE + 15
#define TCM_PRI_PCR_12		TCM_PRI_BASE + 16
#define TCM_PRI_PCR_13		TCM_PRI_BASE + 17
#define TCM_PRI_PCR_14		TCM_PRI_BASE + 18
#define TCM_PRI_PCR_15		TCM_PRI_BASE + 19
#define TCM_PRI_PCR_16		TCM_PRI_BASE + 20
#define TCM_PRI_PCR_17		TCM_PRI_BASE + 21
#define TCM_PRI_PCR_18		TCM_PRI_BASE + 22
#define TCM_PRI_PCR_19		TCM_PRI_BASE + 23
#define TCM_PRI_PCR_20		TCM_PRI_BASE + 24
#define TCM_PRI_PCR_21		TCM_PRI_BASE + 25
#define TCM_PRI_PCR_22		TCM_PRI_BASE + 26
#define TCM_PRI_PCR_23		TCM_PRI_BASE + 27
#define TCM_PRI_PCR_24		TCM_PRI_BASE + 28
#define TCM_PRI_PCR_25		TCM_PRI_BASE + 29
#define TCM_PRI_PCR_26		TCM_PRI_BASE + 30
//#define TCM_PRI_COUNTER
//#define TCM_PRI_TICK
//#define TCM_PRI_RAND
//#define TCM_PRI_SM3


#define TCM_PRI_ERR_MAX    TCM_PRI_BASE + 97

/* location of resource in privilege table , the sequence must be same with the error code */
#define TCM_PRI_ERROR_LOCAL_GAP 1

#define TCM_LOCAL_NV		0
#define TCM_LOCAL_SM2		1
#define TCM_LOCAL_SM4		2
#define TCM_LOCAL_PCR_0	3
#define TCM_LOCAL_PCR_1	4
#define TCM_LOCAL_PCR_2	5
#define TCM_LOCAL_PCR_3	6
#define TCM_LOCAL_PCR_4	7
#define TCM_LOCAL_PCR_5	8
#define TCM_LOCAL_PCR_6	9
#define TCM_LOCAL_PCR_7	10
#define TCM_LOCAL_PCR_8	11
#define TCM_LOCAL_PCR_9	12
#define TCM_LOCAL_PCR_10	13
#define TCM_LOCAL_PCR_11	14
#define TCM_LOCAL_PCR_12	15
#define TCM_LOCAL_PCR_13	16
#define TCM_LOCAL_PCR_14	17
#define TCM_LOCAL_PCR_15	18
#define TCM_LOCAL_PCR_16	19
#define TCM_LOCAL_PCR_17	20
#define TCM_LOCAL_PCR_18	21
#define TCM_LOCAL_PCR_19	22
#define TCM_LOCAL_PCR_20	23
#define TCM_LOCAL_PCR_21	24
#define TCM_LOCAL_PCR_22	25
#define TCM_LOCAL_PCR_23	26
#define TCM_LOCAL_PCR_24	27
#define TCM_LOCAL_PCR_25	28
#define TCM_LOCAL_PCR_26	29


#define TCM_LOCAL_MAX      96  //MUST BE LESS THAN MAX!

//#define TCM_LOCAL_TICK
//#define TCM_LOCAL_RAND
//#define TCM_LOCAL_SM3
//#define TCM_LOCAL_COUNTER




#endif
