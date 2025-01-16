#ifndef __TPCM_COMMAND_H__
#define __TPCM_COMMAND_H__

#ifdef __KERNEL__
#include <linux/byteorder/generic.h>
#else
#include <arpa/inet.h>
#endif

#include "tcs_attest_def.h"

#define TPCM_ORD_BootMeasure					0x00001001
#define TPCM_ORD_InterceptMeasure				0x00001002
#define TPCM_ORD_CollectAndMeasure				0x00001003
#define TPCM_ORD_SetDMeasurePolicy				0x00001004
#define TPCM_ORD_UpdateReference				0x00001005
#define TPCM_ORD_UpdateReferenceIncrement		0x00001006
#define TPCM_ORD_GetTrustedCredential			0x00001007
#define TPCM_ORD_GetBootMeasureReference		0x00001008
#define TPCM_ORD_SetMeasureSwitch				0x00001009
#define TPCM_ORD_GetTPCMStatus					0x0000100A
#define TPCM_ORD_FirmwareUpgrade				0x0000100B
#ifdef __TPCM_MPP__
#define TPCM_ORD_UpdateMemProtectPolicy			0x0000100C
#define TPCM_ORD_SetMenProtectSwitch			0x0000100D
#endif
#define TPCM_ORD_GetTpcmLog						0x0000100E
#define TPCM_ORD_FlashRead						0x0000100F
#define TPCM_ORD_FlashWrite						0x00001010
#define TPCM_ORD_FlashErase						0x00001011
#define TPCM_ORD_SetSystemTime					0x00001012
#define TPCM_ORD_LicenseRequest					0x00001013
#define TPCM_ORD_ImportLicense					0x00001014
#define TPCM_ORD_GetAuthorizationStatus			0x00001015
#define TPCM_ORD_SimpleBootMeasure				0x00001016
#define TPCM_ORD_UpdateSignedReference			0x00001017
#define TPCM_ORD_UpdateSignedReferenceIncrement	0x00001018
#define TPCM_ORD_SaveMemData					0x00001019
#define TPCM_ORD_ReadMemData					0x0000101A
#define TPCM_ORD_SetPlatformPikPubkey			0x0000101B
#define TPCM_ORD_SetTpcmPik						0x0000101C
#define TPCM_ORD_GetTpcmPikPubkey				0x0000101D
#define TPCM_ORD_GetTpcmFeature					0x0000101E
#define TPCM_ORD_TpcmOffCommand					0x0000101F
#define TPCM_ORD_SetSignMeasureSwitch			0x00001020
#define TPCM_ORD_SetSignDMeasurePolicy			0x00001021
#define TPCM_ORD_GetMark						0x00001022
#define TPCM_ORD_PowerManage					0x00001023
#define TPCM_ORD_Reset							0x00001024

#define TPCM_ORD_Reset_TPCM					0x00001025
#define TPCM_ORD_GetTrustedStatus				0x00001026
#define TPCM_ORD_SetTpcmShellAuth				0x00001027
#define TPCM_ORD_SetTpcmParam					0x00001028
#define TPCM_ORD_GetVersion					0x00001029

#define TPCM_ORD_GetBootMeasureRecord			0x0000102A
#define TPCM_ORD_GetBootMeasureReferences		0x0000102B
#define TPCM_ORD_GetProgressReferenceSize		0x0000102C
#define TPCM_ORD_GetProgressReference			0x0000102D
#define TPCM_ORD_GetProcessReferenceValidCount	0x0000102E
#define TPCM_ORD_GetProcessReferenceTotalCount	0x0000102F
#define TPCM_ORD_GetProcessReferenceModifyLimit	0x00001030
#define TPCM_ORD_InterceptMeasureSimple			0x00001031
#define TPCM_ORD_GetDmeasurePolicy				0x00001032

#define TPCM_ORD_UpdateProcessIdentity			0x00001040
#define TPCM_ORD_GetProcessIds			    	0x00001041
#define TPCM_ORD_UpdateProcessRoles			    0x00001042
#define TPCM_ORD_GetProcessRoles			    0x00001043
#define TPCM_ORD_SetGlobalControlPolicy			0x00001044
#define TPCM_ORD_GetGlobalControlPolicy			0x00001045
#define TPCM_ORD_GetPolicyReport				0x00001046
#define TPCM_ORD_SetAdminCert					0x00001047
#define TPCM_ORD_GrantAdminRole					0x00001048
#define TPCM_ORD_RemoveAdminRole				0x00001049
#define TPCM_ORD_GetAdminList					0x0000104A
#define TPCM_ORD_SetAdminAuthPolicies			0x0000104B
#define TPCM_ORD_GetAdminAuthPolicies			0x0000104C
#define TPCM_ORD_GetTrustedEvidence				0x0000104D
#define TPCM_ORD_UpdateDmeasureProcessPolicy    0x0000104E
#define TPCM_ORD_GetDmeasureProcessPolicy       0x0000104F
#define TPCM_ORD_ReferenceMatchHash     		0x00001050
#define TPCM_ORD_ReferenceMatchPathHash    		0x00001051
#define TPCM_ORD_ExternBootMeasure				0x00001052
#define TPCM_ORD_ExternSimpleBootMeasure		0x00001053
#define TPCM_ORD_UpdatePtraceProtectsPolicy		0x00001054
#define TPCM_ORD_GetPtraceProtectsPolicy		0x00001055
#define TPCM_ORD_GetReplayCounter				0x00001056
#define TPCM_ORD_GetBackupDataSize				0x00001057
#define TPCM_ORD_Backup							0x00001058
#define TPCM_ORD_Restore						0x00001059
#define TPCM_ORD_GetLicenseInfo					0x0000105A
#define TPCM_ORD_UpdateTncPolicy				0x0000105B
#define TPCM_ORD_GetTncPolicy					0x0000105C
#define TPCM_ORD_GetPoliciesVersion				0x0000105D
#define TPCM_ORD_SyncTrustedStatus				0x0000105E
#define TPCM_ORD_UpdateCriticalFileIntergrity			0x0000105F
#define TPCM_ORD_GetCriticalFileIntergrityDigest		0x00001060
#define TPCM_ORD_UpdateFileintergrityDigest				0x00001063
#define TPCM_ORD_GetFileintergrityDigest				0x00001064
#define TPCM_ORD_UpdateCriticalFileintergrityDigest		0x00001065
#define TPCM_ORD_UpdateFileProtectPolicy				0x00001066
#define TPCM_ORD_GetLinkedSwitchStatus					0x00001070
#define TPCM_ORD_ClearLinkedSwitchStatus				0x00001071
#define TPCM_ORD_UpdateKernelSectionStatus				0x00001067
#define TPCM_ORD_SELFTEST								0x00001068
#define TPCM_ORD_GetLicenseEntity						0x00001072
#define TPCM_ORD_GetTddStatus							0x00003001
#define TPCM_ORD_SetSwitch 								0x00001073
#define TPCM_ORD_GetSwitch 								0x00001074

#define TPCM_ORD_CollectAndMeasureOpera				0x00001076

/************************************************************/
#define TPCM_ORD_SM3							0x00001034
#define TPCM_ORD_SM4Encrypt						0x00001035
#define TPCM_ORD_SM4Decrypt						0x00001036
#define TPCM_ORD_SM2SignE						0x00001037
#define TPCM_ORD_SM2VerifyE						0x00001038
#define TPCM_ORD_SM2Sign						0x00001039
#define TPCM_ORD_SM2Verify						0x0000103A
#define TPCM_ORD_SM3_INIT						0x0000103B
#define TPCM_ORD_SM3_UPDATE						0x0000103C
#define TPCM_ORD_SM3_FINISH						0x0000103D
#define TPCM_ORD_SM3_VERIFY						0x0000103E
#define TPCM_ORD_SM2VerifyB						0x0000103F
/************************************************************/

#define TSS_ORD_MASK							0x80000000
#define TSS_ORD_GetTrustedStatus				0x80000001
#define TSS_ORD_InformPolicy					0x80000002
#define TSS_ORD_GetDmeasureTrustedStatus		0x80000003
#define TSS_ORD_GetInterecpetTrustedStatus		0x80000004

#define TPCM_ORD_SetRootCert					0x00001203
#define TPCM_ORD_UpdateRootCert					0x00001204
#define TPCM_ORD_QueryRootCert					0x00001205
#define TPCM_ORD_UpdateRoleCert					0x00001206
#define TPCM_ORD_DeleteRoleCert					0x00001207
#define TPCM_ORD_GenerateKey 					0x00001201
#define TPCM_ORD_GetPubKey 						0x00001202
#define TPCM_ORD_GetEKPubKey 					0x0000120B
#define TPCM_ORD_ImportEK 						0x00001208
#define TPCM_ORD_VerifyEK 						0x00001209
#define TPCM_ORD_GetEK    						0x0000120A
#define TPCM_ORD_UpdateRootCert_VIR				0x0000120C
#define TPCM_ORD_HashSign						0x0000120D

#define TPCM_TAG_REQ_COMMAND	0x000000C1 	/** A command with no authentication.  */
#define TPCM_TAG_RSP_COMMAND	0x000000C4 	/** A response from a command with no authentication */

#define COMMAND_HEADER\
	uint32_t uiCmdTag;\
	uint32_t uiCmdLength;\
	uint32_t uiCmdCode

#define RESPONSE_HEADER\
	uint32_t uiRspTag;\
	uint32_t uiRspLength;\
	uint32_t uiRspRet

#pragma pack(push, 1)

typedef struct{
	COMMAND_HEADER;
}tpcm_req_header_st;

typedef struct{
	RESPONSE_HEADER;
}tpcm_rsp_header_st;

typedef struct {
	COMMAND_HEADER;
}get_tdd_info_req;

typedef struct {
	RESPONSE_HEADER;
	struct tdd_info info;
}get_tdd_info_rsp;

#pragma pack(pop)

#define tpcmLocalReqCmd(req)(((tpcm_req_header_st*)req)->uiCmdCode)
#define tpcmLocalRspCmd(rsp)(((tpcm_rsp_header_st*)rsp)->uiRspRet)
#define tpcmReqTag(req)		(htonl(((tpcm_req_header_st*)req)->uiCmdTag))
#define tpcmReqLength(req)	(htonl(((tpcm_req_header_st*)req)->uiCmdLength))
#define tpcmReqCmd(req)		(htonl(((tpcm_req_header_st*)req)->uiCmdCode))
#define tpcmRspTag(rsp)		(ntohl(((tpcm_rsp_header_st*)rsp)->uiRspTag))
#define tpcmRspLength(rsp)	(ntohl(((tpcm_rsp_header_st*)rsp)->uiRspLength))
#define tpcmRspRetCode(rsp)	(ntohl(((tpcm_rsp_header_st*)rsp)->uiRspRet))
#define tpcmRspExecRet(rsp)	(tpcmRspRetCode(rsp) & 0xFFFF)
#define tpcmRspCtrl(rsp)	((tpcmRspRetCode(rsp) >> 16) & 0xFFFF)

#define TCS_POLICY_ADMIN_CERT_PATH 						HTTC_TSS_CONFIG_PATH"admin_cert.data"
#define TCS_POLICY_ADMIN_AUTH_PATH						HTTC_TSS_CONFIG_PATH"admin_auth.data"
#define TCS_POLICY_DMEASURE_PATH 						HTTC_TSS_CONFIG_PATH"dmeasure.data"
#define TCS_POLICY_DMEASURE_PROCESS_PATH 				HTTC_TSS_CONFIG_PATH"dmeasure_process.data"
//#define TCS_POLICY_FILE_INTEGRITY_PATH 				HTTC_TSS_CONFIG_PATH"file_integrity.data"
#define TCS_POLICY_CRITICAL_FILE_INTEGRITY_PATH			HTTC_TSS_CONFIG_PATH"critical_file_integrity.data"
#define TCS_POLICY_FILE_PROTECT_PATH 					HTTC_TSS_CONFIG_PATH"file_protect.data"
#define TCS_POLICY_GLOBAL_CONTROL_PATH 					HTTC_TSS_CONFIG_PATH"global_control.data"
#define TCS_POLICY_PROCESS_IDS_PATH 					HTTC_TSS_CONFIG_PATH"process_ids.data"
#define TCS_POLICY_PROCESS_ROLES_PATH 					HTTC_TSS_CONFIG_PATH"process_roles.data"
#define TCS_POLICY_PTRACE_PROTECT_PATH 					HTTC_TSS_CONFIG_PATH"ptrace_protect.data"
#define TCS_POLICY_TNC_PATH 							HTTC_TSS_CONFIG_PATH"tnc.data"
#define TCS_POLICY_REPLAY_PATH 							HTTC_TSS_CONFIG_PATH"replay.data"
#define TCS_POLICY_LOCAL_REPLAY_PATH 					HTTC_TSS_CONFIG_PATH"local_replay.data"
#define TCS_POLICY_FILE_INTEGRITY_HASH_PATH 			HTTC_TSS_CONFIG_PATH"file_integrity_hash.data"
#define TCS_POLICY_CRITICAL_FILE_INTEGRITY_HASH_PATH	HTTC_TSS_CONFIG_PATH"critical_file_integrity_hash.data"
#define TCS_POLICY_TPCMID_PATH 							HTTC_TSS_CONFIG_PATH"tpcmid.data"
#define TCS_PASSWA_PATH									HTTC_TSS_CONFIG_PATH"passwd.data"
#define TCS_PIK_PATH         							HTTC_TSS_CONFIG_PATH"pik.data"
#define TCS_POLICY_VERSION_PATH         				HTTC_TSS_CONFIG_PATH"policy_version.data"

#endif	/** __TPCM_COMMAND_H__*/

