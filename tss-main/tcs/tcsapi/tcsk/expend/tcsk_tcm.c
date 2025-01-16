#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "memdebug.h"
#include "debug.h"
#include "kutils.h"
#include "tcs_config.h"
#include "tcs_error.h"
#include "tdd.h"
#include "tddl.h"
#include "smk/sm3.h"
#include "tcs_constant.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_tcm");


#define TCM_U8_SIZE            1
#define TCM_U16_SIZE           2
#define TCM_U32_SIZE           4

#define TCM_PARAMSIZE_OFFSET           TCM_U16_SIZE
#define TCM_RETURN_OFFSET              ( TCM_PARAMSIZE_OFFSET + TCM_U32_SIZE )
#define TCM_DATA_OFFSET                ( TCM_RETURN_OFFSET + TCM_U32_SIZE )

#define TCM_TAG_REQ_COMMAND	0x00C1 	/** A command with no authentication.  */
#define TCM_TAG_RSP_COMMAND	0x00C4 	/** A response from a command with no authentication */

#define TCM_ORD_Init 			0x00008097
#define TCM_ORD_Startup			0x00008099
#define TCM_ORD_NV_DefineSpace	0x000080CC
#define TCM_ORD_NV_ReadValue	0x000080CF
#define TCM_ORD_NV_WriteValue	0x000080CD
#define TCM_ORD_GetCapability	0x00008065

#define TCM_NV_PER_OWNERREAD  		0x00020000 	/** 17: The value requires TPCM Owner authorization to read. */

#define TCM_TAG_NV_ATTRIBUTES           0x0017 /*  TCM_NV_ATTRIBUTES */
#define TCM_TAG_NV_DATA_PUBLIC          0x0018 /*  TCM_NV_DATA_PUBLIC */

#define TCM_CAP_NV_INDEX        0x00000011 /* A TCM_NV_DATA_PUBLIC structure that indicates the
                                              values for the TCM_NV_INDEX.  Returns TCM_BADINDEX if
                                              the index is not in the TCM_CAP_NV_LIST list. */

#define TCM_LOC_FOUR    0x10    /* Locality 4 */
#define TCM_LOC_THREE   0x08    /* Locality 3  */
#define TCM_LOC_TWO     0x04    /* Locality 2  */
#define TCM_LOC_ONE     0x02    /* Locality 1  */
#define TCM_LOC_ZERO    0x01    /* Locality 0. This is the same as the legacy interface.  */

#define TCM_LOC_ALL     0x1f    /* kgold - added all localities */
#define TCM_LOC_MAX     4       /* kgold - maximum value for TCM_MODIFIER_INDICATOR */

#define TCM_NUM_PCR 	27
#define CHAR_BIT 		8
#define __pcr_sizeof_select__ (TCM_NUM_PCR / CHAR_BIT + 1)

#define TCM_RSP_HEADER_LEN 10
#define TCM_COMMNAD_HEADER	\
	uint16_t cmd_type;\
	uint32_t total_length;\
	uint32_t ordinal_no;
#define TCM_RESPONSE_HEADER	\
	uint16_t tag; \
	uint32_t returnSize;\
	uint32_t returnCode;
extern volatile uint32_t recv_mdelay;

static unsigned int indexconf = NV_READ_INDEX_BLOCK; 

#pragma pack(push, 1)

typedef struct{
	TCM_COMMNAD_HEADER;
}tcm_req_header_st;

typedef struct{
	TCM_RESPONSE_HEADER;
}tcm_rsp_header_st;

typedef struct {
	TCM_COMMNAD_HEADER;
	uint16_t mode;
}tcm_startup_st;

struct tpcm_pcr_info_short 
{ 
	/** The size in bytes of the pcrSelect structure */
    uint16_t sizeOfSelect;			
    
    /** This SHALL be a bit map that indicates if a PCR is active or not */
    uint8_t  pcrSelect[TCM_NUM_PCR/CHAR_BIT + 1];   
    
    /** This SHALL be the locality modifier required to release the information.  This value must not be zero. */
    uint8_t  localityAtRelease;  
    
    /** This SHALL be the digest of the PCR indices and PCR values to verify when revealing auth data */
    uint8_t  digestAtRelease[DEFAULT_HASH_SIZE];         
}; 
struct tcm_nv_attributes
{ 
    uint16_t tag;      		/** TCM_TAG_NV_ATTRIBUTES */
    uint32_t attributes;	/** The attribute area */
};
struct tcm_nv_data_public
{ 
    uint16_t tag;           /** This SHALL be TCM_TAG_NV_DATA_PUBLIC */
    uint32_t nvIndex;       /** The index of the data area */
    struct tpcm_pcr_info_short pcrInfoRead;	/** The PCR selection that allows reading of the area */
    struct tpcm_pcr_info_short pcrInfoWrite;/** The PCR selection that allows writing of the area */
    struct tcm_nv_attributes permission;	/** The permissions for manipulating the area */
    uint8_t  readSTClear;   /** Set to FALSE on each TCM_Startup(ST_Clear) and set to TRUE after a ReadValuexxx with datasize of 0 */
    uint8_t  writeSTClear;  /** Set to FALSE on each TCM_Startup(ST_CLEAR) and set to TRUE after a WriteValuexxx with a datasize of 0. */
    uint8_t  writeDefine;   /** Set to FALSE after TCM_NV_DefineSpace and set to TRUE after a successful WriteValuexxx with a datasize of 0 */
    uint32_t dataSize;		/** The size of the data area in bytes */
};
 
struct nv_definespace_noauth
{
	TCM_COMMNAD_HEADER;
	struct tcm_nv_data_public pubInfo;
	uint8_t areaEnc[DEFAULT_HASH_SIZE];
}; 

struct nv_data_param
{
	uint32_t index;
	uint32_t offset;
	uint32_t dataLen;
	uint8_t  data[0];
};

struct nv_readvalue_command_noauth
{
	TCM_COMMNAD_HEADER;
	uint32_t index;
	uint32_t offset;
	uint32_t dataLen;
};

typedef struct
{
	uint16_t sizeOfSelect;
	uint8_t	 pcrSelect[__pcr_sizeof_select__];
	uint32_t sizeOfPcrData;
	uint8_t  pcrData[DEFAULT_HASH_SIZE];
}pcr_composite_st;

typedef struct
{ 
	/** The index of NV area */
    uint32_t nvIndex;       							
	/** a bit map that indicates if a PCR for reading NV RAM is active or not */  
    uint8_t  readPcrSelect[TCM_NUM_PCR/CHAR_BIT+1]; 	
	/** the locality modifier required to release the information for reading NV RAM */
    uint8_t  readDigestAtRelease[DEFAULT_HASH_SIZE];	
	/** a bit map that indicates if a PCR for reading NV RAM is active or not */
    uint8_t  writePcrSelect[TCM_NUM_PCR/CHAR_BIT+1]; 
	/** the locality modifier required to release the information for reading NV RAM */
    uint8_t  writeDigestAtRelease[DEFAULT_HASH_SIZE]; 
	/** The permissions attribute for manipulating the area */
	uint32_t perAttr;
	/** The data size of NV area in bytes */
    uint32_t dataSize;
}nvspace_param_st; 

struct capability{
	TCM_COMMNAD_HEADER;
	uint32_t cap;
	uint32_t sublength;
	char subcap[0];
};

#pragma pack(pop)


static uint32_t tcmRspRetCode (void *rsp){
	uint32_t rc_n = 0;
	tpcm_memcpy (&rc_n, &((tcm_rsp_header_st *)rsp)->returnCode, sizeof (rc_n));
	return ntohl (rc_n);
}


/** Init NV public information */
static void init_pubInfo (struct tcm_nv_data_public *pubInfo, nvspace_param_st *spaceParam)
{
	tpcm_memcpy_u16 (&pubInfo->tag, htons (TCM_TAG_NV_DATA_PUBLIC));
	tpcm_memcpy_u32 (&pubInfo->nvIndex, htonl (spaceParam->nvIndex));
	tpcm_memcpy_u16 (&pubInfo->pcrInfoRead.sizeOfSelect, htons (sizeof (spaceParam->readPcrSelect)));
	tpcm_memcpy (pubInfo->pcrInfoRead.pcrSelect, spaceParam->readPcrSelect, sizeof (spaceParam->readPcrSelect));
	pubInfo->pcrInfoRead.localityAtRelease = TCM_LOC_ZERO;
	tpcm_memcpy (pubInfo->pcrInfoRead.digestAtRelease, spaceParam->readDigestAtRelease, DEFAULT_HASH_SIZE);
	tpcm_memcpy_u16 (&pubInfo->pcrInfoWrite.sizeOfSelect, htons (sizeof (spaceParam->writePcrSelect)));
	tpcm_memcpy (pubInfo->pcrInfoWrite.pcrSelect, spaceParam->writePcrSelect, sizeof (spaceParam->writePcrSelect));
	pubInfo->pcrInfoWrite.localityAtRelease = TCM_LOC_ZERO;
	tpcm_memcpy (pubInfo->pcrInfoWrite.digestAtRelease, spaceParam->writeDigestAtRelease, DEFAULT_HASH_SIZE);
	tpcm_memcpy_u16 (&pubInfo->permission.tag, htons (TCM_TAG_NV_ATTRIBUTES));
	tpcm_memcpy_u32 (&pubInfo->permission.attributes, htonl (spaceParam->perAttr));
	pubInfo->readSTClear = 0;
	pubInfo->writeSTClear = 0;
	pubInfo->writeDefine = 0;
	tpcm_memcpy_u32 (&pubInfo->dataSize, htonl (spaceParam->dataSize));
}

/** Define an area in NV RAM space with noauth */
static int do_tcm_cmd_nv_definespace_noauth (nvspace_param_st *spaceParam)	/** [IN] the NV data public information */
{
	int ret = 0;
	uint8_t *buffer = NULL;
	uint8_t *obuffer = NULL;
	uint32_t oLen = PAGE_SIZE / 2;
	uint8_t areaEnc[DEFAULT_HASH_SIZE] = {0};
	struct nv_definespace_noauth *pCmd = NULL;

	if (NULL == spaceParam)	return TSS_ERR_PARAMETER;
	if (NULL == (buffer = tdd_alloc_data_buffer (PAGE_SIZE)))		return TSS_ERR_NOMEM;

	pCmd = (struct nv_definespace_noauth *) buffer;
	tpcm_memcpy_u32 (&pCmd->total_length, htonl (sizeof (*pCmd)));
	tpcm_memcpy_u16 (&pCmd->cmd_type, htons (TCM_TAG_REQ_COMMAND));
	tpcm_memcpy_u32 (&pCmd->ordinal_no, htonl (TCM_ORD_NV_DefineSpace));
	init_pubInfo (&pCmd->pubInfo, spaceParam);
	tpcm_memcpy (pCmd->areaEnc, areaEnc, DEFAULT_HASH_SIZE);

	obuffer = buffer + PAGE_SIZE / 2;
	if (0 != (ret = tcm_tddl_transmit_cmd ((void *)buffer, (int)(sizeof (*pCmd)), (void *)obuffer, (int *)(&oLen)))) goto out;
	ret = tcmRspRetCode (obuffer);

out:
	if (buffer) tdd_free_data_buffer (buffer);
	return ret;
}

/** Write a value into NV RAM space  with no auth */
static int do_tcm_cmd_nv_writevalue_noauth (
						uint32_t index,		/** [IN] the index of NV area */
						uint32_t offset,	/** [IN] the offset of data in NV area */
						uint8_t *data,		/** [IN] the data being inserted into NV area */
						uint32_t dataLen)	/** [IN] the length of data being inserted into NV area */
{
	int ret = 0;
	uint8_t *buffer = NULL;
	uint8_t *obuffer = NULL;
	uint32_t oLen = PAGE_SIZE / 2;
	uint32_t iLen = 0;
	tcm_req_header_st *pCmdHeader = NULL;
	struct nv_data_param  *pNvData = NULL;

	if (NULL == data)	return TSS_ERR_PARAMETER;
	if (NULL == (buffer = tdd_alloc_data_buffer (PAGE_SIZE)))		return TSS_ERR_NOMEM;

	iLen = sizeof (*pCmdHeader) + sizeof (*pNvData) + dataLen;

	pCmdHeader = (tcm_req_header_st *)buffer;
	tpcm_memcpy_u32 (&pCmdHeader->total_length, htonl (iLen));
	tpcm_memcpy_u16 (&pCmdHeader->cmd_type, htons (TCM_TAG_REQ_COMMAND));
	tpcm_memcpy_u32 (&pCmdHeader->ordinal_no, htonl (TCM_ORD_NV_WriteValue));

	pNvData = (struct nv_data_param  *)(buffer + sizeof (*pCmdHeader));
	tpcm_memcpy_u32 (&pNvData->index, htonl (index));
	tpcm_memcpy_u32 (&pNvData->offset, htonl (offset));
	tpcm_memcpy_u32 (&pNvData->dataLen, htonl (dataLen));
	tpcm_memcpy (pNvData->data, data, dataLen);

	obuffer = buffer + PAGE_SIZE / 2;

	if (0 != (ret = tcm_tddl_transmit_cmd ((void *)buffer, iLen, (void *)obuffer, (int *)(&oLen)))) goto out;
	ret = tcmRspRetCode (obuffer);

out:
	if (buffer) tdd_free_data_buffer (buffer);
	return ret;
}

/** Read  value from NV RAM space with no auth */
static int do_tcm_cmd_nv_readvalue_noauth (
						uint32_t  index,	/** [IN] the index of NV area */
						uint32_t  offset,	/** [IN] the offset of data in NV area */
						uint8_t  *data,		/** [OUT] the data being inserted into NV area */
						uint32_t *dataLen)	/** [INOUT] the length of data being inserted into NV area */
{
	int ret = 0;
	uint8_t *buffer = NULL;
	uint8_t *obuffer = NULL;
	uint32_t oLen = PAGE_SIZE / 2;
	uint32_t readLen = 0;
	struct nv_readvalue_command_noauth *pCmd = NULL;

	if ((NULL == data) || (NULL == dataLen))	return TSS_ERR_PARAMETER;
	if (NULL == (buffer = tdd_alloc_data_buffer (PAGE_SIZE)))		return TSS_ERR_NOMEM;

	pCmd = (struct nv_readvalue_command_noauth *)buffer;
	tpcm_memcpy_u32 (&pCmd->total_length, htonl (sizeof (*pCmd)));
	tpcm_memcpy_u16 (&pCmd->cmd_type, htons (TCM_TAG_REQ_COMMAND));
	tpcm_memcpy_u32 (&pCmd->ordinal_no, htonl (TCM_ORD_NV_ReadValue));
	tpcm_memcpy_u32 (&pCmd->index, htonl (index));
	tpcm_memcpy_u32 (&pCmd->offset, htonl (offset));
	tpcm_memcpy_u32 (&pCmd->dataLen, htonl (*dataLen));

	obuffer = buffer + PAGE_SIZE / 2;
	if (0 != (ret = tcm_tddl_transmit_cmd (
				buffer, sizeof (*pCmd), obuffer, (int *)(&oLen))))	goto out;
	if (0 != (ret = tcmRspRetCode (obuffer))) goto out;
	
	tpcm_memcpy_u32 (&readLen, htonl (*((uint32_t *)(obuffer + TCM_DATA_OFFSET))));
	if (*dataLen < readLen){
		httc_util_pr_error ("No enough space (%u < %u)\n", *dataLen, readLen);
		return TSS_ERR_OUTPUT_EXCEED;
	}
	/** Insert data && dataLen */
	*dataLen = readLen;
	tpcm_memcpy (data, obuffer + TCM_DATA_OFFSET + TCM_U32_SIZE, *dataLen);
	
out:
	if (buffer) tdd_free_data_buffer (buffer);
	return ret;
}

int tcm_cmd_nv_definespace_noauth ( 
						uint32_t nvIndex, uint32_t nvSize, 
						uint32_t pcrReadIndex, uint8_t *pcrReadDigest, 
						uint32_t pcrWriteIndex, uint8_t *pcrWriteDigest)
{
	nvspace_param_st spaceParam;
	pcr_composite_st pcrReadComposite;
	pcr_composite_st pcrWriteComposite;
	
	memset (&spaceParam, 0, sizeof (spaceParam));
	memset (&pcrReadComposite, 0, sizeof (pcrReadComposite));
	memset (&pcrWriteComposite, 0, sizeof (pcrWriteComposite));

	if (pcrReadDigest)
	{
		pcrReadComposite.sizeOfSelect = htons (__pcr_sizeof_select__);
		pcrReadComposite.pcrSelect [pcrReadIndex >> 3] |= (1 << (pcrReadIndex & 0x7));
		pcrReadComposite.sizeOfPcrData = htonl (DEFAULT_HASH_SIZE);
		httc_util_str2array ((uint8_t *)(pcrReadComposite.pcrData), (uint8_t *)pcrReadDigest, strlen((const char *)pcrReadDigest));
		spaceParam.readPcrSelect[pcrReadIndex >> 3] |= (1 << (pcrReadIndex & 0x7));
		httc_sm3 ((const unsigned char *)&pcrReadComposite, (int)sizeof (pcrReadComposite), (unsigned char *)(spaceParam.readDigestAtRelease));
	}
	if (pcrWriteDigest)
	{
		pcrWriteComposite.sizeOfSelect = htons (__pcr_sizeof_select__);
		pcrWriteComposite.pcrSelect [pcrWriteIndex >> 3] |= (1 << (pcrWriteIndex & 0x7));
		pcrWriteComposite.sizeOfPcrData = htonl (DEFAULT_HASH_SIZE);
		httc_util_str2array ((uint8_t *)(pcrWriteComposite.pcrData),(uint8_t *)pcrWriteDigest,strlen((const char *)pcrWriteDigest));
		spaceParam.writePcrSelect[pcrWriteIndex >> 3] |= (1 << (pcrWriteIndex & 0x7));
		httc_sm3 ((const unsigned char *)&pcrWriteComposite, (int)sizeof (pcrWriteComposite), (unsigned char *)(spaceParam.writeDigestAtRelease));
	}

	spaceParam.nvIndex = nvIndex;
	spaceParam.perAttr = TCM_NV_PER_OWNERREAD;
    spaceParam.dataSize = nvSize;
	
	return do_tcm_cmd_nv_definespace_noauth (&spaceParam);
}

int tcsk_nv_definespace (uint32_t index, int len)
{
	int rc;
	if ((rc = tcm_cmd_nv_definespace_noauth (index, len, 0, NULL, 0, NULL))){
		httc_util_pr_error ("Nv define hter(rc: %d, index: %d, size: %d)\n", rc, index, len);
		return rc;
	}
	return 0;
}
EXPORT_SYMBOL (tcsk_nv_definespace);

int tcsk_nv_write (uint32_t index, uint8_t *data, int len)
{	
	int rc;

	if ((rc = do_tcm_cmd_nv_writevalue_noauth (index, 0, data, len))){
		httc_util_pr_error ("Nv write hter(rc: %d, index: %d, size: %d)\n", rc, index, len);
		return rc;
	}
	return 0;
}
EXPORT_SYMBOL (tcsk_nv_write);
#if 1
static int do_tcm_cmd_get_capability (uint32_t cap, char *subcap,
								uint32_t sublen, char *rbuffer, int *prlen)
{
	int ret = 0;
	struct capability *cmdp;
	char *buffer;
	int olen = PAGE_SIZE;
	uint32_t rlen;

	if ((subcap == NULL) || (rbuffer == NULL) || (rbuffer == NULL))
		return TSS_ERR_PARAMETER;
	
	if(sizeof(*cmdp) + sublen > PAGE_SIZE){
		httc_util_pr_error ("call  TCM_GetCapability param hter length = %u\n",sublen);
		return TSS_ERR_INPUT_EXCEED;
	}
	if(NULL == (buffer = tdd_alloc_data_buffer(PAGE_SIZE)))return TSS_ERR_NOMEM;

	cmdp = (struct capability *)buffer;
	tpcm_memcpy_u16 (&cmdp->cmd_type, htons(TCM_TAG_REQ_COMMAND));
	tpcm_memcpy_u32 (&cmdp->ordinal_no, htonl(TCM_ORD_GetCapability));
	tpcm_memcpy_u32 (&cmdp->total_length, htonl((uint32_t)( sizeof(*cmdp) + sublen)));
	tpcm_memcpy_u32 (&cmdp->cap, htonl(cap));
	tpcm_memcpy_u32 (&cmdp->sublength, htonl(sublen));
	if(sublen > 0) tpcm_memcpy(cmdp->subcap, subcap, sublen);
	
	if((ret = tcm_tddl_transmit_cmd((char *)cmdp,
			(int)sizeof(*cmdp) + sublen, (char *)buffer, &olen))) goto out;
	if ((ret = tcmRspRetCode (buffer))) goto out;

	tpcm_memcpy_u32 (&rlen, htonl (*((uint32_t *)(buffer + TCM_DATA_OFFSET))));

	if(rlen + TCM_DATA_OFFSET + TCM_U32_SIZE > (uint32_t)olen){
		httc_util_pr_error ("hter: response length too long (%u > %u)\n",
				rlen + TCM_DATA_OFFSET + TCM_U32_SIZE, (uint32_t)olen);
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	if (*prlen < rlen){
		httc_util_pr_error ("No enough space (%u < %u)\n", *prlen, rlen);
		return TSS_ERR_OUTPUT_EXCEED;
	}
	
	*prlen = rlen;
	tpcm_memcpy(rbuffer,buffer + TCM_DATA_OFFSET + TCM_U32_SIZE, rlen);

out:
	tdd_free_data_buffer(buffer);
	return ret;
}

int tcm_cmd_nv_is_definespace_noauth (uint32_t nvIndex, uint32_t nvSize)
{
	int rc;	
	uint32_t cap = TCM_CAP_NV_INDEX;
	uint32_t subcap = htonl (nvIndex);
	struct tcm_nv_data_public n_nv_data;
	int r_cap_len = sizeof (n_nv_data);

	if ((rc = do_tcm_cmd_get_capability (cap, (char *)&subcap, sizeof (subcap), (char *)&n_nv_data, &r_cap_len))){
		httc_util_pr_error ("Get capability hter(rc: %d, cap: %u)\n", rc, cap);
		return rc;
	}
#ifdef NOTIFY_DEBUG	
    httc_util_dump_hex ("NV data", &n_nv_data, r_cap_len);
	printk("rc:%d\r\n",rc);
#endif
	return rc;
	
	//return do_tcm_cmd_nv_is_definespace_noauth (&spaceParam);
}
int tcsk_nv_is_definespace(uint32_t index, int len)
{
	int rc;
	if ((rc = tcm_cmd_nv_is_definespace_noauth (index, len))){
		httc_util_pr_error ("Nv define hter(rc: %d, index: %d, size: %d)\n", rc, index, len);
		return rc;
	}
	return 0;
}
EXPORT_SYMBOL (tcsk_nv_is_definespace);
#endif


int tcsk_nv_read (uint32_t index,	uint8_t *data, int *len_inout)
{
	int rc;

	if ((rc = do_tcm_cmd_nv_readvalue_noauth (index, 0, data, (uint32_t *)len_inout))){
		if(indexconf != index){
			httc_util_pr_error ("Nv read hter(rc: %d, index: %u, size: %u)\n", rc, index, *len_inout);
		}
		return rc;
	}	
	return 0;
}
EXPORT_SYMBOL (tcsk_nv_read);
module_param(indexconf, uint, S_IRUGO | S_IWUSR);

