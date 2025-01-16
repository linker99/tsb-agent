#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <fcntl.h>


#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "tcs_error.h"
#include "tpcm_command.h"

#pragma pack(push, 1)
struct tddl_buffer
{
  int cmd_len;
  int rsp_len;
  int rsp_maxlen;
  uint32_t res;
  unsigned char buffer[0];
};
#pragma pack(pop)

#define MAGIC 'T'

#define IOCTL_TYPE_TCM		1
#define IOCTL_TYPE_TPCM		2

#define IOCTL_PROC_TRANSMIT		1
#define IOCTL_PROC_SPEC			2

#define ioctlCmd(type,proc)	_IOWR(MAGIC, ((type)|(proc<<2)), unsigned int)
#define ioctlType(cmd)	(cmd&0x03)
#define ioctlProc(cmd)	((cmd>>2)&0x03)

static int is_spec_proc_cmd (char *cmd)
{
#ifndef V3301
	return ((tpcmLocalReqCmd (cmd) & TSS_ORD_MASK)
				|| (tpcmLocalReqCmd (cmd) == TPCM_ORD_FirmwareUpgrade)
				|| (tpcmLocalReqCmd (cmd) == TPCM_ORD_InterceptMeasure)
				|| (tpcmLocalReqCmd (cmd) == TPCM_ORD_SM3)
				|| (tpcmLocalReqCmd (cmd) == TPCM_ORD_SM3_UPDATE)
				|| (tpcmLocalReqCmd (cmd) == TPCM_ORD_SM3_FINISH)
				|| (tpcmLocalReqCmd (cmd) == TPCM_ORD_SM4Encrypt)
				|| (tpcmLocalReqCmd (cmd) == TPCM_ORD_SM4Decrypt)
				|| (tpcmLocalReqCmd (cmd) == TPCM_ORD_GetProgressReference)
				|| (tpcmLocalReqCmd (cmd) == TPCM_ORD_GetTrustedCredential)
				|| (tpcmLocalReqCmd (cmd) == TPCM_ORD_SM2SignE)   
				|| (tpcmLocalReqCmd (cmd) == TPCM_ORD_SM2VerifyE)
				|| (tpcmLocalReqCmd (cmd) == TSS_ORD_InformPolicy)
				|| (tpcmReqCmd (cmd) == TPCM_ORD_UpdateSignedReferenceIncrement)
				|| (tpcmReqCmd (cmd) == TPCM_ORD_GetTrustedStatus)
				|| (tpcmReqCmd (cmd) == TPCM_ORD_SetSignDMeasurePolicy)
				|| (tpcmReqCmd (cmd) == TPCM_ORD_UpdateDmeasureProcessPolicy)
				|| (tpcmReqCmd (cmd) == TPCM_ORD_UpdateProcessIdentity)
				|| (tpcmReqCmd (cmd) == TPCM_ORD_UpdateProcessRoles)
				|| (tpcmReqCmd (cmd) == TPCM_ORD_SetGlobalControlPolicy)
				|| (tpcmReqCmd (cmd) == TPCM_ORD_SetAdminAuthPolicies)
				|| (tpcmReqCmd (cmd) == TPCM_ORD_SetSignDMeasurePolicy)
				|| (tpcmReqCmd (cmd) == TPCM_ORD_SetSignMeasureSwitch)
				|| (tpcmReqCmd (cmd) == TPCM_ORD_UpdatePtraceProtectsPolicy)
				|| (tpcmReqCmd (cmd) == TPCM_ORD_UpdateTncPolicy)
				|| (tpcmReqCmd (cmd) == TPCM_ORD_Reset)
				|| (tpcmReqCmd (cmd) == TPCM_ORD_SyncTrustedStatus)
				|| (tpcmReqCmd (cmd) == TSS_ORD_GetDmeasureTrustedStatus)
				|| (tpcmReqCmd (cmd) == TSS_ORD_GetInterecpetTrustedStatus)
				|| (tpcmReqCmd (cmd) == TPCM_ORD_UpdateRootCert_VIR));
#else
	return 0;
#endif
}

int tpcm_transmit (void *sbuf, int slength, void *rbuf, int *rlength)
{
	int ret = 0;
	int gui_tddl_fd = 0;
	int retry_num=0;
	struct tddl_buffer *gst_tddl_msg = NULL;

	int ioctl_proc = is_spec_proc_cmd (sbuf) ? IOCTL_PROC_SPEC : IOCTL_PROC_TRANSMIT;
	int ioctl_cmd = ioctlCmd(IOCTL_TYPE_TPCM, ioctl_proc);
	int msg_len = HTTC_ALIGN_SIZE ((slength > (*rlength) ? slength : (*rlength)) + sizeof (struct tddl_buffer), 8); 
				
	if (NULL == (gst_tddl_msg = malloc (msg_len))){
		httc_util_pr_error ("gst_tddl_msg alloc error!\n");
		return TSS_ERR_NOMEM;	
	}
	memset (gst_tddl_msg, 0, sizeof (struct tddl_buffer));

	gst_tddl_msg->cmd_len = slength;
	gst_tddl_msg->rsp_maxlen = *rlength;
	if (sbuf) memcpy (gst_tddl_msg->buffer, sbuf, slength);
       do
	{
		gui_tddl_fd = open("/dev/tpcm_ttd", O_RDWR);
		if(gui_tddl_fd <0)
		{
			retry_num++;
			sleep(1);
			printf("errno:%d\r\n",errno);
		}
	} while ((gui_tddl_fd<0)&&(retry_num<5));

	if(gui_tddl_fd  < 0)
	{			
		httc_util_pr_error("open tpcm_ttd fail\n");
		free (gst_tddl_msg);
		return TSS_ERR_DEV_OPEN;
	}
	//httc_util_dump_hex ((uint8_t *)"Send", gst_tddl_msg->buffer, gst_tddl_msg->cmd_len);
	if (ioctl (gui_tddl_fd, ioctl_cmd, gst_tddl_msg)){
		close(gui_tddl_fd);
		free (gst_tddl_msg);
		return TSS_ERR_IO;
	}
	if (gst_tddl_msg->res){
		ret = gst_tddl_msg->res;
		close(gui_tddl_fd);
		free (gst_tddl_msg);
		return ret;
	}
	
	if (!gst_tddl_msg->rsp_len){
		close(gui_tddl_fd);
		free (gst_tddl_msg);
		return TSS_ERR_IO;
	}

	//httc_util_dump_hex ((uint8_t *)"Recv", gst_tddl_msg->buffer, gst_tddl_msg->rsp_len);
	*rlength = gst_tddl_msg->rsp_len;
	memcpy (rbuf, gst_tddl_msg->buffer, gst_tddl_msg->rsp_len);
	
	close(gui_tddl_fd);
	free (gst_tddl_msg);

	return 0;
}

