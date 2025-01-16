#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "mem.h"
#include "file.h"
#include "debug.h"
#include "convert.h"
#include "uutils.h"
#include "transmit.h"
#include "tcs_config.h"
#include "tcs_constant.h"
#include "tcs_error.h"

#include "crypto/sm/sm2_if.h"
#include "crypto/sm/sm3.h"
#include "tcs_auth_def.h"
#include "tcs_auth.h"



/** ÑéÇ©update */
int tcs_dev_verify_update (struct admin_cert_item *cert,
		int auth_type, int auth_length, unsigned char *auth, void *update, int update_size)
{
	int r;
	
	r = os_sm2_verify (update, update_size, cert->data, ntohl(cert->be_cert_len), auth, auth_length);
	return r ? TSS_ERR_VERIFY : TSS_SUCCESS;
}

int tcs_dev_get_cert_by_uid (const char *uid, struct admin_cert_item *cert)
{
	int ret;
	int number = 128;
	int i=0;
	struct admin_cert_item *item = NULL;

	ret = tcs_get_admin_list(&item,&number);
	
	if(ret) goto out;

	for (i = 0; i < number; i++){
		if (!strncmp ((const char *)item[i].name, uid, strlen(uid)<TPCM_UID_MAX_LENGTH ? strlen(uid) : TPCM_UID_MAX_LENGTH)){
			memcpy (cert, &item[i], sizeof(struct admin_cert_item));			
			goto out;
		}
	}
 out:
   if(item) httc_free(item);
	return ret;

}









