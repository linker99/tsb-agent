#ifndef __TCSU_CERT_VERIFY_H__
#define __TCSU_CERT_VERIFY_H__
#include <stdint.h>

int tcs_dev_verify_update (struct admin_cert_item *cert,
		int auth_type, int auth_length, unsigned char *auth, void *update, int update_size);


int tcs_dev_get_cert_by_uid (const char *uid, struct admin_cert_item *cert);

#endif	/** __TCSU_CERT_VERIFY_H__ */


