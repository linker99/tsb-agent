
#include "public.h"

#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_license.h"
#include "tcsapi/tcs_maintain.h"
#include "tcsapi/tcs_tpcm_error.h"

#define TCM_DEFAULT_PASSWORD	"12345678"

int ht_init_command_reset(int argc, char **argv)
{
	int ret;
	char *password = TCM_DEFAULT_PASSWORD;

	int pubkey_len = PUBKEY_LENGTH;
	
	if (argc > 1)
		return HT_INIT_HELP;

	if (argc == 1)
		password = argv[0];

	/* 清除所有数据(license试用期有效) */
	ret = tcf_reset_test_license();
	if (ret == TPCM_LICENSE_TYPE_ERROR) {
		unsigned char platform_pubkey[PUBKEY_LENGTH];
		if(tcf_get_pik_pubkey(platform_pubkey, &pubkey_len) == 140){//pik is null
			/* PIK初始化 */
			ret = tcs_init(password);
			if (ret) {
				printf("tcs_init fail, ret=%08X, pwd=%s\n", ret, password);
			}

			ret = tcf_generate_tpcm_pik(password);
			if (ret) {
				printf("tcf_generate_tpcm_pik fail, ret=%08X, pwd=%s\n", ret, password);
			}

		}

		printf("tcf_reset_test_license already exists, ret=%08X\n", ret);
		return HT_INIT_ERR_LICENSE;
	}
	else if (ret) {
		printf("tcf_reset_test_license fail, ret=%08X\n", ret);
		return HT_INIT_ERR_TCF;
	}

	/* PIK初始化 */
	ret = tcs_init(password);
	if (ret) {
		printf("tcs_init fail, ret=%08X, pwd=%s\n", ret, password);
		return HT_INIT_ERR_TCF;
	}

	ret = tcf_generate_tpcm_pik(password);
	if (ret) {
		printf("tcf_generate_tpcm_pik fail, ret=%08X, pwd=%s\n", ret, password);
		return HT_INIT_ERR_TCF;
	}

	return HT_INIT_OK;
}
