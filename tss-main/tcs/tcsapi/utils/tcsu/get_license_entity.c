#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sys.h"
#include "debug.h"
#include "tcs_license.h"
#include "convert.h"

const char * license_desc[LICENSE_ATTR_MAX] = {"ALL", "TPCM", "TSB", "TERM", "RESERVED"};
const char * license_type_desc[LICENSE_LTYPE_MAX] = {"V2.0", "V2.1"};
uint32_t license_type = LICENSE_ATTR_ALL;

int test_get_license_entity(void)
{
	int ret = 0;
	struct license_entity data[4];
	int num = 0;
	uint32_t be_license_type = 0;
	uint32_t be_license_type_low = 0;
	uint32_t be_license_type_high = 0;
	int i = 0;

	memset(data, 0, sizeof(data));
	if(0 != (ret = tcs_get_license_entity(data, &num))) {
		httc_util_pr_error ("ret: %d(0x%08x)\n", ret, ret);
		return -1;
	}

	printf("license_entity,num is: %d\n", num);
	for (i = 0; i < num; ++i)
	{
		be_license_type = ntohl(data[i].be_license_type);
		be_license_type_low = be_license_type & 0x0000ffff;
		be_license_type_high = (be_license_type & 0xffff0000) >> 16;
		printf ("\n");
		printf("license_entity, i is : %d\n", i);
		printf("license_type         : %d, license_type_low: %d, license_type_high: %d\n", be_license_type, be_license_type_low, be_license_type_high);
		if ((be_license_type_high < LICENSE_LTYPE_MAX) && (be_license_type_high >= LICENSE_LTYPE_ZERO)){
			printf("version              : %s\n", license_type_desc[be_license_type_high]);
		}
		printf("client_id_length     : %d\n", ntohl(data[i].be_client_id_length));
		printf("tpcm_id_length       : %d\n", ntohl(data[i].be_tpcm_id_length));
		printf("host_id_length       : %d\n", ntohl(data[i].be_host_id_length));
		httc_util_time_print ("time_stamp           : %s\n", ntohll(data[i].be_time_stamp));
		httc_util_time_print ("deadline             : %s\n", ntohll(data[i].be_deadline));
		httc_util_dump_hex ("client_id", data[i].client_id, ntohl(data[i].be_client_id_length));
		httc_util_dump_hex ("tpcm_id", data[i].tpcm_id, ntohl(data[i].be_tpcm_id_length));
		httc_util_dump_hex ("host_id", data[i].host_id, ntohl(data[i].be_host_id_length));
	}
	
	return 0;
}

static void usage (void)
{
	printf ("\n"
			"  Usage: ./get_license_entity -t <type>\n"
			"  options:\n"
			"        -t <type>    : license type (0-all; 1-tpcm; 2-tsb; 3-term; 4-reserved)\n"
			"\n");
}

int main (int argc, char **argv)
{
	int ret = 0;

	if (argc >= 3){
		license_type = atoi (argv[2]);
		if ( (license_type >= LICENSE_ATTR_MAX) || (license_type < LICENSE_ATTR_ALL) )
		{
			httc_util_pr_error ("type: %d(0x%08x) illegal\n", license_type, license_type);
			return -1;
		}
	}

	if((ret = test_get_license_entity()) != 0) {
		printf("test_get_license_entity, ret = %d\n", ret);
		return -1;
	}
	else {
		printf("test_get_license_entity OK\n");
	}

	return 0;
}

