#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "httcutils/sys.h"
#include "httcutils/debug.h"
#include "tcsapi/tcs_license.h"

const char * license_desc[LICENSE_ATTR_MAX] = {"ALL", "TPCM", "TSB", "TERM", "RESERVED"};
const char * license_type_desc[LICENSE_LTYPE_MAX] = {"V2.0", "V2.1"};
uint32_t license_type = LICENSE_ATTR_TPCM;

static void usage (void)
{
	printf ("\n"
			"  Usage: ./get_license_info -t <type>\n"
			"  options:\n"
			"        -t <type>    : license type,v2.0(1:test　2:TPCM　3:TPCM && TSB),v2.1(1:TPCM)\n"
			"\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	int status = 0;
	uint64_t deadline = 0;
    uint32_t be_license_type = 0;
    uint32_t be_license_type_low = 0;
    uint32_t be_license_type_high = 0;

	if (argc >= 3){
		license_type = atoi (argv[2]);
		if ( (license_type >= LICENSE_ATTR_MAX) || (license_type < LICENSE_ATTR_TPCM) )
		{
			httc_util_pr_error ("type: %d(0x%08x) illegal\n", license_type, license_type);
			return -1;
		}
	}

	if(0 != (ret = tcs_get_license_info (&status, &deadline))) {
		httc_util_pr_error ("ret: %d(0x%08x)\n", ret, ret);
		return -1;
	}

	printf ("License status \n");
	printf ("status         : %d\n", status);
	be_license_type = status;
	be_license_type_low = be_license_type & 0x0000ffff;
	be_license_type_high = (be_license_type & 0xffff0000) >> 16;
	printf("license_type   : %d, license_type_low: %d, license_type_high: %d\n", be_license_type, be_license_type_low, be_license_type_high);
	if ((be_license_type_high < LICENSE_LTYPE_MAX) && (be_license_type_high >= LICENSE_LTYPE_ZERO)){
		if ((be_license_type_high == LICENSE_LTYPE_ZERO) && (be_license_type_low == LICENSE_LTYPE_ZERO)){
			printf("version        : %s\n", license_type_desc[LICENSE_LTYPE_ONE]);
		}
	else{
			printf("version        : %s\n", license_type_desc[be_license_type_high]);
		}
	}
	else
	{
		httc_util_pr_error ("Invalid version: %d\n", be_license_type_high);
	}
	httc_util_time_print ("deadline       : %s\n", deadline);
	
	return 0;
}

