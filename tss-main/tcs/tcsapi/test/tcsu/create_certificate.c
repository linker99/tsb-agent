/*************************************************************************
	> File Name: test.c
	> Author: 
	> Mail: 
	> Created Time: 2021年05月14日 星期五 14时41分15秒
 ************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "debug.h"
#include "convert.h"
#include "tcs_attest.h"

void usage()
{
    printf ("\n");
    printf ("  Usage: ./creat_certificate [id] [cert>");
	printf ("         id    - cert id (32 Bytes, Default: tpcm id)\n");
	printf ("         cert  - cert data (Default: tpcm pik pubkey)\n");
    printf ("     eg: ./create_certificate\n");
    printf ("     eg: ./create_certificate client 17189C78C49FC2CF859E7D152D525D885E8479278A1B5F875D67A3E663F30B6912A66596227539320E877EA140C672296F966E2221BFCE92D7893F014FF5C55E\n");
    printf ("\n");
}

int main(int argc, char *argv[])
{
	int r;
	int id_len = MAX_TPCM_ID_SIZE;
	char *pubkeystr = NULL;
    struct remote_cert cert;
	uint32_t pubkey_len = sizeof(cert.cert);

	memset (&cert, 0, sizeof (cert));

	if (argc >= 2){
		if (strlen(argv[1]) != MAX_TPCM_ID_SIZE){
			usage ();
			return -1;
		}
		memcpy (cert.id, argv[1], MAX_TPCM_ID_SIZE);
	}else{
		if ((r = tcs_get_tpcm_id (cert.id, &id_len))){
			httc_util_pr_error ("tcf_get_tpcm_id error: %d(0x%x)\n", r, r);
			return -1;
		}
	}

	if (argc == 3){
		pubkeystr = argv[2];
		pubkey_len = strlen (pubkeystr)/2;
		httc_util_str2array (cert.cert, pubkeystr, strlen (pubkeystr));
	}else{
		if((r = tcs_get_pik_pubkey(cert.cert, &pubkey_len))) {
			httc_util_pr_error ("tcs_get_pik_pubkey error: %d(0x%x)\n", r, r);
			return -1;
		}
	}

    cert.be_alg = 0; 
    cert.be_length = htonl (pubkey_len);

    if ((r = tcs_add_remote_cert (&cert))){
		httc_util_pr_error ("tcs_add_remote_cert error: %d(0x%x)\n", r, r);
		return -1;
	}

    return 0;
}
