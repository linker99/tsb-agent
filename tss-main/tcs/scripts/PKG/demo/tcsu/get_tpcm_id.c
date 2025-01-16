#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tcs_attest.h"

void httc_util_dump_hex (const char *name, void *p, int bytes)
{
    int i = 0;
    uint8_t *data = p;
    int hexlen = 0;
    int chrlen = 0;
    uint8_t hexbuf[49] = {0};
    uint8_t chrbuf[17] = {0};
    uint8_t dumpbuf[128] = {0};

    printf ("%s length=%d:\n", name, bytes);

    for (i = 0; i < bytes; i ++){
        hexlen += sprintf ((char *)&hexbuf[hexlen], "%02X ", data[i]);
        chrlen += sprintf ((char *)&chrbuf[chrlen], "%c", ((data[i] >= 33) && (data[i] <= 126)) ? (unsigned char)data[i] : '.');
        if (i % 16 == 15){
            sprintf ((char *)&dumpbuf[0], "%08X: %-49s%-17s", i / 16 * 16, hexbuf, chrbuf);
            printf ("%s\n", dumpbuf);
            hexlen = 0;
            chrlen = 0;
        }
    }

    if (i % 16 != 0){
        sprintf ((char *)&dumpbuf[0], "%08X: %-49s%-17s", i / 16 * 16, hexbuf, chrbuf);
        printf ("%s\n", dumpbuf);
    }
}


int main(void)
{
	int ret = 0;
	uint8_t id[128] = {0};
	uint32_t id_len = sizeof(id);

	ret = tcs_get_tpcm_id(id, &id_len);
	if(ret) {
		printf("[tcs_get_tpcm_id] ret: 0x%08x\n", ret);
		return -1;
	}
	printf("\n");
	httc_util_dump_hex("TPCM ID", id, id_len);
	printf("\n");
	
	return 0;
}

