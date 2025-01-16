/********************************************************************************/

/********************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "tcmfunc.h"

void print_array(const char *name, const unsigned char *data, unsigned int len)
{
    unsigned int i = 0;
    printf(" %s \n", name);
    while (i < len) {
        printf("0x%02X ", data[i]);
        i++;
        if (0 == (i & 0xf)) {
            printf("\n");
        }
    }
    printf("\n");
}



void  TCM_dump_data(const char *name, const void *s, size_t len)
{
    size_t i, j;
    const u_char *p = (const u_char *)s;
    printf("[debug] %s :\n", name);

    for (i = 0; i < len; i += 16) {
        printf( "%.4zu: ", i);
        for (j = i; j < i + 16; j++) {
            if (j < len)
                printf( "%02x ", p[j]);
            else
                printf( "   ");
        }
        printf( " ");
        for (j = i; j < i + 16; j++) {
            if (j < len) {
                if  (isascii(p[j]) && isprint(p[j]))
                    printf("%c", p[j]);
                else
                    printf(".");
            }
        }
        printf("\n");
    }
}
