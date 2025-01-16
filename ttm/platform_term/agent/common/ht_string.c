#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/limits.h>

#include "ht_string.h"

char id_values[] = {'0','1','2','3','4','5','6','7','8','9',
                                        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                                        'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'};





void str_to_binary(const char *src, char *dst, int dst_len)
{
	unsigned int i, k;

	for (i=0; i<dst_len; i++) {
		sscanf(&src[i*2], "%02X", &k);
		dst[i] = (unsigned char)k;
	}
}

void binary_to_str(const void *src, char *dst, int dst_len)
{
	unsigned int i;

	for (i=0; i<dst_len/2; i++) {
		sprintf(dst + i*2, "%02X", ((unsigned char *)src)[i]);
	}
}
