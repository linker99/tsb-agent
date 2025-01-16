#ifndef __HT_RAND_H__
#define __HT_RAND_H__

#include <stdlib.h>

static inline void ht_rand_bytes (unsigned char *buffer, int size)
{
	int i;
    for(i = 0; i < size; i++)
    	buffer[i] = (unsigned char)(rand() & 0xff);
}
#endif /** __HT_RAND_H__ */

