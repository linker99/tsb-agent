#ifndef __HT_RAND_H__
#define __HT_RAND_H__

#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

static inline void ht_rand_bytes (unsigned char *buffer, int size)
{
	int i;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	srand(tv.tv_usec);
    for(i = 0; i < size; i++)
    	buffer[i] = (unsigned char)(rand() & 0xff);
}
#endif /** __HT_RAND_H__ */

