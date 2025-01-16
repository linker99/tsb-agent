/*
 * offset.h
 *
 *  Created on: Sep 16, 2014
 *      Author: wangtao
 */

#ifndef OFFSET_H_
#define OFFSET_H_
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

static inline void __get_int(char **p, int *val)
{
	memcpy(val, *p, sizeof(uint32_t));
	*p += sizeof(uint32_t);
	return;
}

static inline void __set_int(char **p, int val)
{
	memcpy(*p, &val, sizeof(uint32_t));
	*p += sizeof(uint32_t);
	return;
}

static inline void __back_int(char **p)
{
	*p -= sizeof(uint32_t);
	return;
}

static inline void  __get_string(char **p, int len, char **str)
{
	*str = *p;
	*p += len;
	return;
}

static inline void __set_string(char **p, int len, char *str)
{
	memcpy(*p, str, len-1);
	*(*p + len -1) = '\0';
	*p += len;
	return;
}


static inline void __back_string(char **p, int len)
{
	*p -= len;
	return;
}

static inline void  __get_mem(char **p, int len, char **mem)
{
	*mem = *p;
	*p += len;
	return;
}
static inline void __set_mem(char **p, int len, char *mem)
{
	memcpy(*p, mem, len);
	*p += len;
	return;
}

static inline void __back_mem(char **p, int len)
{
	*p -= len;
	return;
}


#ifdef __cplusplus
}
#endif

#endif /* FILE_UTIL_H_ */
