/*
 * types.h
 *
 *  Created on: 2021年5月6日
 *      Author: wangtao
 */

#ifndef HTTCUTILS_TYPES_H_
#define HTTCUTILS_TYPES_H_

#define httc_util_offset(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define httc_util_container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - httc_util_offset(type,member) );})

#endif /* HTTCUTILS_TYPES_H_ */
