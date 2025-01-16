/*
 * align.h
 *
 *  Created on: 2021年4月16日
 *      Author: wangtao
 */

#ifndef HTTCUTILS_CONVERT_H_
#define HTTCUTILS_CONVERT_H_
#ifndef __KERNEL__
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stddef.h>
#endif

#ifndef MIN
#define MIN(x,y) ((x)<(y)?(x):(y))
#endif

#ifndef MAX
#define MAX(x,y) ((x)>(y)?(x):(y))
#endif

#define HTTC_ALIGN_SIZE(len,align) ((len)%(align) == 0 ? (len) : (len) + (align) - (len)%(align))
//static union { char c[4]; unsigned long mylong; } endian_test = {{ 'l', '?', '?', 'b' } };
//#define ENDIANNESS ((char)endian_test.mylong)
//#if __BYTE_ORDER__ ==__ORDER_BIG_ENDIAN__
//#define htonll(val) (val)
//#define ntohll(val) (val)
//#else
static inline uint64_t htonll(uint64_t val)
{
	int a = 0x01;
    char * p = (char*) & a;
    if(*p == 1){
//		printf ("little endian\n");
        return (((uint64_t)htonl(val)) << 32) + htonl(val >> 32);
    }else{
//		printf ("big endian\n");
        return val;
    }
}

static inline  uint64_t ntohll(uint64_t val)
{
	int a = 0x01;
    char * p = (char*) & a;
    if(*p == 1){
//		printf ("little endian\n");
		return (((uint64_t)ntohl(val)) << 32) + ntohl(val >> 32);
    }else{
//    	printf ("big endian\n");
		return val;
	}
}
//#endif

//#if defined platform_2700
//
//int ctoi (char c);
//void httc_util_str2array (uint8_t *output, uint8_t *input, uint32_t insize);
//
//#else

static inline int ctoi (char c)
{
	int n = 0;
	if (c >= '0' && c <= '9'){
		n = c - '0';
	}
	else if (c >= 'a' && c <= 'f'){
		n = c - 'a' + 10;
	}
	else if (c >= 'A' && c <= 'F'){
		n = c - 'A' + 10;
	}

	return n;
}

static inline void httc_util_str2array (uint8_t *output, uint8_t *input, uint32_t insize)
{
    uint32_t i = 0;    
	while (i < (insize / 2)) {
		output[i] = (ctoi(input[i*2]) << 4) | ctoi(input[i*2+1]);
       	i++;
	}
}

//
//#endif
//static inline void httc_util_dump_hex (unsigned char *name, void *p, int bytes)
//{
//    int i = 0;
//    uint8_t *data = p;
//    int hexlen = 0;
//    int chrlen = 0;
//    uint8_t hexbuf[128] = {0};
//    uint8_t chrbuf[128] = {0};
//    uint8_t dumpbuf[128] = {0};
//
//    printf ("%s length=%d:\n", name, bytes);
//
//    for (i = 0; i < bytes; i ++){
//        hexlen += sprintf ((char *)&hexbuf[hexlen], "%02X ", data[i]);
//        chrlen += sprintf ((char *)&chrbuf[chrlen], "%c", ((data[i] >= 33) && (data[i] <= 126)) ? (unsigned char)data[i] : '.');
//        if (i % 16 == 15){
//            sprintf ((char *)&dumpbuf[0], "%08X: %s %s", i / 16 * 16, hexbuf, chrbuf);
//            printf ("%s\n", dumpbuf);
//            hexlen = 0;
//            chrlen = 0;
//        }
//    }
//
//    if (i % 16 != 0){
//        sprintf ((char *)&dumpbuf[0], "%08X: %-48s %s", i / 16 * 16, hexbuf, chrbuf);
//        printf ("%s\n", dumpbuf);
//    }
//}
//
//

#endif /* HTTCUTILS_CONVERT_H_ */
