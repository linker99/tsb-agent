#ifndef _SSL_H_
#define _SSL_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __KERNEL__
#include <stdio.h>
#include <string.h>
#endif

#include "stub.h"
#include "bn.h"
#include "ec.h"
#include "rand.h"
#include "err.h"
#include "ecdsa.h"
#include "ecdh.h"
#include "evp.h"

#ifdef __KERNEL__
#define MY_PRINT(fmt, args...) printk("OS_SAFE:(%s)(%s)-L%d: "fmt, __FILE__ , __FUNCTION__, __LINE__, ##args)
#else
#define MY_PRINT(fmt, args...) printf("OS_SAFE:(%s)(%s)-L%d: "fmt, __FILE__ , __FUNCTION__, __LINE__, ##args)
#endif

#ifdef __cplusplus
}
#endif

#endif

