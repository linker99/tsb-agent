#ifndef __TCS_KERNEL_DEBUG_H__
#define __TCS_KERNEL_DEBUG_H__

#include <linux/slab.h>

#ifdef HTTCUTILS_DEBUG
#define httc_util_pr_dev_0(fmt, arg...)  \
	printk (KERN_DEBUG "DEBUG:%s:%s:%d:" fmt, __FILE__, __func__,__LINE__, ##arg)
#else
#define  httc_util_pr_dev_0(fmt, arg...) do{}while(0)
#endif

#define httc_util_pr_error_0(fmt, arg...)  \
		printk ("hter:%s:%s:%d:" fmt, __FILE__, __func__,__LINE__, ##arg)

#define httc_util_pr_dev(fmt, arg...) httc_util_pr_dev_0(fmt,##arg)
#define httc_util_pr_error(fmt, arg...) httc_util_pr_error_0(fmt,##arg)

static inline void httc_util_dump_hex_exec (const char *name, void *p, int bytes)
{
    int i = 0;
    uint8_t *data = p;
    int hexlen = 0;
    int chrlen = 0;
    uint8_t hexbuf[49] = {0};
    uint8_t chrbuf[17] = {0};
    uint8_t dumpbuf[128] = {0};

    printk ("%s length=%d:\n", name, bytes);
    
    for (i = 0; i < bytes; i ++){
        hexlen += sprintf ((char *)&hexbuf[hexlen], "%02X ", data[i]); 
        chrlen += sprintf ((char *)&chrbuf[chrlen], "%c", ((data[i] >= 33) && (data[i] <= 126)) ? (unsigned char)data[i] : '.');
        if (i % 16 == 15){
            sprintf ((char *)&dumpbuf[0], "%08X: %-49s%-17s", i / 16 * 16, hexbuf, chrbuf);
            printk ("%s\n", dumpbuf);
            hexlen = 0;
            chrlen = 0;
        }
    }

    if (i % 16 != 0){    
        sprintf ((char *)&dumpbuf[0], "%08X: %-49s%-17s", i / 16 * 16, hexbuf, chrbuf);
        printk ("%s\n", dumpbuf);
    }
}

#ifdef HTTCUTILS_DEBUG
#define httc_util_dump_hex httc_util_dump_hex_exec
#else
#define httc_util_dump_hex(name,p,bytes)
#endif

#endif	/** __TCS_KERNEL_DEBUG_H__ */

