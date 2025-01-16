#ifndef DEBUG_H_
#define DEBUG_H_
#include <stdio.h>
#ifdef DEBUG
#define pr_dev(fmt, arg...) \
		printf("%s:%s:%d:" fmt, __FILE__, __func__,__LINE__, ##arg)
#else
#define  pr_dev(fmt, arg...) do{}while(0)
#endif
#endif /* DEBUG_H_ */
