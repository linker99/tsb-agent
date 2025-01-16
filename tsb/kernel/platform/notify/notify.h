#ifndef SRC_NOTIFY_H_
#define SRC_NOTIFY_H_

#include "tsbapi/tsb_log_notice.h"

#define MAX_CONCURR_PROCESS 32 
/* #define TSB_NOTIFY_DEBUG  */
/* #undef TSB_NOTIFY_DEBUG */

#define MAX_BUF_ITEMS_NUM       1000
#define MIN_BUF_ITEMS_NUM       100
#define DEFAULT_BUF_ITEMS_NUM   500 

int tsb_notify_init(void);
void tsb_notify_exit(void);

long tsb_destroy_notify_read_queue(struct file *filp);
#endif
