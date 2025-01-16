#ifndef __HTTC_PDRIVE_DEBUG_H_
#define __HTTC_PDRIVE_DEBUG_H_

#define INTERCEPT 0x01
#define ENGINE    0x02
#define MEASURE   0x04

#define	PDRIVE_ERR      0   /* error conditions */
#define	PDRIVE_WARNING	1	/* warning conditions */
#define	PDRIVE_NOTICE	2	/* normal but significant condition	*/
#define	PDRIVE_INFO	    3	/* informational */
#define	PDRIVE_DEBUG	4	/* debug-level messages	*/

static unsigned int default_level = 3;
static unsigned int default_type = 0xFF;

void pdrive_print(int level, int type, const char *fmt, ...)
{
	if((level <= default_level) && (type & default_type)){
		va_list args;
		int r;

		va_start(args, fmt);
		r = vprintk(fmt, args);
		va_end(args);
		}
}

#define print_message(level, type, fmt, ...) ({\
	if(((int)level <= default_level) && ((int)type & default_type)){\
		printk("%s, Line%d in %s: " fmt, current->comm, __LINE__, __func__, ##arg);\
\})

#endif
