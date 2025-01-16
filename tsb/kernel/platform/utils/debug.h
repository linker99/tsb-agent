

#ifndef HTTC_DEBUG_H_
#define HTTC_DEBUG_H_
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#ifdef DEBUG
void httc_dump_hex(const void *data, int n);
void httc_dump_hex_name(const char *name,const void *data, int n);
void dump_hex(void *data, int n);
void dump_hex_string(void *data, int n);
void dump_hex_string_for_crc32(void *data, int n);
#define pr_dev(fmt, arg...) \
		printk( "%s, Line%d in %s: " fmt, current->comm, __LINE__, __func__, ##arg)


static inline void *fdkmalloc(size_t size, gfp_t flags,const char *func,int line){
	void *p = kmalloc(size,flags);
	printk("%s,Kmalloc size %d,p=%p func=%s,line=%d\n",current->comm,(int)size,p,func,line);
	return p;
}


static inline void *fdkzalloc(size_t size, gfp_t flags,const char *func,int line){
	void *p = kzalloc(size,flags);
	printk("%s,Kzalloc size %d,p=%p func=%s,line=%d\n",current->comm,(int)size,p,func,line);
	return p;
}

static inline void *fdvmalloc(size_t size, const char *func,int line){
	void *p = vmalloc(size);
	printk("%s,Vmalloc size %d,p=%p func=%s,line=%d\n",current->comm,(int)size,p,func,line);
	return p;
}

static inline void fdkfree(void *p,const char *func,int line){

	printk("%s,Kfree ,p=%p  func=%s,line=%d\n",current->comm,p,func,line);
	kfree(p);
}
static inline void fdvfree(void *p,const char *func,int line){

	printk("%s,Vfree ,p=%p  func=%s,line=%d\n",current->comm,p,func,line);
	vfree(p);
}


//#define dkmalloc(size,flags) fdkmalloc(size,flags,__func__,__LINE__)
//#define dkzalloc(size,flags) fdkzalloc(size,flags,__func__,__LINE__)
//#define dvmalloc(size) fdvmalloc(size,__func__,__LINE__)
//#define dkfree(p) fdkfree(p,__func__,__LINE__)
//#define dvfree(p) fdvfree(p,__func__,__LINE__)

#define dkmalloc(size,flags) kmalloc(size,flags)
#define dkzalloc(size,flags) kzalloc(size,flags)
#define dvmalloc(size) vmalloc(size)
#define dkfree(p) kfree(p)
#define dvfree(p) vfree(p)

#else
#define  pr_dev(fmt, arg...) do{}while(0)
#define dump_hex(data, n) do{}while(0)
#define dump_hex_string(data, n) do{}while(0)

#define dkmalloc(size,flags) kmalloc(size,flags)
#define dkzalloc(size,flags) kzalloc(size,flags)
#define dvmalloc(size) vmalloc(size)
#define dkfree(p) kfree(p)
#define dvfree(p) vfree(p)
#endif


#define HTTC_TSB_INFO	        0x1	/* normal 消息 */
#define HTTC_TPCM_DEBUG       0x2	/* TPCM 调试信息 */
#define HTTC_TSB_DEBUG        0x4	/* TSB 调试信息 */
extern  unsigned int  LOG_MODE;


#if defined DTSB
#define HTTC_LOG_DEFAULT      (HTTC_TSB_INFO | HTTC_TSB_DEBUG)
#elif defined DTPCM
#define HTTC_LOG_DEFAULT      (HTTC_TSB_INFO | HTTC_TPCM_DEBUG)
#elif defined DEBUG
#define HTTC_LOG_DEFAULT      (HTTC_TSB_INFO | HTTC_TSB_DEBUG | HTTC_TPCM_DEBUG)
#else
#define HTTC_LOG_DEFAULT      (HTTC_TSB_INFO)
#endif


int get_log_mode(void);
void set_log_mode(unsigned int  mode);

#define DEBUG_MSG(mode, ...)                                            \
        do {                                                            \
		if (mode<=LOG_MODE)                            \
        printk("HTTC: "__VA_ARGS__);                    \
        } while(0)


int debug_log_init(void);
void debug_log_exit(void);
#endif /* HTTC_DEBUG_H_ */
