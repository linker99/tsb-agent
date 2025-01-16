#ifndef TPCMSYS_H_
#define TPCMSYS_H_
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <tpcm_config.h>
#include "tpcm_debug.h"
typedef void (*TPCM_entry_func)(void);
extern 	TPCM_entry_func tpcm_main_func;
#define TPCM_MAIN(fun) TPCM_entry_func tpcm_main_func = fun;

extern 	TPCM_entry_func tpcm_init_early_func;
#define TPCM_INIT_EARLY(fun) TPCM_entry_func tpcm_init_early_func = fun;

extern 	TPCM_entry_func tpcm_init_func;
#define TPCM_INIT(fun) TPCM_entry_func tpcm_init_func = fun;

extern 	TPCM_entry_func tpcm_bois_measure_func;
#define TPCM_BIOS_FUNC(fun) TPCM_entry_func tpcm_bois_measure_func = fun;

extern 	TPCM_entry_func tpcm_sys_restore_init_func;
#define TPCM_RESTORE_INIT(fun) TPCM_entry_func tpcm_sys_restore_init_func = fun;


typedef void * MAPObject;
struct tpcm_sys_time{
	uint32_t seconds;
	uint32_t millis;
}__attribute__((packed));


void tpcm_sys_printf(const char *fmt, ...) ;
void tpcm_sys_level_printf(int level, const char *fmt, ...) ;

void *tpcm_sys_malloc(unsigned int size);
void tpcm_sys_free(void * p);
int tpcm_sys_rand(unsigned char *buffer,int length);
int tpcm_sys_get_time(struct tpcm_sys_time *time);
MAPObject tpcm_sys_map(uint64_t paddr,unsigned length,void **vadrr);
void tpcm_sys_unmap(MAPObject apobj);
void tpcm_sys_unmap_modified(MAPObject apobj);
void tpcm_sys_get_memory_status(uint32_t *total,uint32_t* used);
uint32_t tpcm_sys_get_cpu_id(void);
void tpcm_sys_udelay(uint32_t us);
void tpcm_sys_mdelay(uint32_t us);
void tpcm_sys_dcache_cleaninv_range(void *addr, size_t size);
void tpcm_sys_dcache_clean_range(void *addr, size_t size);
void tpcm_sys_dcache_inv_range(void *addr, size_t size);
void tpcm_sys_disable_irq(uint64_t *status );
void tpcm_sys_enable_irq(uint64_t status );
int tpcm_sys_get_tpcm_hardware_tag(unsigned char *tag,unsigned int *length);

//uint32_t tpcm_sys_notify_pending(void);
//void tpcm_sys_clear_pending(void);




#ifndef DIRECT_IMPL_SYSFUNC
typedef void (* PRINT_FUNC)(const char *fmt, ...) ;
typedef void (* PRINT_FUNC_LEVEL)(int level,const char *fmt, ...);

struct tpcm_sys{
	PRINT_FUNC printf;
	PRINT_FUNC_LEVEL level_printf;
	void *(* malloc)(size_t size);
	void (* free)(void * p);
	int (* rand)(unsigned char *buffer,int length);
	int (* get_time)(struct tpcm_sys_time *time);
	MAPObject (* map)(uint64_t  paddr,unsigned length,void **vadrr);
	void (* unmap)(MAPObject apobj);
	void (* unmap_modified)(MAPObject apobj);
	void (* get_memory_status)(uint32_t *total,uint32_t* used);
	uint32_t (* get_cpu_id)(void);
	void (* udelay)(uint32_t us);
	void (* mdelay)(uint32_t us);
	void (* dcache_cleaninv_range)(void *addr, size_t size);
	void (* dcache_clean_range)(void *addr, size_t size);
	void (* dcache_inv_range)(void *addr, size_t size);
	void (* disable_irq)(uint64_t *status );
	void (* enable_irq)(uint64_t status );
	int  (* get_tpcm_hardware_tag)(unsigned char *tag,unsigned int* length);

};

extern struct tpcm_sys tpcm_sys;
#define tpcm_sys_printf(fmt,...)  		tpcm_sys.printf(fmt,##__VA_ARGS__)
#define tpcm_sys_level_printf(level,fmt,...)  		tpcm_sys.level_printf(level,fmt,##__VA_ARGS__)

#define tpcm_sys_msleep(miliseconds) 	tpcm_sys.mdelay(miliseconds)
#ifdef MEM_TEST
#define tpcm_sys_malloc(size) 			(tpcm_sys.printf("Malloc at (%s:%d),size=%d\n" , __func__, __LINE__,(int)size),tpcm_sys.malloc(size))
#define tpcm_sys_free(p)				(tpcm_sys.printf("Free at (%s:%d),pointer=%p\n",__func__, __LINE__,p),tpcm_sys.free(p))
#else
#define tpcm_sys_malloc(size) 			tpcm_sys.malloc(size)
#define tpcm_sys_free(p)				tpcm_sys.free(p)
#endif
#define	tpcm_sys_rand(buffer,length)	tpcm_sys.rand(buffer,length)

#define	tpcm_sys_get_time(time)	tpcm_sys.get_time(time)

#define	tpcm_sys_map(paddr,length,vadrr) \
										tpcm_sys.map(paddr,length,vadrr)

#define	tpcm_sys_unmap(apobj) 			tpcm_sys.unmap(apobj)
#define	tpcm_sys_unmap_modified(apobj) 			tpcm_sys.unmap_modified(apobj)

#define	tpcm_sys_get_memory_status(total,used)	\
										tpcm_sys.get_memory_status(total,used)

#define	tpcm_sys_get_cpu_id() 			tpcm_sys.get_cpu_id()
#define	tpcm_sys_udelay(us) 			tpcm_sys.udelay(us)

#define	tpcm_sys_mdelay(ms)	 			tpcm_sys.mdelay(ms)
#define	tpcm_sys_dcache_cleaninv_range(addr,size) \
										tpcm_sys.dcache_cleaninv_range(addr,size)
#define	tpcm_sys_dcache_clean_range(addr,size) \
										tpcm_sys.dcache_clean_range(addr,size)
#define	tpcm_sys_dcache_inv_range(addr,size) \
										tpcm_sys.dcache_inv_range(addr,size)


#define	tpcm_sys_disable_irq(status) 	tpcm_sys.disable_irq(status)
#define	tpcm_sys_enable_irq(status) 	tpcm_sys.enable_irq(status)

#define	tpcm_sys_get_tpcm_hardware_tag(tag,length) tpcm_sys.get_tpcm_hardware_tag(tag,length)
#endif

//enum CMD_ERR_E {
//    CMD_ERR_NONE = 0x0,
//	CMD_ERR_NO_HANDLER,
//    CMD_ERR_API,
//    CMD_ERR_NULL_POINTER,
//    CMD_ERR_INVALID_INPUT_POINTER,
//	CMD_ERR_INVALID_OUTPUT_POINTER,
//	CMD_ERR_MAP_FAIL,
//	CMD_ERR_FUNCTION_ERROR
//};

//
enum{
	TPCM_ERROR_UNSUPPORTED_CMD_TYPE = 256,
	TPCM_ERROR_INVALID_COMMAND,
	TPCM_ERROR_MAP_FAIL,
	TPCM_ERROR_NO_SPACE,
	//TPCM_ERROR_UNSUPPORTED,
	TPCM_ERROR_INVALID_PARAM,
};
#endif /* TPCMSYS_H_ */
