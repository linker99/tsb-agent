#ifndef __HTTCUTILS_MEM_H__
#define __HTTCUTILS_MEM_H__

#include <linux/vmalloc.h>
#include <linux/slab.h>

#ifdef MEM_TEST
void *httc_kmalloc(size_t size, gfp_t flags);
void *httc_kzalloc(size_t size, gfp_t flags);
void httc_kfree (const void *ptr);
void *httc_vmalloc(unsigned long size);
void *httc_vzalloc(unsigned long size);
void httc_vfree (const void *ptr);
#else
static inline void *httc_kmalloc(size_t size, gfp_t flags){
	return kmalloc(size,flags);
}
static inline void *httc_kzalloc(size_t size, gfp_t flags){
	return kzalloc(size,flags);
}
static inline void httc_kfree (const void *ptr){
	kfree(ptr);
}

static inline void *httc_vmalloc(unsigned long size){
	return vmalloc(size);
}
static inline void *httc_vzalloc(unsigned long size){
	return vzalloc(size);
}
static inline void httc_vfree (const void *ptr){
	vfree(ptr);
}
#endif

#endif	/** __HTTCUTILS_MEM_H__ */
