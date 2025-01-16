#ifndef __HTTCUTILS_MEM_H__
#define __HTTCUTILS_MEM_H__

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>

static atomic64_t kmalloc_cnt = ATOMIC64_INIT(0);
static atomic64_t vmalloc_cnt = ATOMIC64_INIT(0);

void *httc_kmalloc(size_t size, gfp_t flags){
	printk ("****** Inc kalloc cnt: %ld\n", atomic64_inc_return(&kmalloc_cnt));
	return kmalloc(size,flags);
}
EXPORT_SYMBOL_GPL (httc_kmalloc);
void *httc_kzalloc(size_t size, gfp_t flags){
	printk ("****** Inc kalloc cnt: %ld\n", atomic64_inc_return(&kmalloc_cnt));
	return kzalloc(size,flags);
}
EXPORT_SYMBOL_GPL (httc_kzalloc);
void httc_kfree (const void *ptr){
	printk ("****** Dec kalloc cnt: %ld\n", atomic64_dec_return(&kmalloc_cnt));
	kfree(ptr);
}
EXPORT_SYMBOL_GPL (httc_kfree);
void *httc_vmalloc(unsigned long size){
	printk ("****** Inc valloc cnt: %ld\n", atomic64_inc_return(&vmalloc_cnt));
	return vmalloc(size);
}
EXPORT_SYMBOL_GPL (httc_vmalloc);
void *httc_vzalloc(unsigned long size){
	printk ("****** Inc valloc cnt: %ld\n", atomic64_inc_return(&vmalloc_cnt));
	return vzalloc(size);
}
EXPORT_SYMBOL_GPL (httc_vzalloc);
void httc_vfree (const void *ptr){
	printk ("****** Dec valloc cnt: %ld\n", atomic64_dec_return(&vmalloc_cnt));
	vfree(ptr);
}
EXPORT_SYMBOL_GPL (httc_vfree);

#endif	/** __HTTCUTILS_MEM_H__ */
