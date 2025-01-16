#ifndef __FLUSH_DCACHE_H__
#define __FLUSH_DCACHE_H__

int init_flush_dcache_area(void);
void kernel_flush_dcache_area(void *addr, size_t len);

#endif
