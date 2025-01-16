#ifndef __HTTCUTILS_MEM_H__
#define __HTTCUTILS_MEM_H__

void *httc_util_malloc(size_t size, const char *func, int line);
void *httc_util_calloc(size_t nmemb, size_t size, const char *func, int line);
void httc_util_free(void *ptr, const char *func, int line);

#define httc_malloc(size) httc_util_malloc(size,__func__,__LINE__)
#define httc_calloc(nmemb,size)	httc_util_calloc(nmemb,size,__func__,__LINE__)
#define httc_free(ptr)	httc_util_free(ptr,__func__,__LINE__)

#endif	/** __HTTCUTILS_MEM_H__ */

