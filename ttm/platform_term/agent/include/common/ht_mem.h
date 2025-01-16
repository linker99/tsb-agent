#ifndef __HTTCUTILS_MEM_H__
#define __HTTCUTILS_MEM_H__

void *httc_malloc(size_t size);
void *httc_calloc(size_t nmemb, size_t size);
void httc_free(void *ptr);

#endif	/** __HTTCUTILS_MEM_H__ */

