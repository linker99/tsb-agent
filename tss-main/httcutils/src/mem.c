#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <httcutils/mem.h>

#ifdef MEM_TEST

static unsigned long long mem_cnt = 0;
static pthread_mutex_t mem_metux = PTHREAD_MUTEX_INITIALIZER;


void *httc_util_malloc (size_t size, const char *func, int line){
	func = func;
	line = line;
	pthread_mutex_lock (&mem_metux);
	printf ("****** Inc mem cnt: %lld\n", ++mem_cnt);
	pthread_mutex_unlock (&mem_metux);
	return malloc(size);
}
void *httc_util_calloc (size_t nmemb, size_t size, const char *func, int line){
	func = func;
	line = line;
	pthread_mutex_lock (&mem_metux);
	printf ("****** Inc mem cnt: %lld\n", ++mem_cnt);
	pthread_mutex_unlock (&mem_metux);
	return calloc(nmemb, size);
}
void httc_util_free (void *ptr, const char *func, int line){
	func = func;
	line = line;
	pthread_mutex_lock (&mem_metux);
	printf ("****** Dec mem cnt: %lld\n", --mem_cnt);
	pthread_mutex_unlock (&mem_metux);
	free(ptr);
}

#else
void *httc_util_malloc(size_t size, const char *func, int line){
	func = func;
	line = line;
	return malloc(size);
}
void *httc_util_calloc(size_t nmemb, size_t size, const char *func, int line){
	func = func;
	line = line;
	return calloc(nmemb, size);
}
void httc_util_free(void *ptr, const char *func, int line){
	func = func;
	line = line;
	free(ptr);
}
#endif


