#ifndef _STUB_H_
#define _STUB_H_

#ifdef __cplusplus
    extern "C" {
#endif    

#ifdef __KERNEL__
#include <asm/atomic.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/stddef.h>
#include <linux/time.h>
#include <linux/ctype.h>

typedef int FILE;

extern int errno;
extern FILE *stderr;

#define fprintf(stream, fmt, args...)	MY_PRINT(fmt, ##args)

#define printf printk
#define fflush(a)
#define strtol simple_strtol

#define assert(cond) do { \
    if (!(cond)) \
        panic("assert(" #cond ")fail!"); \
} while(0)

#define double long

#define abort() panic("error.");

//#define INT_MAX ((unsigned int)~0)>>1

extern void qsort(void *base, size_t nmemb, size_t size,
                  int(*compar)(const void *, const void *));

static inline time_t time(time_t *t)
{
    time_t result;

    result = get_seconds();

    *t = result;

    return result;
}

#ifdef __KERNEL__
static inline FILE * fopen(const char *filename, const char *mode)
{
    return NULL;
}

static inline void fclose(void *p)
{
    return;
}


static inline size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    return 0;
}

static inline size_t fwrite(const void *ptr, size_t size, size_t nmemb,
                     FILE *stream)
{
    return 0;
}
#endif

static inline int fseek(FILE *stream, long offset, int whence)
{
    return 0;
}

static inline int feof(FILE *stream)
{
    return 0;
}

static inline long ftell(FILE *stream)
{
    return 0;
}

static inline int ferror(FILE *stream)
{
    return 0;
}

static inline char *fgets(char *s, int size, FILE *stream)
{
    return NULL;
}

static inline pid_t getpid(void)
{
    return current->pid;
}

static inline int vfprintf(FILE *stream, const char *format, va_list ap)
{
    return 0;
}

static inline char *getenv(const char *name)
{
    return NULL;
}

static inline char *strerror(int errnum)
{
    return NULL;
}


#endif

#ifdef __cplusplus
}
#endif    
#endif
