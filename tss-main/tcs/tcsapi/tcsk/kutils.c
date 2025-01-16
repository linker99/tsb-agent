#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0))
#include <linux/libnvdimm.h>
#endif

#if (defined __arm64__ || defined __aarch64__ || defined __csky__)
#include <linux/mm_types.h>
#endif
#include "version.h"
#include "kutils.h"

#if defined(CONFIG_64BIT)
#define  INVALID_DATA_FULL_FF   0xffffffffffffffff
#else
#define  INVALID_DATA_FULL_FF   0xffffffff
#endif

/** kallsyms_lookup_name */
unsigned long k_kallsyms_lookup_name = INVALID_DATA_FULL_FF;
module_param(k_kallsyms_lookup_name, ulong, 0644);
EXPORT_SYMBOL_GPL(k_kallsyms_lookup_name);
/*MODULE_PARM_DESC(k_kallsyms_lookup_name, "ulong kallsyms lookup name");
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33))
unsigned long (*httc_kallsyms_lookup_name) (const char *name) = (void *)INVALID_DATA_FULL_FF;
#else
unsigned long (*httc_kallsyms_lookup_name) (const char *name) = kallsyms_lookup_name;
#endif
EXPORT_SYMBOL_GPL (httc_kallsyms_lookup_name);*/

/** arch_invalidate_pmem */
static unsigned long k_do_invalidatepage = INVALID_DATA_FULL_FF;
module_param(k_do_invalidatepage, ulong, 0644);
MODULE_PARM_DESC(k_do_invalidatepage, "ulong k_do_invalidatepage");
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0))
typedef void (*do_invalidatepage_type)(struct page *page,unsigned int offset,unsigned int length);
void httc_arch_invalidate_pmem (void *addr, size_t size){
        int i = 0;
        int s_off = 0;
        int s_size = 0;
        int rest = 0;
        do_invalidatepage_type do_invalidatepage = (void*)k_do_invalidatepage;


		s_off = (unsigned long)addr % PAGE_SIZE;


        if (s_off){
                s_size = PAGE_SIZE - s_off;
                do_invalidatepage (virt_to_page (addr), s_off, s_size);
        }
        addr += s_off;
        rest -= s_off;

        for (i = 0; i < rest / PAGE_SIZE; i++)
                do_invalidatepage (virt_to_page (addr), 0, (rest < PAGE_SIZE) ? rest : PAGE_SIZE);
}
#else
void httc_arch_invalidate_pmem(void *addr, size_t size)
{
        #ifdef __aarch64__
         arch_invalidate_pmem (addr, size);
        #else
        addr = addr;
        size = size;
        #endif
}
#endif
EXPORT_SYMBOL_GPL (httc_arch_invalidate_pmem);

char* tpcm_memcpy(void __iomem *dst, const void *src, int size)
{
	int i = 0;
	char *s = dst;
	char *pdst = dst;
	const char *psrc = src;
	while (i < size)
	{
		*(pdst + i) = *(psrc + i);
		i ++;
	}
	return s;
}
EXPORT_SYMBOL_GPL (tpcm_memcpy);

char* tpcm_memcpy_u16(void __iomem *dst, const uint16_t src)
{
	int i = 0;
	char *s = dst;
	char *pdst = dst;
	const char *psrc = (char *)&src;
	while (i < sizeof (src))
	{
		*(pdst + i) = *(psrc + i);
		i ++;
	}
	return s;
}
EXPORT_SYMBOL_GPL (tpcm_memcpy_u16);

char* tpcm_memcpy_u32(void __iomem *dst, const uint32_t src)
{
	int i = 0;
	char *s = dst;
	char *pdst = dst;
	const char *psrc = (char *)&src;
	while (i < sizeof (src))
	{
		*(pdst + i) = *(psrc + i);
		i ++;
	}
	return s;
}
EXPORT_SYMBOL_GPL (tpcm_memcpy_u32);

char* tpcm_memcpy_u64(void __iomem *dst, const uint64_t src)
{
	int i = 0;
	char *s = dst;
	char *pdst = dst;
	const char *psrc = (char *)&src;
	while (i < sizeof (src))
	{
		*(pdst + i) = *(psrc + i);
		i ++;
	}
	return s;
}
EXPORT_SYMBOL_GPL (tpcm_memcpy_u64);

char* tpcm_memclear(void __iomem *dst, int size)
{
	int i = 0;
	char *s = dst;
	char *pdst = dst;
	while (i < size)
	{
		*(pdst + i) = 0;
		i ++;
	}
	return s;
}
EXPORT_SYMBOL_GPL (tpcm_memclear);

int ctoi (char c)
{
	int n = 0;
	if (c >= '0' && c <= '9'){
		n = c - '0';
	}
	else if (c >= 'a' && c <= 'f'){
		n = c - 'a' + 10;
	}
	else if (c >= 'A' && c <= 'F'){
		n = c - 'A' + 10;
	}
	
	return n;
}
void httc_util_str2array (uint8_t *output, uint8_t *input, uint32_t insize)
{
    uint32_t i = 0;    
	while (i < (insize / 2)) {
		output[i] = (ctoi(input[i*2]) << 4) | ctoi(input[i*2+1]);
       	i++;
	}
}
EXPORT_SYMBOL_GPL (httc_util_str2array);

int tpcm_util_cache_flush (void *kaddr, size_t len) 
{
        typedef void (*flush_cache_t)(void);
        typedef long (*flush_cache_range_t)(void *, unsigned long);
        static flush_cache_t flush_cache = NULL;
        static flush_cache_range_t flush_cache_range = NULL;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)) || (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
	 	unsigned long (*httc_kallsyms_lookup_name) (const char *name) = (void *)k_kallsyms_lookup_name;
#else
	   	unsigned long (*httc_kallsyms_lookup_name) (const char *name) = kallsyms_lookup_name;
#endif
		/** x86 */
		if ((NULL != flush_cache_range)
			|| (NULL != (flush_cache_range = (flush_cache_range_t)httc_kallsyms_lookup_name ("clflush_cache_range")))){
                (flush_cache_range)(kaddr, len);
                return 0;
        }

		/** aarch64 */
		if ((NULL != flush_cache_range)
			|| (NULL != (flush_cache_range = (flush_cache_range_t)httc_kallsyms_lookup_name ("__flush_dcache_area")))){
                (flush_cache_range)(kaddr, len);
                return 0;
        }

		/** deepin */
		if ((NULL != flush_cache)
			|| (NULL != (flush_cache = (flush_cache_t)httc_kallsyms_lookup_name ("cache_flush")))){
                (flush_cache)();
                return 0;
        }

        printk ("[%s:%d] tpcm_util_cache_flush is not found \n", __func__, __LINE__);
        return 0;
}
EXPORT_SYMBOL_GPL (tpcm_util_cache_flush);

int httc_insert_uid_align4 (const char *uid, void *ptr)
{
	int uid_size = 0;
	struct tpcm_data *uid_st = (struct tpcm_data *)ptr;
	if (uid){
		uid_size = strlen (uid) + 1;
		uid_st->be_size = htonl (uid_size);
		tpcm_memcpy (uid_st->value, uid, uid_size);
	}
	return sizeof (struct tpcm_data) + httc_align_size (uid_size, 4);
}
EXPORT_SYMBOL_GPL (httc_insert_uid_align4);

int httc_extract_uid_align4_size (void *ptr)
{
	struct tpcm_data *uid_st = (struct tpcm_data *)ptr;
	int uid_size = ntohl (uid_st->be_size);
	return sizeof (struct tpcm_data) + httc_align_size (uid_size, 4);
}
EXPORT_SYMBOL_GPL (httc_extract_uid_align4_size);

int httc_insert_auth_align4 (int auth_type, int auth_length,unsigned char *auth, void *ptr)
{
	struct tpcm_auth *auth_st = (struct tpcm_auth *)ptr;
	auth_st = (struct tpcm_auth *)ptr;
	auth_st->be_type = htonl (auth_type);
	auth_st->be_size = htonl (auth_length);
	if (auth_length) tpcm_memcpy (auth_st->value, auth, auth_length);
	return sizeof (struct tpcm_auth) + httc_align_size (auth_length, 4);
}
EXPORT_SYMBOL_GPL (httc_insert_auth_align4);

int httc_extract_auth_align4_size (void *ptr)
{
	struct tpcm_auth *auth_st = (struct tpcm_auth *)ptr;
	int auth_length = ntohl (auth_st->be_size);
	return sizeof (struct tpcm_auth) + httc_align_size (auth_length, 4);
}
EXPORT_SYMBOL_GPL (httc_extract_auth_align4_size);

int httc_insert_data_align4 (const char *data, int size, void *ptr)
{
	struct tpcm_data *data_st = (struct tpcm_data *)ptr;
	data_st->be_size = htonl (size);
	if (size) tpcm_memcpy (data_st->value, data, size);
	return sizeof (struct tpcm_data) + httc_align_size (size, 4);
}
EXPORT_SYMBOL_GPL (httc_insert_data_align4);

int httc_insert_data (const char *data, int size, void *ptr)
{
	struct tpcm_data *data_st = (struct tpcm_data *)ptr;
	data_st->be_size = htonl (size);
	if (size) tpcm_memcpy (data_st->value, data, size);
	return sizeof (struct tpcm_data) + size;
}
EXPORT_SYMBOL_GPL (httc_insert_data);

